package common

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func testIndividualSoftwareReconciliationTransport(t *testing.T, db *sql.DB, store *registry.Store, client *nats.Conn, issued enrollment.Response, keys *enrollment.Keys, key *enrollment.SoftwareRecipientKey, recipient enrollment.SoftwareRecipient, plan enrollment.SoftwarePlan, cert, root *x509.Certificate) {
	t.Helper()
	scope := registry.Scope{TenantID: issued.TenantID, SiteID: issued.SiteID}
	subject, _ := enrollment.RequestSubject(issued.DeviceID, "software")
	exchange := func(request any) []byte {
		t.Helper()
		wire, err := json.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(wire)
		response, err := client.Request(subject, wire, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	software := func(action string, result *enrollment.SoftwareResult, submission *enrollment.SoftwareSubmission) enrollment.SoftwareRequest {
		request := enrollment.SoftwareRequest{Version: enrollment.SoftwareVersion, Protocol: enrollment.SoftwareProtocol, AgentID: issued.DeviceID, Action: action, Result: result, Submission: submission}
		if action == "poll" {
			request.RecipientID = recipient.ID
		}
		return request
	}
	reconciliation := func(action string, result *enrollment.SoftwareReconciliationResult, submission *enrollment.SoftwareReconciliationSubmission) enrollment.SoftwareReconciliationRequest {
		return enrollment.SoftwareReconciliationRequest{Version: enrollment.SoftwareReconciliationVersion, Protocol: enrollment.SoftwareReconciliationProtocol, AgentID: issued.DeviceID, Action: action, Result: result, Submission: submission}
	}
	queueSoftware := func() (*enrollment.SoftwareTask, error) {
		tx, err := db.BeginTx(t.Context(), nil)
		if err != nil {
			return nil, err
		}
		defer tx.Rollback()
		task, err := store.QueueSoftwareTaskInTransaction(t.Context(), tx, scope, issued.DeviceID, uuid.NewString(), uuid.NewString(), uuid.NewString(), plan, time.Now().Add(5*time.Minute), "owned-operator")
		if err != nil {
			return nil, err
		}
		return task, tx.Commit()
	}
	original, err := queueSoftware()
	if err != nil {
		t.Fatal(err)
	}
	reply, err := enrollment.DecodeSoftwareReply(exchange(software("poll", nil, nil)), time.Now())
	if err != nil || reply.Task == nil || !reply.Task.Context.Equal(original.Context) {
		t.Fatal("second executable intent was not delivered", err)
	}
	secret, err := key.Open(*original, root, recipient.Identity, recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	nonce := secret.Nonce()
	defer clear(nonce)
	outcome := enrollment.SoftwareOutcome{State: "uncertain", Execution: "unknown", Before: enrollment.SoftwareObservation{State: "unknown"}, After: enrollment.SoftwareObservation{State: "unknown"}, Error: "interrupted"}
	result, err := enrollment.SignSoftwareResult(original.Context, recipient.Identity, secret.TaskHash(), nonce, outcome, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.Nonce)
	proof, err := enrollment.SignSoftwareSubmission(*result, recipient.Identity, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.DecodeSoftwareReply(exchange(software("result", result, proof)), time.Now()); err != nil {
		t.Fatal(err)
	}
	var originalReceipt []byte
	if err := db.QueryRow(`SELECT result FROM uem_agent_software_tasks WHERE id=$1`, original.Context.TaskID).Scan(&originalReceipt); err != nil {
		t.Fatal(err)
	}
	defer clear(originalReceipt)
	for _, observation := range []string{"unknown", "observed"} {
		tx, err := db.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatal(err)
		}
		task, err := store.QueueSoftwareReconciliationInTransaction(t.Context(), tx, scope, issued.DeviceID, original.Context.TaskID, uuid.NewString(), time.Now().Add(5*time.Minute), "owned-operator")
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		poll := reconciliation("poll", nil, nil)
		if _, err := db.Exec(`UPDATE agents SET agent_status='Disabled' WHERE oid=$1`, issued.DeviceID); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(exchange(poll)), "denied") {
			t.Fatal("disabled device received a new reconciliation")
		}
		if _, err := db.Exec(`UPDATE agents SET agent_status='Enabled' WHERE oid=$1`, issued.DeviceID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`DELETE FROM site_agents WHERE agent_id=$1`, issued.DeviceID); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(exchange(poll)), "denied") {
			t.Fatal("unscoped inventory received a reconciliation")
		}
		if _, err := db.Exec(`INSERT INTO site_agents(site_id,agent_id) VALUES($1,$2)`, issued.SiteID, issued.DeviceID); err != nil {
			t.Fatal(err)
		}
		if observation == "unknown" {
			if _, err := db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT owned_reconciliation_delivery_failure CHECK(action!='software.reconciliation.delivered')`); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(exchange(poll)), "denied") {
				t.Fatal("delivery audit failure acknowledged")
			}
			var absent bool
			if err := db.QueryRow(`SELECT delivered_at IS NULL FROM uem_agent_software_reconciliations WHERE id=$1`, task.Context.ID).Scan(&absent); err != nil || !absent {
				t.Fatal("failed delivery audit consumed intent", err)
			}
			if _, err := db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT owned_reconciliation_delivery_failure`); err != nil {
				t.Fatal(err)
			}
		}
		readOnly, err := enrollment.DecodeSoftwareReconciliationReply(exchange(poll), time.Now())
		if err != nil || readOnly.Task == nil || !readOnly.Task.Context.Equal(task.Context) || enrollment.VerifySoftwareReconciliationTask(*readOnly.Task, root, recipient.Identity, time.Now()) != nil {
			t.Fatal("signed read-only intent did not cross worker transport", err)
		}
		outcome := enrollment.SoftwareReconciliationOutcome{State: observation, Admission: enrollment.SoftwareBootSession{Sequence: 21, SystemProcessCreated: 133000000000000000}, Current: enrollment.SoftwareBootSession{Sequence: 22, SystemProcessCreated: 133000100000000000}, Observation: enrollment.SoftwareObservation{State: "unknown"}}
		if observation == "observed" {
			outcome.Observation = enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}
		}
		hash, _ := task.Digest()
		result, err := enrollment.SignSoftwareReconciliationResult(task.Context, hash, nonce, outcome, cert, keys.Certificate, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		defer clear(result.OriginalNonce)
		proof, err := enrollment.SignSoftwareReconciliationSubmission(*result, recipient.Identity, cert, keys.Certificate, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(exchange(reconciliation("result", result, nil))), "denied") {
			t.Fatal("reconciliation omitted current certificate proof")
		}
		request := reconciliation("result", result, proof)
		action := "software.reconciliation.reported"
		if observation == "observed" {
			action = "software.task.reconciled"
		}
		// These actions have not yet been committed when each constraint is added.
		if _, err := db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT owned_reconciliation_result_failure CHECK(action!='` + action + `')`); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(exchange(request)), "denied") {
			t.Fatal("failed receipt/release audit acknowledged")
		}
		var absent bool
		if err := db.QueryRow(`SELECT result IS NULL FROM uem_agent_software_reconciliations WHERE id=$1`, task.Context.ID).Scan(&absent); err != nil || !absent {
			t.Fatal("failed audit retained a partial observation", err)
		}
		if _, err := queueSoftware(); err == nil {
			t.Fatal("failed audit released original reservation")
		}
		if _, err := db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT owned_reconciliation_result_failure; UPDATE agents SET agent_status='Disabled'`); err != nil {
			t.Fatal(err)
		}
		for range 2 {
			readOnly, err = enrollment.DecodeSoftwareReconciliationReply(exchange(request), time.Now())
			if err != nil || readOnly.Receipt == nil || readOnly.Receipt.TaskID != task.Context.ID {
				t.Fatal("disabled device could not submit retained observation", err)
			}
		}
		var retained []byte
		if err := db.QueryRow(`SELECT result FROM uem_agent_software_tasks WHERE id=$1`, original.Context.TaskID).Scan(&retained); err != nil || !bytes.Equal(originalReceipt, retained) {
			t.Fatal("worker replaced original execution evidence", err)
		}
		clear(retained)
		var audits int
		if err := db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='software.reconciliation.reported' AND resource_id=$1`, task.Context.ID).Scan(&audits); err != nil || audits != 1 {
			t.Fatal("transport retry duplicated receipt audit", err)
		}
		if _, err := db.Exec(`UPDATE agents SET agent_status='Enabled' WHERE oid=$1`, issued.DeviceID); err != nil {
			t.Fatal(err)
		}
		_, err = queueSoftware()
		if (err == nil) != (observation == "observed") {
			t.Fatal("worker reservation differs from authenticated observation", err)
		}
	}
}
