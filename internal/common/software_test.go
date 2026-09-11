package common

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestIndividualSoftwarePayloadRejectsForeignAndNoncanonicalRequests(t *testing.T) {
	i := registry.Identity{ID: uuid.NewString(), Scope: registry.Scope{TenantID: 1, SiteID: 2}, Platform: "windows"}
	key, err := enrollment.NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	r := enrollment.SoftwareRequest{Version: 1, Protocol: enrollment.SoftwareProtocol, AgentID: i.ID, Action: "challenge", PublicKey: key.PublicKey()}
	data, _ := json.Marshal(r)
	if payload, err := bindIndividualPayload(i, "software", data); err != nil || payload.software == nil {
		t.Fatal("valid software request denied", err)
	}
	for _, bad := range [][]byte{append(bytes.Clone(data), ' '), bytes.Replace(data, []byte(i.ID), []byte(uuid.NewString()), 1), bytes.Replace(data, []byte(`"agent_id"`), []byte(`"Agent_ID"`), 1), bytes.Repeat([]byte("x"), enrollment.MaxSoftwareMessage+1)} {
		if _, err := bindIndividualPayload(i, "software", bad); err == nil {
			t.Fatal("ambiguous/foreign software request accepted")
		}
	}
	i.Platform = "macos"
	if _, err := bindIndividualPayload(i, "software", data); err == nil {
		t.Fatal("Mac accepted as Windows software endpoint")
	}
}

func TestIndividualSoftwareReconciliationPayloadIsBoundAndDistinct(t *testing.T) {
	i := registry.Identity{ID: uuid.NewString(), Scope: registry.Scope{TenantID: 1, SiteID: 2}, Platform: "windows"}
	request := enrollment.SoftwareReconciliationRequest{Version: enrollment.SoftwareReconciliationVersion, Protocol: enrollment.SoftwareReconciliationProtocol, AgentID: i.ID, Action: "poll"}
	data, _ := json.Marshal(request)
	payload, err := bindIndividualPayload(i, "software", data)
	if err != nil || payload.softwareReconciliation == nil || payload.software != nil || !bytes.Equal(payload.data, data) {
		t.Fatal("read-only protocol was not selected distinctly", err)
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(data), ' '),
		bytes.Replace(data, []byte(i.ID), []byte(uuid.NewString()), 1),
		bytes.Replace(data, []byte(`"agent_id"`), []byte(`"Agent_ID"`), 1),
		append([]byte(`{"agent_id":"foreign",`), data[1:]...),
		append([]byte(`{"recipient_id":"`+uuid.NewString()+`",`), data[1:]...),
		bytes.Repeat([]byte("x"), enrollment.MaxSoftwareMessage+1),
	} {
		if _, err := bindIndividualPayload(i, "software", bad); err == nil {
			t.Fatal("ambiguous or foreign reconciliation body accepted")
		}
	}
	for _, platform := range []string{"macos", "linux", ""} {
		i.Platform = platform
		if _, err := bindIndividualPayload(i, "software", data); err == nil {
			t.Fatal("non-Windows device reached reconciliation")
		}
	}
}

func testIndividualSoftwareTransport(t *testing.T, db *sql.DB, store *registry.Store, client *nats.Conn, issued enrollment.Response, keys *enrollment.Keys, platform string) []byte {
	t.Helper()
	key, err := enrollment.NewSoftwareRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	subject, err := enrollment.RequestSubject(issued.DeviceID, "software")
	if err != nil {
		t.Fatal(err)
	}
	exchange := func(r enrollment.SoftwareRequest) []byte {
		t.Helper()
		r.Version, r.Protocol, r.AgentID = 1, enrollment.SoftwareProtocol, issued.DeviceID
		wire, _ := json.Marshal(r)
		defer clear(wire)
		response, err := client.Request(subject, wire, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	data := exchange(enrollment.SoftwareRequest{Action: "challenge", PublicKey: key.PublicKey()})
	if platform != "windows" {
		if !strings.Contains(string(data), "denied") {
			t.Fatal("Mac reached Windows software registration")
		}
		wire, _ := json.Marshal(enrollment.SoftwareReconciliationRequest{Version: enrollment.SoftwareReconciliationVersion, Protocol: enrollment.SoftwareReconciliationProtocol, AgentID: issued.DeviceID, Action: "poll"})
		response, err := client.Request(subject, wire, 2*time.Second)
		if err != nil || !strings.Contains(string(response.Data), "denied") {
			t.Fatal("Mac reached Windows software reconciliation", err)
		}
		return nil
	}
	if !strings.Contains(string(data), "denied") {
		t.Fatal("agent awaiting admission registered for software")
	}
	if _, err = db.Exec(`UPDATE agents SET agent_status='Enabled' WHERE oid=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	data = exchange(enrollment.SoftwareRequest{Action: "challenge", PublicKey: key.PublicKey()})
	reply, err := enrollment.DecodeSoftwareReply(data, time.Now())
	if err != nil || reply.Registration == nil {
		t.Fatal("Windows software registration unavailable", err)
	}
	parse := func(raw string) *x509.Certificate {
		t.Helper()
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			t.Fatal("missing fixture certificate")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	cert, root := parse(issued.Certificate), parse(issued.Authority)
	signature, err := enrollment.SignSoftwareRegistration(*reply.Registration, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	reply, err = enrollment.DecodeSoftwareReply(exchange(enrollment.SoftwareRequest{Action: "register", Registration: reply.Registration, Signature: signature}), time.Now())
	if err != nil || reply.Recipient == nil {
		t.Fatal("signed software registration failed", err)
	}
	recipient := *reply.Recipient
	plan := enrollment.SoftwarePlan{Kind: "windows-msi", Operation: "install", Identifier: "Owned.WorkerFixture", Version: "1.2.3", Architecture: "amd64", MinimumOS: "10.0.26100", Artifact: enrollment.SoftwareArtifact{URL: "https://packages.example.test/owned.msi?token=private-source", SHA256: strings.Repeat("a", 64), Format: "msi"}, Detection: enrollment.SoftwareDetection{Kind: "msi-product", ProductCode: "{AABBCCDD-0000-4000-8000-000000000001}", Version: "1.2.3"}, SuccessCodes: []uint32{0}, RebootCodes: []uint32{3010}}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	task, err := store.QueueSoftwareTaskInTransaction(t.Context(), tx, registry.Scope{TenantID: issued.TenantID, SiteID: issued.SiteID}, issued.DeviceID, uuid.NewString(), uuid.NewString(), uuid.NewString(), plan, time.Now().Add(5*time.Minute), "owned-operator")
	if err != nil || tx.Commit() != nil {
		t.Fatal("queue trusted fixture task", err)
	}
	poll := enrollment.SoftwareRequest{Version: 1, Protocol: enrollment.SoftwareProtocol, AgentID: issued.DeviceID, Action: "poll", RecipientID: recipient.ID}
	if _, err = db.Exec(`DELETE FROM site_agents WHERE agent_id=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exchange(poll)), "denied") {
		t.Fatal("unscoped inventory received task")
	}
	if _, err = db.Exec(`INSERT INTO site_agents(site_id,agent_id) VALUES($1,$2)`, issued.SiteID, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE agents SET agent_status='Disabled' WHERE oid=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exchange(poll)), "denied") {
		t.Fatal("disabled inventory received task")
	}
	var undelivered bool
	if err = db.QueryRow(`SELECT delivered_at IS NULL FROM uem_agent_software_tasks WHERE id=$1`, task.Context.TaskID).Scan(&undelivered); err != nil || !undelivered {
		t.Fatal("denied poll consumed delivery", err)
	}
	if _, err = db.Exec(`UPDATE agents SET agent_status='Enabled' WHERE oid=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	reply, err = enrollment.DecodeSoftwareReply(exchange(poll), time.Now())
	if err != nil || reply.Task == nil || !reply.Task.Context.Equal(task.Context) {
		t.Fatal("exact encrypted task did not cross private transport", err)
	}
	secret, err := key.Open(*reply.Task, root, recipient.Identity, recipient.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer secret.Close()
	zero := uint32(0)
	outcome := enrollment.SoftwareOutcome{State: "observed", Execution: "started", ExitCode: &zero, Before: enrollment.SoftwareObservation{State: "absent"}, After: enrollment.SoftwareObservation{State: "present", Version: "1.2.3"}}
	result, err := enrollment.SignSoftwareResult(task.Context, recipient.Identity, secret.TaskHash(), secret.Nonce(), outcome, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(result.Nonce)
	proof, err := enrollment.SignSoftwareSubmission(*result, recipient.Identity, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := enrollment.SoftwareRequest{Action: "result", Result: result, Submission: proof}
	if !strings.Contains(string(exchange(enrollment.SoftwareRequest{Action: "result", Result: result})), "denied") {
		t.Fatal("result omitted current certificate proof")
	}
	if _, err = db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT owned_software_audit_failure CHECK(action!='software.task.reported')`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exchange(request)), "denied") {
		t.Fatal("failed audit committed result")
	}
	var empty bool
	if err = db.QueryRow(`SELECT result IS NULL FROM uem_agent_software_tasks WHERE id=$1`, task.Context.TaskID).Scan(&empty); err != nil || !empty {
		t.Fatal("failed audit consumed result", err)
	}
	if _, err = db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT owned_software_audit_failure; UPDATE agents SET agent_status='Disabled'`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reply, err = enrollment.DecodeSoftwareReply(exchange(request), time.Now())
		if err != nil || reply.Receipt == nil {
			t.Fatal("disabled agent could not report/retry existing work", err)
		}
	}
	var audits int
	if err = db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='software.task.reported' AND resource_id=$1`, task.Context.TaskID).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("receipt retry changed durable history", err)
	}
	if _, err = db.Exec(`UPDATE agents SET agent_status='Enabled' WHERE oid=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	testIndividualSoftwareReconciliationTransport(t, db, store, client, issued, keys, key, recipient, plan, cert, root)
	wire, _ := json.Marshal(poll)
	return wire
}
