package common

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestIndividualRotationRejectsForeignAndAmbiguousRequests(t *testing.T) {
	i := registry.Identity{ID: uuid.NewString(), Scope: registry.Scope{TenantID: 1, SiteID: 2}, Platform: "macos"}
	r := enrollment.RotationRequest{Version: 1, Protocol: enrollment.RotationProtocol, AgentID: i.ID, Action: "poll", RecipientID: uuid.NewString()}
	data, _ := json.Marshal(r)
	if payload, err := bindIndividualPayload(i, "rotation", data); err != nil || payload.rotation == nil {
		t.Fatal("valid rotation poll denied", err)
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(data), ' '), bytes.Replace(data, []byte(i.ID), []byte(uuid.NewString()), 1),
		bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1),
		bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"tenant_id":2`), 1),
		bytes.Replace(data, []byte(enrollment.RotationProtocol), []byte("validation"), 1),
		bytes.Repeat([]byte("x"), enrollment.MaxRecoveryMessage+1),
	} {
		if _, err := bindIndividualPayload(i, "rotation", bad); err == nil {
			t.Fatal("ambiguous or foreign rotation accepted")
		}
	}
	if _, err := bindIndividualPayload(i, "recovery", data); err == nil {
		t.Fatal("rotation poll entered validation protocol")
	}
	i.Platform = "windows"
	if _, err := bindIndividualPayload(i, "rotation", data); err == nil {
		t.Fatal("Windows rotation accepted")
	}
}

func testIndividualRotationTransport(t *testing.T, db *sql.DB, client *nats.Conn, issued enrollment.Response, keys *enrollment.Keys, agentKey *enrollment.RecoveryRecipientKey, recipient enrollment.RecoveryRecipient, certificate *x509.Certificate) []byte {
	t.Helper()
	subject, _ := enrollment.RequestSubject(issued.DeviceID, "rotation")
	exchange := func(request enrollment.RotationRequest) []byte {
		t.Helper()
		request.Version, request.Protocol, request.AgentID = 1, enrollment.RotationProtocol, issued.DeviceID
		wire, _ := json.Marshal(request)
		response, err := client.Request(subject, wire, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	poll := enrollment.RotationRequest{Version: 1, Protocol: enrollment.RotationProtocol, AgentID: issued.DeviceID, Action: "poll", RecipientID: recipient.ID}
	access, err := registry.NewAccessStore(db)
	if err != nil {
		t.Fatal(err)
	}
	consoleKey, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer consoleKey.Close()
	nonce := bytes.Repeat([]byte{7}, 32)
	hash := sha256.Sum256(nonce)
	c := enrollment.RotationContext{Binding: enrollment.RecoveryContext{Version: 1, Identity: recipient.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: recipient.ID, ExpiresAt: time.Now().Add(time.Minute).Unix()}, Ordinal: 1, EscrowID: uuid.NewString(), ReplyKey: hex.EncodeToString(consoleKey.PublicKey())}
	task, err := enrollment.EncryptRotationTask(recipient, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = access.QueueRotationTask(t.Context(), tx, *task, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	result, err := enrollment.NewRotationResult(c, "unverified", nonce, []byte("1111-2222-3333-4444-5555-6666"), certificate, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exchange(enrollment.RotationRequest{Action: "result", Result: result})), "denied") {
		t.Fatal("undelivered rotation returned a key")
	}
	if _, err = db.Exec(`DELETE FROM site_agents WHERE agent_id=$1`, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exchange(poll)), "denied") {
		t.Fatal("unscoped inventory received rotation")
	}
	var undelivered bool
	if err = db.QueryRow(`SELECT delivered_at IS NULL FROM uem_agent_rotation_tasks WHERE id=$1`, c.Binding.TaskID).Scan(&undelivered); err != nil || !undelivered {
		t.Fatal("scope denial recorded delivery", err)
	}
	if _, err = db.Exec(`INSERT INTO site_agents(site_id,agent_id) VALUES($1,$2)`, issued.SiteID, issued.DeviceID); err != nil {
		t.Fatal(err)
	}
	data := exchange(poll)
	if bytes.Contains(data, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("routing response exposed old key")
	}
	reply, err := enrollment.DecodeRotationReply(data, time.Now())
	if err != nil || reply.Task == nil || reply.Task.Context != c {
		t.Fatal("rotation task did not cross private transport", err)
	}
	secret, err := agentKey.OpenRotationTask(*reply.Task, recipient.Identity, recipient.ID, time.Now())
	if err != nil || !bytes.Equal(secret.Key(), []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("endpoint could not decrypt delivered task", err)
	}
	secret.Close()
	forged := *result
	forged.Outcome = "rotated"
	if !strings.Contains(string(exchange(enrollment.RotationRequest{Action: "result", Result: &forged})), "denied") {
		t.Fatal("forged rotation outcome accepted")
	}
	if _, err = db.Exec(`ALTER TABLE uem_agent_audit ADD CONSTRAINT worker_rotation_audit_failure CHECK(action!='recovery.rotation.reported')`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exchange(enrollment.RotationRequest{Action: "result", Result: result})), "denied") {
		t.Fatal("worker acknowledged a receipt without its audit commit")
	}
	var rolledBack bool
	if err = db.QueryRow(`SELECT status='pending' AND result IS NULL AND octet_length(envelope)>0 FROM uem_agent_rotation_tasks WHERE id=$1`, c.Binding.TaskID).Scan(&rolledBack); err != nil || !rolledBack {
		t.Fatal("worker receipt transaction did not roll back", err)
	}
	if _, err = db.Exec(`ALTER TABLE uem_agent_audit DROP CONSTRAINT worker_rotation_audit_failure`); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		data := exchange(enrollment.RotationRequest{Action: "result", Result: result})
		if _, err = enrollment.DecodeRotationReply(data, time.Now()); err != nil {
			t.Fatal("encrypted result or retry denied", err)
		}
	}
	var receipt []byte
	var complete bool
	if err = db.QueryRow(`SELECT status='completed' AND octet_length(envelope)=0,result FROM uem_agent_rotation_tasks WHERE id=$1`, c.Binding.TaskID).Scan(&complete, &receipt); err != nil || !complete {
		t.Fatal("worker did not commit/scrub rotation", err)
	}
	var stored enrollment.RotationResult
	if json.Unmarshal(receipt, &stored) != nil {
		t.Fatal("missing encrypted receipt")
	}
	newKey, err := consoleKey.OpenRotationResult(stored, c, hex.EncodeToString(hash[:]), certificate, time.Now())
	if err != nil || !bytes.Equal(newKey.Key(), []byte("1111-2222-3333-4444-5555-6666")) {
		t.Fatal("console could not decrypt returned candidate", err)
	}
	newKey.Close()
	var audits int
	if err = db.QueryRow(`SELECT count(*) FROM uem_agent_audit WHERE action='recovery.rotation.reported'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatal("receipt retry duplicated audit", audits, err)
	}
	if bytes.Contains(receipt, []byte("1111-2222-3333-4444-5555-6666")) {
		t.Fatal("routing database contains plaintext new key")
	}
	if _, err = db.Exec(`ALTER TABLE uem_agent_rotation_tasks RENAME TO isolated_missing_rotation_tasks`); err != nil {
		t.Fatal(err)
	}
	configSubject, _ := enrollment.RequestSubject(issued.DeviceID, "agentconfig")
	configBody, _ := json.Marshal(openuem.RemoteConfigRequest{AgentID: issued.DeviceID})
	configReply, err := client.Request(configSubject, configBody, 2*time.Second)
	var config openuem.Config
	if err != nil || json.Unmarshal(configReply.Data, &config) != nil || config.RotationTaskVersion != 0 || config.RecoveryTaskVersion != 1 {
		t.Fatal("missing rotation schema advertised capability or disabled validation", err)
	}
	if !strings.Contains(string(exchange(poll)), "denied") {
		t.Fatal("missing rotation schema acknowledged operation")
	}
	if _, err = db.Exec(`ALTER TABLE isolated_missing_rotation_tasks RENAME TO uem_agent_rotation_tasks`); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(poll)
	return encoded
}
