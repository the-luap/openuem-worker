package common

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestIndividualRecoveryPayloadRejectsForeignAndNoncanonicalRequests(t *testing.T) {
	i := registry.Identity{ID: uuid.NewString(), Scope: registry.Scope{TenantID: 1, SiteID: 2}, Platform: "macos"}
	k, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	r := enrollment.RecoveryRequest{Version: 1, AgentID: i.ID, Action: "challenge", PublicKey: k.PublicKey()}
	data, _ := json.Marshal(r)
	payload, err := bindIndividualPayload(i, "recovery", data)
	if err != nil || payload.recovery == nil {
		t.Fatal("valid recovery request denied", err)
	}
	for _, invalid := range [][]byte{
		append(bytes.Clone(data), byte(' ')), append(bytes.Clone(data[:len(data)-1]), []byte(`,"tenant_id":2}`)...),
		bytes.Replace(data, []byte(i.ID), []byte(uuid.NewString()), 1), bytes.Repeat([]byte("x"), enrollment.MaxRecoveryMessage+1),
	} {
		if _, err = bindIndividualPayload(i, "recovery", invalid); err == nil {
			t.Fatal("ambiguous or foreign recovery payload accepted")
		}
	}
	i.Platform = "windows"
	if _, err = bindIndividualPayload(i, "recovery", data); err == nil {
		t.Fatal("Windows recovery request accepted")
	}
}

func testIndividualRecoveryTransport(t *testing.T, db *sql.DB, client *nats.Conn, issued enrollment.Response, keys *enrollment.Keys, platform string) ([]byte, []byte) {
	t.Helper()
	key, err := enrollment.NewRecoveryRecipientKey()
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	subject, _ := enrollment.RequestSubject(issued.DeviceID, "recovery")
	exchange := func(request enrollment.RecoveryRequest) []byte {
		t.Helper()
		request.Version, request.AgentID = 1, issued.DeviceID
		data, _ := json.Marshal(request)
		response, err := client.Request(subject, data, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	data := exchange(enrollment.RecoveryRequest{Action: "challenge", PublicKey: key.PublicKey()})
	if platform != "macos" {
		if !strings.Contains(string(data), "denied") {
			t.Fatal("Windows agent obtained Mac recipient challenge")
		}
		rotationSubject, _ := enrollment.RequestSubject(issued.DeviceID, "rotation")
		poll, _ := json.Marshal(enrollment.RotationRequest{Version: enrollment.RotationVersion, Protocol: enrollment.RotationProtocol, AgentID: issued.DeviceID, Action: "poll", RecipientID: uuid.NewString()})
		response, err := client.Request(rotationSubject, poll, 2*time.Second)
		if err != nil || !strings.Contains(string(response.Data), "denied") {
			t.Fatal("Windows agent reached FileVault rotation", err)
		}
		return nil, nil
	}
	reply, err := enrollment.DecodeRecoveryReply(data)
	if err != nil || reply.Registration == nil {
		t.Fatal("Mac registration challenge unavailable", err)
	}
	block, _ := pem.Decode([]byte(issued.Certificate))
	if block == nil {
		t.Fatal("fixture certificate unavailable")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := enrollment.SignRecoveryRegistration(*reply.Registration, cert, keys.Certificate, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	data = exchange(enrollment.RecoveryRequest{Action: "register", Registration: reply.Registration, Signature: signature})
	reply, err = enrollment.DecodeRecoveryReply(data)
	if err != nil || reply.Recipient == nil {
		t.Fatal("recipient proof not accepted", err)
	}
	r := reply.Recipient
	access, err := registry.NewAccessStore(db)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	c := enrollment.RecoveryContext{Version: 1, Identity: r.Identity, TaskID: uuid.NewString(), NativeID: uuid.NewString(), KeyID: uuid.NewString(), RecipientID: r.ID, ExpiresAt: time.Now().Add(time.Minute).Unix()}
	nonce := bytes.Repeat([]byte{5}, 32)
	hash := sha256.Sum256(nonce)
	task, err := enrollment.EncryptRecoveryTask(*r, c, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF"), nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = access.QueueRecoveryTask(t.Context(), tx, *task, hex.EncodeToString(hash[:])); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	poll := enrollment.RecoveryRequest{Version: 1, AgentID: issued.DeviceID, Action: "poll", RecipientID: r.ID}
	data = exchange(poll)
	if bytes.Contains(data, []byte("AAAA-BBBB-CCCC-DDDD-EEEE-FFFF")) {
		t.Fatal("worker received plaintext")
	}
	reply, err = enrollment.DecodeRecoveryReply(data)
	if err != nil || reply.Task == nil || reply.Task.Context != c {
		t.Fatal("private task was not routed", err)
	}
	secret, err := key.Open(*reply.Task, r.Identity, r.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	result, err := secret.Result("invalid", cert, keys.Certificate, time.Now())
	secret.Close()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		reply, err = enrollment.DecodeRecoveryReply(exchange(enrollment.RecoveryRequest{Action: "result", Result: result}))
		if err != nil || !reply.OK {
			t.Fatal("result or idempotent retry denied", err)
		}
	}
	var state string
	var envelope, receipt []byte
	if err = db.QueryRow(`SELECT status,envelope,result FROM uem_agent_recovery_tasks WHERE id=$1`, c.TaskID).Scan(&state, &envelope, &receipt); err != nil || state != "completed" || len(envelope) != 0 {
		t.Fatal("worker did not complete and scrub task", err)
	}
	var stored enrollment.RecoveryResult
	if json.Unmarshal(receipt, &stored) != nil || stored.Outcome != "invalid" || enrollment.VerifyRecoveryResult(stored, cert, time.Now()) != nil {
		t.Fatal("worker lost signed outcome")
	}
	rotationPoll := testIndividualRotationTransport(t, db, client, issued, keys, key, *r, cert)
	if _, err = db.Exec(`ALTER TABLE uem_agent_recovery_tasks RENAME TO isolated_missing_recovery_tasks`); err != nil {
		t.Fatal(err)
	}
	configSubject, _ := enrollment.RequestSubject(issued.DeviceID, "agentconfig")
	configBody, _ := json.Marshal(openuem.RemoteConfigRequest{AgentID: issued.DeviceID})
	configReply, err := client.Request(configSubject, configBody, 2*time.Second)
	var config openuem.Config
	if err != nil || json.Unmarshal(configReply.Data, &config) != nil || config.RecoveryTaskVersion != 0 || config.RotationTaskVersion != 0 || config.HardwareInventoryVersion != 1 {
		t.Fatal("missing recovery schema advertised capability", err)
	}
	if !strings.Contains(string(exchange(poll)), "denied") {
		t.Fatal("missing recovery schema accepted operation")
	}
	if _, err = db.Exec(`ALTER TABLE isolated_missing_recovery_tasks RENAME TO uem_agent_recovery_tasks`); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(poll)
	return encoded, rotationPoll
}
