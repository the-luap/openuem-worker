package common

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/open-uem/ent/agent"
	"github.com/open-uem/ent/wingetconfigexclusion"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment"
	"github.com/open-uem/nats/enrollment/registry"
	"github.com/open-uem/openuem-worker/internal/models"
)

func TestIndividualWorkerRejectsForgedBodiesRepliesAndRevokedSenders(t *testing.T) {
	for _, platform := range []string{"windows", "macos"} {
		t.Run(platform, func(t *testing.T) { testIndividualWorkerBoundary(t, platform) })
	}
}

func testIndividualWorkerBoundary(t *testing.T, platform string) {
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for worker/broker integration")
	}
	t.Setenv("ENV", "development")
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "true")
	ctx := context.Background()
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "agent_worker_broker_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	model, err := models.New(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		model.Close()
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	tenant, err := model.Client.Tenant.Create().SetDescription("Own").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	site, err := model.Client.Site.Create().SetDescription("Own site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store, err := registry.NewStore(model.DB, "isolated-worker-test-master-key-32-bytes")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = store.EnsureAuthority(ctx, tenant.ID, "Own", "https://uem.example.test", "test-admin", nil, nil); err != nil {
		t.Fatal(err)
	}
	scope := registry.Scope{TenantID: tenant.ID, SiteID: site.ID}
	invitation, err := store.Invite(ctx, registry.InvitationOptions{Scope: scope, Platform: platform, Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], platform, "amd64", "Endpoint")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Claim(ctx, *request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = model.Client.Agent.Create().SetID(issued.DeviceID).SetOs(platform).SetHostname("Endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(site.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	public, _ := keys.Broker.PublicKey()
	workerKey, _ := nkeys.CreateUser()
	workerPublic, _ := workerKey.PublicKey()
	monitorKey, _ := nkeys.CreateUser()
	monitorPublic, _ := monitorKey.PublicKey()
	deniedKey, _ := nkeys.CreateUser()
	deniedPublic, _ := deniedKey.PublicKey()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	certificate := certServer.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	caPath := filepath.Join(t.TempDir(), "broker-ca.pem")
	if err = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certServer.Certificate().Raw}), 0644); err != nil {
		t.Fatal(err)
	}
	certServer.Close()
	writeSeed := func(key nkeys.KeyPair) string {
		t.Helper()
		seed, _ := key.Seed()
		defer clear(seed)
		path := filepath.Join(t.TempDir(), "service.seed")
		if err := os.WriteFile(path, seed, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	workerRequests := []string{}
	for _, operation := range enrollment.Operations() {
		workerRequests = append(workerRequests, "uem.v1.agent.*.request."+operation)
	}
	policy, _ := enrollment.DeviceSubjects(issued.DeviceID)
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, Nkeys: []*server.NkeyUser{
			{Nkey: public, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: policy.Publish}, Subscribe: &server.SubjectPermission{Allow: policy.Subscribe}}},
			{Nkey: workerPublic, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Deny: []string{">"}}, Subscribe: &server.SubjectPermission{Allow: workerRequests}, Response: &server.ResponsePermission{MaxMsgs: 1, Expires: 30 * time.Second}}},
			{Nkey: deniedPublic, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Deny: []string{">"}}, Subscribe: &server.SubjectPermission{Allow: []string{"uem.v1.agent.*.request.agentconfig"}}}},
			{Nkey: monitorPublic},
		}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	workerConnection, err := nats.Connect(broker.ClientURL(), nats.Nkey(monitorPublic, monitorKey.Sign), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer workerConnection.Close()
	t.Setenv("OPENUEM_AGENT_DATABASE_URL", u.String())
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", broker.ClientURL())
	t.Setenv("OPENUEM_AGENT_WORKER_KEY_FILE", writeSeed(workerKey))
	t.Setenv("OPENUEM_AGENT_BROKER_CA_FILE", caPath)
	t.Setenv("OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE", "")
	t.Setenv("OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE", "")
	worker := &Worker{}
	if configured, err := worker.ConfigureIndividualAgentService(); err != nil || !configured {
		t.Fatal("individual service configuration failed", err)
	}
	workerContext, stopWorker := context.WithCancel(ctx)
	workerResult := make(chan error, 1)
	go func() { workerResult <- worker.RunIndividualAgentWorker(workerContext) }()
	t.Cleanup(func() {
		stopWorker()
		select {
		case err := <-workerResult:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(8 * time.Second):
			t.Error("individual worker did not stop")
		}
	})
	prefix, _ := enrollment.ReplyPrefix(issued.DeviceID)
	client, err := nats.Connect(broker.ClientURL(), nats.Nkey(public, keys.Broker.Sign), nats.CustomInboxPrefix(prefix), nats.Secure(&tls.Config{RootCAs: roots}), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	subject, _ := enrollment.RequestSubject(issued.DeviceID, "wingetcfg.exclude")
	deadline := time.Now().Add(8 * time.Second)
	for {
		response, err := client.Request(subject, []byte(`{}`), time.Second)
		if err == nil && strings.Contains(string(response.Data), "denied") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("individual worker subscriptions did not become ready", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	count := func() int {
		t.Helper()
		n, err := model.Client.WingetConfigExclusion.Query().Where(wingetconfigexclusion.HasOwnerWith(agent.ID(issued.DeviceID))).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	// Publish to an authorized request subject with a forbidden worker reply.
	foreign := uuid.NewString()
	commands, err := workerConnection.SubscribeSync("agent.reboot." + foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err = workerConnection.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(openuem.DeployAction{AgentId: issued.DeviceID, PackageId: "forged-reply"})
	if err = client.PublishRequest(subject, "agent.reboot."+foreign, body); err != nil {
		t.Fatal(err)
	}
	if err = client.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err = commands.NextMsg(100 * time.Millisecond); err != nats.ErrTimeout {
		t.Fatal("worker response became a foreign command", err)
	}
	if count() != 0 {
		t.Fatal("forged reply reached mutation")
	}
	requestResult := func(agentID, packageID string) []byte {
		t.Helper()
		body, _ := json.Marshal(openuem.DeployAction{AgentId: agentID, PackageId: packageID})
		response, err := client.Request(subject, body, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	if response := requestResult(foreign, "forged-body"); !strings.Contains(string(response), "denied") || count() != 0 {
		t.Fatal("foreign body reached mutation")
	}
	if response := requestResult(issued.DeviceID, "own-package"); len(response) != 0 || count() != 1 {
		t.Fatal("valid scoped message did not reach real handler")
	}
	hardwareSubject, _ := enrollment.RequestSubject(issued.DeviceID, "hardware")
	hardware := enrollment.HardwareInventory{Version: 1, AgentID: issued.DeviceID, Model: "iMacPro1,1", Serial: "ABCD123456", PlatformUUID: "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", Binding: &enrollment.MacBindingProof{ChallengeID: uuid.NewString(), DeviceID: uuid.NewString(), Token: base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))}}
	sendHardware := func(h enrollment.HardwareInventory) []byte {
		t.Helper()
		data, _ := json.Marshal(h)
		response, err := client.Request(hardwareSubject, data, 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return response.Data
	}
	configSubject, _ := enrollment.RequestSubject(issued.DeviceID, "agentconfig")
	configBody, _ := json.Marshal(openuem.RemoteConfigRequest{AgentID: issued.DeviceID})
	response, err := client.Request(configSubject, configBody, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var config openuem.Config
	if json.Unmarshal(response.Data, &config) != nil || (config.HardwareInventoryVersion == 1) != (platform == "macos") || (config.RecoveryTaskVersion == 1) != (platform == "macos") || (config.RotationTaskVersion == enrollment.RotationVersion) != (platform == "macos") {
		t.Fatal("hardware capability did not follow platform/schema")
	}
	if config.Ok {
		t.Fatal("missing frequency settings reported successful configuration")
	}
	if _, err := model.Client.Settings.Create().SetTenantID(tenant.ID).SetAgentReportFrequenceInMinutes(15).SetProfilesApplicationFrequenceInMinutes(30).Save(ctx); err != nil {
		t.Fatal(err)
	}
	response, err = client.Request(configSubject, configBody, 2*time.Second)
	config = openuem.Config{}
	if err != nil || json.Unmarshal(response.Data, &config) != nil || !config.Ok || config.AgentFrequency != 15 || (config.HardwareInventoryVersion == 1) != (platform == "macos") || (config.RotationTaskVersion == enrollment.RotationVersion) != (platform == "macos") {
		t.Fatal("configured hardware capability unavailable", err)
	}
	if platform == "macos" {
		var receipt enrollment.HardwareReceipt
		if json.Unmarshal(sendHardware(hardware), &receipt) != nil || !receipt.OK || receipt.Version != 1 {
			t.Fatal("Mac evidence was not acknowledged")
		}
		var stored string
		digest := sha256.Sum256([]byte(hardware.Binding.Token))
		if err := model.DB.QueryRow(`SELECT binding_token_hash FROM uem_agent_hardware WHERE device_id=$1 AND tenant_id=$2 AND site_id=$3`, issued.DeviceID, scope.TenantID, scope.SiteID).Scan(&stored); err != nil || stored != hex.EncodeToString(digest[:]) {
			t.Fatal("proof not committed under authorized scope", err)
		}
		foreignHardware := hardware
		foreignHardware.AgentID = foreign
		if !strings.Contains(string(sendHardware(foreignHardware)), "denied") {
			t.Fatal("foreign hardware identity accepted")
		}
		if _, err := model.DB.Exec(`ALTER TABLE uem_agent_hardware RENAME TO isolated_unavailable_hardware`); err != nil {
			t.Fatal(err)
		}
		response, err = client.Request(configSubject, configBody, 2*time.Second)
		config = openuem.Config{}
		if err != nil || json.Unmarshal(response.Data, &config) != nil || config.HardwareInventoryVersion != 0 {
			t.Fatal("missing hardware schema advertised", err)
		}
		if !strings.Contains(string(sendHardware(hardware)), "denied") {
			t.Fatal("missing schema returned hardware success")
		}
		if _, err := model.DB.Exec(`ALTER TABLE isolated_unavailable_hardware RENAME TO uem_agent_hardware`); err != nil {
			t.Fatal(err)
		}
	} else if !strings.Contains(string(sendHardware(hardware)), "denied") {
		t.Fatal("Windows identity wrote Mac evidence")
	}
	recoveryPoll, rotationPoll := testIndividualRecoveryTransport(t, model.DB, client, *issued, keys, platform)
	if err = store.RevokeIdentity(ctx, scope, issued.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	// Even before the separate disconnect worker kicks this open connection,
	// every new request must observe persisted revocation.
	if response := requestResult(issued.DeviceID, "after-revocation"); !strings.Contains(string(response), "denied") || count() != 1 {
		t.Fatal("revoked sender reached mutation")
	}
	if !strings.Contains(string(sendHardware(hardware)), "denied") {
		t.Fatal("revoked sender refreshed hardware evidence")
	}
	if recoveryPoll != nil {
		subject, _ := enrollment.RequestSubject(issued.DeviceID, "recovery")
		response, err := client.Request(subject, recoveryPoll, 2*time.Second)
		if err != nil || !strings.Contains(string(response.Data), "denied") {
			t.Fatal("revoked agent polled recovery tasks", err)
		}
	}
	if rotationPoll != nil {
		subject, _ := enrollment.RequestSubject(issued.DeviceID, "rotation")
		response, err := client.Request(subject, rotationPoll, 2*time.Second)
		if err != nil || !strings.Contains(string(response.Data), "denied") {
			t.Fatal("revoked agent polled rotation tasks", err)
		}
	}
	// A service with only some permitted queues must return a failure instead
	// of remaining alive with an incomplete set of subscriptions.
	partial := *worker.IndividualAgentService
	partial.KeyFile = writeSeed(deniedKey)
	badWorker := &Worker{DBUrl: u.String(), IndividualAgentService: &partial}
	badContext, cancelBad := context.WithTimeout(ctx, 8*time.Second)
	defer cancelBad()
	if err = badWorker.RunIndividualAgentWorker(badContext); err == nil || badContext.Err() != nil {
		t.Fatal("partial subscription permissions did not stop worker", err)
	}
}
