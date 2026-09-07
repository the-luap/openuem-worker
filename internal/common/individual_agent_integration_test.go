package common

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"os"
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
	invitation, err := store.Invite(ctx, registry.InvitationOptions{Scope: scope, Platform: "windows", Architecture: "amd64", MaxUses: 1, ExpiresAt: time.Now().Add(time.Hour)}, "test-admin")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := enrollment.GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	request, err := keys.Request(invitation.URL[strings.LastIndex(invitation.URL, "/")+1:], "windows", "amd64", "Endpoint")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := store.Claim(ctx, *request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = model.Client.Agent.Create().SetID(issued.DeviceID).SetOs("windows").SetHostname("Endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(site.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	public, _ := keys.Broker.PublicKey()
	workerKey, _ := nkeys.CreateUser()
	workerPublic, _ := workerKey.PublicKey()
	policy, _ := enrollment.DeviceSubjects(issued.DeviceID)
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, Nkeys: []*server.NkeyUser{
		{Nkey: public, Permissions: &server.Permissions{Publish: &server.SubjectPermission{Allow: policy.Publish}, Subscribe: &server.SubjectPermission{Allow: policy.Subscribe}}},
		{Nkey: workerPublic},
	}})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	t.Cleanup(func() { broker.Shutdown(); broker.WaitForShutdown() })
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("broker did not start")
	}
	workerConnection, err := nats.Connect(broker.ClientURL(), nats.Nkey(workerPublic, workerKey.Sign), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer workerConnection.Close()
	worker := &Worker{Model: model, NATSConnection: workerConnection}
	if err = worker.SubscribeToAgentWorkerQueues(); err != nil {
		t.Fatal(err)
	}
	prefix, _ := enrollment.ReplyPrefix(issued.DeviceID)
	client, err := nats.Connect(broker.ClientURL(), nats.Nkey(public, keys.Broker.Sign), nats.CustomInboxPrefix(prefix), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	subject, _ := enrollment.RequestSubject(issued.DeviceID, "wingetcfg.exclude")
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
	if err = store.RevokeIdentity(ctx, scope, issued.DeviceID, "test-admin"); err != nil {
		t.Fatal(err)
	}
	// Even before the separate disconnect worker kicks this open connection,
	// every new request must observe persisted revocation.
	if response := requestResult(issued.DeviceID, "after-revocation"); !strings.Contains(string(response), "denied") || count() != 1 {
		t.Fatal("revoked sender reached mutation")
	}
}
