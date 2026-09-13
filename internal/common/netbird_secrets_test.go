package common

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/utils"
)

func TestNetbirdEncryptedCredentialsPreserveFollowingTasks(t *testing.T) {
	m := profileOrderTestModel(t)
	ctx := t.Context()
	organization, err := m.Client.Tenant.Create().SetDescription("Owned NetBird secret organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	site, err := m.Client.Site.Create().SetDescription("Owned NetBird secret site").SetTenantID(organization.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	_, err = m.Client.Agent.Create().SetID(agentID).SetOs("linux").SetHostname("owned-netbird.example").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(site.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	var expected atomic.Value
	expected.Store("")
	provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Token "+expected.Load().(string) {
			t.Error("NetBird provider received an incorrect credential")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/peers":
			if r.URL.Query().Get("name") != "owned-netbird.example" {
				t.Error("NetBird peer lookup lost its endpoint")
			}
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/setup-keys":
			var payload struct {
				Type       string `json:"type"`
				UsageLimit int    `json:"usage_limit"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Type != "one-off" || payload.UsageLimit != 1 {
				t.Error("NetBird registration lost its one-off key request")
			}
			_, _ = w.Write([]byte(`{"id":"owned-key-id","key":"owned-one-off-key","valid":true,"type":"one-off","usage_limit":1}`))
		default:
			t.Error("unexpected owned NetBird provider request")
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	configuration, err := m.Client.NetbirdSettings.Create().SetManagementURL(provider.URL).AddTenantIDs(organization.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	profile := &ent.Profile{ID: 7, Edges: ent.ProfileEdges{Tasks: []*ent.Task{
		{ID: 101, Order: 1, Type: task.TypeNetbirdRegister, Tenant: organization.ID},
		{ID: 102, Order: 2, Type: task.TypeNetbirdInstall},
	}}}
	key := strings.Repeat("k", 32)
	ciphertext, err := utils.EncryptSensitiveField("owned-netbird-token", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		name, stored, key, plain string
		valid                    bool
	}{
		{"encrypted", ciphertext, key, "owned-netbird-token", true},
		{"legacy-short-hex", "aabb", key, "aabb", true},
		{"legacy-plaintext-without-key", "owned-legacy-token", "", "owned-legacy-token", true},
		{"missing-key", ciphertext, "", "", false},
		{"wrong-key", ciphertext, strings.Repeat("z", 32), "", false},
		{"corrupt-long-hex", strings.Repeat("a", 56), key, "", false},
		{"oversized", strings.Repeat("x", legacysecret.MaxStoredSize+1), key, "", false},
		{"empty", "", key, "", false},
	} {
		t.Run(entry.name, func(t *testing.T) {
			if err := m.Client.NetbirdSettings.UpdateOneID(configuration.ID).SetAccessToken(entry.stored).Exec(ctx); err != nil {
				t.Fatal(err)
			}
			expected.Store(entry.plain)
			before := requests.Load()
			worker := &Worker{Model: m, EncryptionMasterKey: entry.key, netbirdHTTPTransport: provider.Client().Transport}
			actual, err := worker.GenerateNetbirdConfig(profile, agentID)
			if !entry.valid {
				if err == nil || actual != nil || requests.Load() != before {
					t.Fatal("unreadable NetBird token produced configuration or contacted the provider")
				}
				return
			}
			if err != nil || len(actual) != 2 {
				t.Fatal("NetBird token decryption dropped configuration or following tasks", err)
			}
			if actual[0].ID != strconv.Itoa(101) || !actual[0].Register || actual[0].RegisterInfo.OneOffKey != "owned-one-off-key" || actual[0].RegisterInfo.ManagementURL != provider.URL || actual[1].ID != strconv.Itoa(102) || !actual[1].Install {
				t.Fatal("NetBird configuration lost registration or the following install task")
			}
			if requests.Load()-before != 2 {
				t.Fatal("NetBird generated an unexpected number of provider requests")
			}
			stored, err := m.Client.NetbirdSettings.Get(ctx, configuration.ID)
			if err != nil || stored.AccessToken != entry.stored {
				t.Fatal("NetBird decryption changed stored credentials")
			}
		})
	}
}
