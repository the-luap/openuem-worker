package common

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent/task"
	ansiblecfg "github.com/open-uem/openuem-ansible-config/ansible"
	"github.com/open-uem/openuem-worker/internal/models"
)

func profileOrderTestModel(t *testing.T) *models.Model {
	t.Helper()
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for profile task order tests")
	}
	t.Setenv("ENV", "development")
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "worker_profile_order_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`); err != nil {
			t.Error(err)
		}
		admin.Close()
	})
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	model, err := models.New(u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(model.Close)
	return model
}

func TestProfileTaskOrderSurvivesAllThreeConfigurationGenerators(t *testing.T) {
	m := profileOrderTestModel(t)
	ctx := t.Context()
	worker := &Worker{Model: m}
	tenant, err := m.Client.Tenant.Create().SetDescription("Owned order organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	site, err := m.Client.Site.Create().SetDescription("Owned order site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	_, err = m.Client.Agent.Create().SetID(agentID).SetOs("linux").SetHostname("Owned order endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(site.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []struct {
		name     string
		taskType task.Type
		platform task.AgentType
	}{{"winget", task.TypePowershellScript, task.AgentTypeWindows}, {"ansible", task.TypeUnixScript, task.AgentTypeLinux}, {"netbird", task.TypeNetbirdInstall, task.AgentTypeAny}} {
		t.Run(kind.name, func(t *testing.T) {
			p, err := m.Client.Profile.Create().SetName("Owned " + kind.name + " order").SetApplyToAll(true).AddTenantIDs(tenant.ID).AddSiteIDs(site.ID).Save(ctx)
			if err != nil {
				t.Fatal(err)
			}
			ids := []int{}
			for i, position := range []int{7, 0, 7, 0, 1} {
				entry, err := m.Client.Task.Create().SetName("Owned generated task").SetType(kind.taskType).SetAgentType(kind.platform).SetOrder(position).SetVersion(3).SetScript("echo owned").SetDisabled(i == 4).SetProfileID(p.ID).Save(ctx)
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, entry.ID)
			}
			if _, err = m.DB.ExecContext(ctx, `UPDATE tasks SET "order"=NULL WHERE id=$1`, ids[3]); err != nil {
				t.Fatal(err)
			}
			var before string
			if err = m.DB.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(t) ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1`, p.ID).Scan(&before); err != nil {
				t.Fatal(err)
			}
			profiles, err := m.GetProfilesAppliedToAllFilteredByProfile(site.ID, tenant.ID, p.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(profiles) != 1 {
				t.Fatalf("wanted one profile, got %d", len(profiles))
			}
			expected := []string{}
			for _, id := range []int{ids[1], ids[0], ids[2], ids[3]} {
				switch kind.name {
				case "winget":
					expected = append(expected, fmt.Sprintf("task_%d_3", id))
				case "ansible":
					expected = append(expected, fmt.Sprintf("task_%d", id))
				default:
					expected = append(expected, strconv.Itoa(id))
				}
			}
			actual := []string{}
			switch kind.name {
			case "winget":
				config, err := worker.GenerateWinGetConfig(profiles[0])
				if err != nil {
					t.Fatal(err)
				}
				for _, resource := range config.Properties.Resources {
					id, ok := resource.Settings["ID"].(string)
					if !ok {
						t.Fatal("generated PowerShell task lacks its settings ID")
					}
					actual = append(actual, id)
				}
			case "ansible":
				config, err := worker.GenerateAnsibleConfig(profiles[0], agentID)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range config.Tasks {
					script, ok := entry.(*ansiblecfg.AnsibleBuiltinShell)
					if !ok {
						t.Fatalf("unexpected task type %T", entry)
					}
					actual = append(actual, script.TaskName)
				}
			case "netbird":
				config, err := worker.GenerateNetbirdConfig(profiles[0], agentID)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range config {
					actual = append(actual, entry.ID)
				}
			}
			if !slices.Equal(actual, expected) {
				t.Fatalf("generated task order %v, want %v", actual, expected)
			}
			var after string
			if err = m.DB.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(t) ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1`, p.ID).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatal("generating configuration changed stored tasks")
			}
		})
	}
}
