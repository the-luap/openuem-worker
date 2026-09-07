package models

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats/enrollment/registry"
)

func individualTestModel(t *testing.T) (*Model, string) {
	t.Helper()
	dsn := os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set AGENT_ENROLLMENT_TEST_DATABASE_URL for PostgreSQL worker tests")
	}
	t.Setenv("ENV", "development")
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := "agent_worker_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
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
	model, err := New(u.String())
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
	return model, u.String()
}

func TestProfileQueriesAndTaskReportsCannotCrossOrganizationOrSite(t *testing.T) {
	m, _ := individualTestModel(t)
	ctx := context.Background()
	one, err := m.Client.Tenant.Create().SetDescription("One").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	two, err := m.Client.Tenant.Create().SetDescription("Two").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := m.Client.Site.Create().SetDescription("First").SetTenantID(one.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Client.Site.Create().SetDescription("Second").SetTenantID(one.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.Client.Site.Create().SetDescription("Other").SetTenantID(two.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.NewString()
	if _, err = m.Client.Agent.Create().SetID(id).SetOs("windows").SetHostname("Endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(first.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	identity := registry.Identity{ID: id, Scope: registry.Scope{TenantID: one.ID, SiteID: first.ID}, Platform: "windows"}
	makeProfile := func(name string, tenantID, siteID int) *ent.Profile {
		t.Helper()
		create := m.Client.Profile.Create().SetName(name).SetApplyToAll(true).SetDisabled(false)
		if tenantID > 0 {
			create.AddTenantIDs(tenantID)
		}
		if siteID > 0 {
			create.AddSiteIDs(siteID)
		}
		p, err := create.Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	global := makeProfile("Global", 0, 0)
	own := makeProfile("Own", one.ID, first.ID)
	otherSite := makeProfile("Other site", one.ID, second.ID)
	foreign := makeProfile("Foreign", two.ID, other.ID)
	for _, profile := range []*ent.Profile{global, own, otherSite, foreign} {
		allowed := profile.ID == global.ID || profile.ID == own.ID
		found, err := m.GetProfilesAppliedToAllFilteredByProfile(first.ID, one.ID, profile.ID)
		if err != nil || (len(found) == 1) != allowed {
			t.Fatal("explicit profile lookup bypassed scope", profile.Name, err)
		}
		err = m.AuthorizeIndividualRequest(ctx, identity, "wingetcfg.profiles", profile.ID, nil)
		if (err == nil) != allowed {
			t.Fatal("profile authorization bypassed scope", profile.Name, err)
		}
	}
	found, err := m.GetProfilesAppliedToAll(first.ID, one.ID)
	if err != nil || len(found) != 2 {
		t.Fatal("bulk profile lookup ignored explicit site", err)
	}
	ownTask, err := m.Client.Task.Create().SetName("Own task").SetType(task.TypePowershellScript).SetProfileID(own.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	foreignTask, err := m.Client.Task.Create().SetName("Foreign task").SetType(task.TypePowershellScript).SetProfileID(foreign.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.AuthorizeIndividualRequest(ctx, identity, "wingetcfg.report", own.ID, []int{ownTask.ID}); err != nil {
		t.Fatal("own task rejected", err)
	}
	if err = m.AuthorizeIndividualRequest(ctx, identity, "wingetcfg.report", own.ID, []int{foreignTask.ID}); !errors.Is(err, ErrAgentScope) {
		t.Fatal("foreign task report accepted", err)
	}
	identity.SiteID = second.ID
	if err = m.AuthorizeIndividualRequest(ctx, identity, "report", 0, nil); !errors.Is(err, ErrAgentScope) {
		t.Fatal("desktop record scope disagrees with enrollment", err)
	}
}

func TestWorkerStartupPreservesColumnsAndIndexesFromNewerComponents(t *testing.T) {
	m, dsn := individualTestModel(t)
	if _, err := m.DB.Exec(`ALTER TABLE sites ADD COLUMN enrollment_future_field TEXT; CREATE INDEX enrollment_future_index ON sites(enrollment_future_field)`); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	var exists bool
	if err = restarted.DB.QueryRow(`SELECT to_regclass('enrollment_future_index') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatal("startup removed a newer component's index", err)
	}
	if _, err = restarted.DB.Exec(`UPDATE sites SET enrollment_future_field='retained'`); err != nil {
		t.Fatal("startup removed a newer component's column", err)
	}
}
