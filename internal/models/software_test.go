package models

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestSoftwareAuthorizationHoldsAdmissionAndScopeUntilCommit(t *testing.T) {
	m, _ := individualTestModel(t)
	ctx := t.Context()
	tenant, err := m.Client.Tenant.Create().SetDescription("Owned software tenant").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	site, err := m.Client.Site.Create().SetDescription("Owned software site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other, err := m.Client.Site.Create().SetDescription("Other software site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	i := registry.Identity{ID: uuid.NewString(), Scope: registry.Scope{TenantID: tenant.ID, SiteID: site.ID}, Platform: "windows"}
	if _, err = m.Client.Agent.Create().SetID(i.ID).SetOs("windows").SetHostname("Owned software endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(site.ID).Save(ctx); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"WaitingForAdmission", "Disabled", "Enabled", "No contact"} {
		if _, err = m.DB.Exec(`UPDATE agents SET agent_status=$2 WHERE oid=$1`, i.ID, status); err != nil {
			t.Fatal(err)
		}
		for _, receipt := range []bool{false, true} {
			tx, err := m.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = m.AuthorizeIndividualSoftware(ctx, tx, i, receipt)
			_ = tx.Rollback()
			allowed := receipt || status == "Enabled" || status == "No contact"
			if (err == nil) != allowed {
				t.Fatal("incorrect admission/receipt policy", status, receipt, err)
			}
		}
	}
	for _, query := range []string{
		`UPDATE agents SET agent_status='Disabled' WHERE oid=$1`,
		`UPDATE agents SET os='macos' WHERE oid=$1`,
		`DELETE FROM site_agents WHERE agent_id=$1`,
		`INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)`,
	} {
		tx, err := m.DB.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.AuthorizeIndividualSoftware(ctx, tx, i, false); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		writer, err := m.DB.BeginTx(ctx, nil)
		if err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if _, err = writer.Exec(`SET LOCAL statement_timeout='100ms'`); err != nil {
			writer.Rollback()
			tx.Rollback()
			t.Fatal(err)
		}
		args := []any{i.ID}
		if query == `INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)` {
			args = append(args, other.ID)
		}
		started := time.Now()
		_, err = writer.Exec(query, args...)
		writer.Rollback()
		tx.Rollback()
		var timeout *pgconn.PgError
		if !errors.As(err, &timeout) || timeout.Code != "57014" || time.Since(started) < 50*time.Millisecond {
			t.Fatal("scope/status changed before software commit", err)
		}
	}
	if _, err = m.DB.Exec(`INSERT INTO site_agents(agent_id,site_id) VALUES($1,$2)`, i.ID, other.ID); err != nil {
		t.Fatal(err)
	}
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = m.AuthorizeIndividualSoftware(ctx, tx, i, true); !errors.Is(err, ErrAgentScope) {
		t.Fatal("ambiguous inventory submitted scoped receipt", err)
	}
}
