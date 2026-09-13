package models

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent"
)

func TestProfileTaskQueriesMatchStoredOrderAndKeepReadsUnchanged(t *testing.T) {
	m, _ := individualTestModel(t)
	ctx := t.Context()
	tenant, err := m.Client.Tenant.Create().SetDescription("Owned order organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	site, err := m.Client.Site.Create().SetDescription("Owned order site").SetTenantID(tenant.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	_, err = m.Client.Agent.Create().SetID(agentID).SetOs("windows").SetHostname("Owned order endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").AddSiteIDs(site.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := m.Client.Tag.Create().SetTag("Owned order tag").SetColor("blue").SetTenantID(tenant.ID).AddOwnerIDs(agentID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := m.Client.Profile.Create().SetName("Owned order profile").SetApplyToAll(true).AddTenantIDs(tenant.ID).AddSiteIDs(site.ID).AddTagIDs(tag.ID).Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ids := []int{}
	for i, position := range []int{7, 0, 7, 0} {
		task, err := m.Client.Task.Create().SetName(fmt.Sprintf("Owned order task %d", i)).SetType("powershell_script").SetOrder(position).SetVersion(3).SetProfileID(p.ID).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, task.ID)
	}
	if _, err = m.DB.ExecContext(ctx, `UPDATE tasks SET "order"=NULL WHERE id=$1`, ids[3]); err != nil {
		t.Fatal(err)
	}
	var before string
	if err = m.DB.QueryRowContext(ctx, `SELECT jsonb_agg(to_jsonb(t) ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1`, p.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	expected := []int{ids[1], ids[0], ids[2], ids[3]}
	for name, query := range map[string]func() ([]*ent.Profile, error){
		"all": func() ([]*ent.Profile, error) { return m.GetProfilesAppliedToAll(site.ID, tenant.ID) },
		"all filtered": func() ([]*ent.Profile, error) {
			return m.GetProfilesAppliedToAllFilteredByProfile(site.ID, tenant.ID, p.ID)
		},
		"tagged": func() ([]*ent.Profile, error) { return m.GetProfilesAppliedToAgent(site.ID, agentID, tenant.ID) },
		"tagged filtered": func() ([]*ent.Profile, error) {
			return m.GetProfilesAppliedToAgentFilteredByProfile(site.ID, agentID, tenant.ID, p.ID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			profiles, err := query()
			if err != nil {
				t.Fatal(err)
			}
			if len(profiles) != 1 {
				t.Fatalf("wanted one assigned profile, got %d", len(profiles))
			}
			actual := []int{}
			for i, task := range profiles[0].Edges.Tasks {
				actual = append(actual, task.ID)
				if task.Order != i+1 {
					t.Errorf("task %d has runtime position %d, want %d", task.ID, task.Order, i+1)
				}
			}
			if !slices.Equal(expected, actual) {
				t.Errorf("task order %v, want %v", actual, expected)
			}
		})
	}
	var after string
	if err = m.DB.QueryRowContext(context.Background(), `SELECT jsonb_agg(to_jsonb(t) ORDER BY id)::text FROM tasks t WHERE profile_tasks=$1`, p.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("reading assigned profiles changed stored task configuration or order")
	}
}
