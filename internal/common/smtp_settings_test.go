package common

import (
	"strings"
	"testing"

	"github.com/open-uem/ent/settings"
)

func TestSMTPSettingsReadCurrentGlobalSnapshotAndRejectAmbiguity(t *testing.T) {
	model := profileOrderTestModel(t)
	ctx := t.Context()
	global, err := model.Client.Settings.Create().SetSMTPServer("smtp.example.invalid").SetSMTPPort(587).SetSMTPUser("owned-user").SetSMTPPassword("owned-first").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := model.Client.Tenant.Create().SetDescription("Owned SMTP organization").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = model.Client.Settings.Create().SetTenantID(tenant.ID).SetSMTPServer("organization.example.invalid").SetSMTPPassword("owned-foreign-password").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	first, err := model.GetSMTPSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != global.ID || first.SMTPPassword != "owned-first" {
		t.Fatal("wrong SMTP audience")
	}
	if err = model.Client.Settings.UpdateOneID(global.ID).SetSMTPPassword("owned-second").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	second, err := model.GetSMTPSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.SMTPPassword != "owned-second" || first.SMTPPassword != "owned-first" {
		t.Fatal("SMTP snapshots are stale or shared")
	}
	if err = model.Client.Settings.UpdateOneID(global.ID).SetSMTPUser(strings.Repeat("x", 1025)).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = model.GetSMTPSettings(ctx); err == nil {
		t.Fatal("oversized SMTP configuration accepted")
	}
	if err = model.Client.Settings.UpdateOneID(global.ID).SetSMTPUser("owned").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	_, err = model.Client.Settings.Create().SetSMTPPassword("owned-other-global").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = model.GetSMTPSettings(ctx); err == nil {
		t.Fatal("ambiguous global SMTP configuration accepted")
	}
	if _, err = model.Client.Settings.Delete().Where(settings.Not(settings.HasTenant())).Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = model.GetSMTPSettings(ctx); err == nil {
		t.Fatal("organization SMTP configuration used as global fallback")
	}
}
