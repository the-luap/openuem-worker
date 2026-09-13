package models

import (
	"reflect"
	"testing"

	"github.com/google/uuid"
	nats "github.com/open-uem/nats"
	"github.com/open-uem/nats/netbirdstate"
)

func TestNetbirdReportPreservesProfileIdentityAndLastConfirmedState(t *testing.T) {
	m, _ := individualTestModel(t)
	ctx := t.Context()
	id := uuid.NewString()
	if err := m.Client.Agent.Create().SetID(id).SetOs("windows").SetHostname("Owned NetBird fixture").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	details := []nats.NetbirdProfile{{ID: "default", Name: "office, spaces", Active: true}, {ID: "abcd1234", Name: "office, spaces"}}
	report := &nats.AgentReport{AgentID: id, Netbird: nats.Netbird{Installed: true, Version: "owned", ProfileDetails: details}}
	if err := m.SaveNetbirdInfo(report); err != nil {
		t.Fatal(err)
	}
	row, err := m.Client.Netbird.Query().Only(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := netbirdstate.Decode(row.ProfilesAvailable)
	if err != nil || !reflect.DeepEqual(got, details) {
		t.Fatal("profile identities were split or renamed")
	}
	for _, invalid := range []*nats.AgentReport{nil, {AgentID: id, Netbird: nats.Netbird{Error: "owned failure"}}, {AgentID: id, Netbird: nats.Netbird{Profiles: []string{"duplicate", "duplicate"}}}} {
		if err := m.SaveNetbirdInfo(invalid); err == nil {
			t.Fatal("failed/ambiguous observation was persisted")
		}
		after, err := m.Client.Netbird.Query().Only(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if !after.Installed || after.Version != "owned" || after.ProfilesAvailable != row.ProfilesAvailable {
			t.Fatal("last confirmed state was replaced")
		}
	}
}
