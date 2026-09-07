package common

import (
	"encoding/json"
	"strings"
	"testing"

	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/registry"
)

func TestIndividualPayloadBindsIdentityAndRejectsScopeEscalation(t *testing.T) {
	id := "12345678-1234-4234-8234-123456789abc"
	foreign := "12345678-1234-4234-8234-123456789abd"
	identity := registry.Identity{ID: id, Scope: registry.Scope{TenantID: 1, SiteID: 10}, Platform: "windows"}
	for _, operation := range []string{"report", "agentconfig"} {
		body := `{"id":"` + id + `"}`
		if operation == "agentconfig" {
			body = `{"agentID":"` + id + `"}`
		}
		payload, err := bindIndividualPayload(identity, operation, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if operation == "report" {
			var report openuem.AgentReport
			_ = json.Unmarshal(payload.data, &report)
			if report.AgentID != id || report.Tenant != "1" || report.Site != "10" || !report.CertificateReady {
				t.Fatal("report lost authoritative identity")
			}
		} else {
			var request openuem.RemoteConfigRequest
			_ = json.Unmarshal(payload.data, &request)
			if request.AgentID != id || request.TenantID != "1" || request.SiteID != "10" {
				t.Fatal("config lost authoritative identity")
			}
		}
	}
	for _, test := range []struct{ operation, body string }{
		{"report", `{"id":"` + foreign + `"}`},
		{"report", `{"id":"` + id + `","tenant":"2"}`},
		{"report", `{"id":"` + id + `","site":"11"}`},
		{"report", `{"id":"` + id + `","ID":"` + foreign + `"}`},
		{"report", `{"id":"` + id + `","unexpected":"value"}`},
		{"agentconfig", `{"agentID":"` + id + `","tenantID":"2"}`},
		{"agentconfig", `{"agentID":"` + foreign + `"}`},
		{"deployresult", `{"agentid":"` + foreign + `","packageid":"example","action":"install"}`},
		{"deployresult", `{"agentid":"` + id + `","packageid":"example","action":"wipe"}`},
		{"wingetcfg.profiles", `{"agentID":"` + foreign + `","profileID":1}`},
		{"wingetcfg.profiles", `{"agentID":"` + id + `","profileID":-1}`},
		{"ansiblecfg.profiles", `{"agentID":"` + id + `","profileID":1}`},
		{"wingetcfg.report", `{"agentID":"` + id + `","profileID":0}`},
		{"report", `{"id":"` + id + `"} {}`},
		{"report", `null`},
		{"unknown", `{}`},
	} {
		if _, err := bindIndividualPayload(identity, test.operation, []byte(test.body)); err == nil {
			t.Fatalf("accepted %s %s", test.operation, test.body)
		}
	}
	if _, err := bindIndividualPayload(identity, "report", []byte(strings.Repeat(" ", 8<<20+1))); err == nil {
		t.Fatal("unbounded payload accepted")
	}
	// If an alias appears before the final canonical identity, the checked
	// representation contains only the resulting, authorized identity.
	payload, err := bindIndividualPayload(identity, "report", []byte(`{"ID":"`+foreign+`","id":"`+id+`"}`))
	if err != nil || strings.Contains(string(payload.data), foreign) {
		t.Fatal("conflicting alias survived canonicalization", err)
	}
}

func TestIndividualTaskReportsExtractOnlyCanonicalUniqueTaskIDs(t *testing.T) {
	identity := registry.Identity{ID: "12345678-1234-4234-8234-123456789abc", Scope: registry.Scope{TenantID: 1, SiteID: 10}, Platform: "macos"}
	report := openuem.ProfileReport{AgentID: identity.ID, ProfileID: 12, Tasks: []openuem.TaskReport{{Name: "task_41_2"}, {Name: "task_42"}}}
	data, _ := json.Marshal(report)
	payload, err := bindIndividualPayload(identity, "wingetcfg.report", data)
	if err != nil || payload.profileID != 12 || len(payload.taskIDs) != 2 || payload.taskIDs[0] != 41 || payload.taskIDs[1] != 42 {
		t.Fatal("valid task report rejected", err)
	}
	for _, name := range []string{"41", "task_+41", "task_041", "task_0", "task_-1", "task_42_other"} {
		report.Tasks[0].Name = name
		data, _ = json.Marshal(report)
		if _, err := bindIndividualPayload(identity, "wingetcfg.report", data); err == nil {
			t.Fatal("invalid or duplicate task accepted", name)
		}
	}
}
