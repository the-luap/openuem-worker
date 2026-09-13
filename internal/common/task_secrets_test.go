package common

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/open-uem/ent"
	"github.com/open-uem/ent/task"
	"github.com/open-uem/nats/tasksecrets"
	"github.com/open-uem/utils"
	"gopkg.in/yaml.v3"
)

const ownedTaskKey = "0123456789abcdef0123456789abcdef"

func ownedSecretProfile(platform task.AgentType, password, passphrase string) *ent.Profile {
	kind, next := task.TypeAddUnixLocalUser, task.TypeRemoveUnixLocalUser
	if platform == task.AgentTypeWindows {
		kind, next = task.TypeAddLocalUser, task.TypeRemoveLocalUser
	}
	return &ent.Profile{ID: 7, Name: "Owned secret profile", Edges: ent.ProfileEdges{Tasks: []*ent.Task{
		{ID: 1, Order: 1, Version: 3, Type: kind, AgentType: platform, LocalUserUsername: "owned-account", LocalUserPassword: password, LocalUserSSHKeyPassphrase: passphrase, LocalUserGenerateSSHKey: true},
		{ID: 2, Order: 2, Version: 3, Type: next, AgentType: platform, LocalUserUsername: "owned-obsolete-account"},
	}}}
}

func assertSecretConfiguration(t *testing.T, config any, original *ent.Profile, password, passphrase string) {
	t.Helper()
	data, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{password, passphrase, "owned-obsolete-account"} {
		if wanted != "" && !bytes.Contains(data, []byte(wanted)) {
			t.Fatal("configuration lost a secret or following task")
		}
	}
	for _, stored := range []string{original.Edges.Tasks[0].LocalUserPassword, original.Edges.Tasks[0].LocalUserSSHKeyPassphrase} {
		if stored != "" && stored != password && stored != passphrase && bytes.Contains(data, []byte(stored)) {
			t.Fatal("configuration contains encrypted storage bytes")
		}
	}
}

func TestTaskSecretsWindowsPreserveFullConfiguration(t *testing.T) {
	plain := "owned-private-password"
	// Use the independent historical utility to prove storage compatibility.
	encrypted, err := utils.EncryptSensitiveField(plain, ownedTaskKey)
	if err != nil {
		t.Fatal(err)
	}
	worker := &Worker{EncryptionMasterKey: ownedTaskKey}
	for _, stored := range []string{encrypted, "aabb", ""} {
		profile := ownedSecretProfile(task.AgentTypeWindows, stored, "")
		expected := stored
		if stored == encrypted {
			expected = plain
		}
		for i := 0; i < 2; i++ {
			cfg, err := worker.GenerateWinGetConfig(profile)
			if err != nil {
				t.Fatal(err)
			}
			if cfg == nil || len(cfg.Properties.Resources) != 2 {
				t.Fatal("generator dropped resources after password decryption")
			}
			assertSecretConfiguration(t, cfg, profile, expected, "")
			if profile.Edges.Tasks[0].LocalUserPassword != stored {
				t.Fatal("generator mutated stored password")
			}
		}
	}
	for _, stored := range []string{strings.Repeat("a", 56), encrypted} {
		profile := ownedSecretProfile(task.AgentTypeWindows, stored, "")
		cfg, err := (&Worker{EncryptionMasterKey: strings.Repeat("k", 32)}).GenerateWinGetConfig(profile)
		if err != tasksecrets.ErrUnavailable || cfg != nil {
			t.Fatal("invalid password returned a partial configuration")
		}
	}
}

func TestTaskSecretsUnixPreserveFullConfiguration(t *testing.T) {
	m := profileOrderTestModel(t)
	plainPassword, plainSSH := "owned-private-password", "owned-private-SSH"
	encrypted, err := utils.EncryptSensitiveField(plainPassword, ownedTaskKey)
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := tasksecrets.SealSSH(plainSSH, ownedTaskKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, platform := range []task.AgentType{task.AgentTypeLinux, task.AgentTypeMacos} {
		t.Run(platform.String(), func(t *testing.T) {
			agentID := uuid.NewString()
			_, err := m.Client.Agent.Create().SetID(agentID).SetOs(platform.String()).SetHostname("Owned secret endpoint").SetIP("192.0.2.1").SetMAC("02:00:00:00:00:01").SetWan("192.0.2.1").Save(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			worker := &Worker{Model: m, EncryptionMasterKey: ownedTaskKey}
			for _, storedSSH := range []string{ssh, plainSSH, ""} {
				profile := ownedSecretProfile(platform, encrypted, storedSSH)
				expectedSSH := plainSSH
				if storedSSH == "" {
					expectedSSH = ""
				}
				for i := 0; i < 2; i++ {
					cfg, err := worker.GenerateAnsibleConfig(profile, agentID)
					if err != nil {
						t.Fatal(err)
					}
					if cfg == nil || len(cfg.Tasks) != 2 {
						t.Fatal("generator dropped decrypted account or Unix removal task")
					}
					assertSecretConfiguration(t, cfg, profile, plainPassword, expectedSSH)
					if profile.Edges.Tasks[0].LocalUserPassword != encrypted || profile.Edges.Tasks[0].LocalUserSSHKeyPassphrase != storedSSH {
						t.Fatal("generator mutated stored secrets")
					}
				}
			}
			for _, invalid := range []struct{ password, passphrase, key string }{
				{encrypted, ssh, strings.Repeat("k", 32)}, {"", ssh, ""}, {"", tasksecrets.Prefix + "ssh:v2:bad", ownedTaskKey}, {"aabb", ssh, strings.Repeat("k", 32)},
			} {
				worker.EncryptionMasterKey = invalid.key
				cfg, err := worker.GenerateAnsibleConfig(ownedSecretProfile(platform, invalid.password, invalid.passphrase), agentID)
				if err != tasksecrets.ErrUnavailable || cfg != nil {
					t.Fatal("invalid secret returned a partial Unix configuration")
				}
			}
		})
	}
}
