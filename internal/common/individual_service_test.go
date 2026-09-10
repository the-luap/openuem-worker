package common

import "testing"

func TestIndividualServiceConfigurationCannotFallBackToLegacyCredentials(t *testing.T) {
	for _, name := range []string{"OPENUEM_AGENT_DATABASE_URL_FILE", "ENCRYPTION_MASTER_KEY", "ENCRYPTION_MASTER_KEY_FILE", "OPENUEM_AGENT_DATABASE_URL", "OPENUEM_AGENT_BROKER_URLS", "OPENUEM_AGENT_WORKER_KEY_FILE", "OPENUEM_AGENT_BROKER_CA_FILE", "OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE", "OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "true")
	worker := &Worker{NATSServers: "nats://legacy:4222", ClientCertPath: "legacy.cer", ClientKeyPath: "legacy.key"}
	if configured, err := worker.ConfigureIndividualAgentService(); err == nil || configured {
		t.Fatal("individual mode accepted legacy credentials instead of required service configuration")
	}
	t.Setenv("OPENUEM_AGENT_DATABASE_URL", "postgres://worker@db/uem")
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", "tls://broker.internal:4222")
	t.Setenv("OPENUEM_AGENT_WORKER_KEY_FILE", "/run/worker.seed")
	if err := worker.GenerateCommonWorkerConfig("agent-worker"); err != nil {
		t.Fatal("individual service unnecessarily required legacy INI configuration", err)
	}
	if worker.IndividualAgentService == nil || worker.NATSServers != "tls://broker.internal:4222" || worker.IndividualAgentService.CertificateFile != "" || worker.IndividualAgentService.TLSKeyFile != "" {
		t.Fatal("individual connection retained legacy certificate authentication")
	}
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", "tls://user:secret@broker.internal:4222")
	if _, err := (&Worker{}).ConfigureIndividualAgentService(); err == nil {
		t.Fatal("credential-bearing broker URL accepted")
	}
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "invalid")
	if _, err := (&Worker{}).ConfigureIndividualAgentService(); err == nil {
		t.Fatal("invalid mode silently selected legacy behavior")
	}
}
