package commands

import (
	"io"
	"strings"
	"testing"

	"github.com/urfave/cli/v2"
)

func TestAgentCLIReachesIndividualConfigurationWithoutLegacyFlags(t *testing.T) {
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "true")
	t.Setenv("OPENUEM_AGENT_DATABASE_URL", "")
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", "")
	t.Setenv("OPENUEM_AGENT_WORKER_KEY_FILE", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("NATS_SERVERS", "")
	app := &cli.App{Commands: []*cli.Command{AgentWorker()}, Writer: io.Discard, ErrWriter: io.Discard}
	err := app.Run([]string{"worker", "agents", "start"})
	if err == nil || !strings.Contains(err.Error(), "individual agent worker requires") {
		t.Fatal("legacy CLI flags prevented individual startup validation", err)
	}
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "false")
	app = &cli.App{Commands: []*cli.Command{AgentWorker()}, Writer: io.Discard, ErrWriter: io.Discard}
	err = app.Run([]string{"worker", "agents", "start"})
	if err == nil || err.Error() != "legacy worker requires dburl and nats-servers" {
		t.Fatal("legacy CLI lost its required configuration validation", err)
	}
}
