package common

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/open-uem/nats/enrollment/keyfile"
	"github.com/open-uem/nats/enrollment/servicecredentials"
)

func TestIndividualServiceProtectedDatabaseAndEncryptionInputs(t *testing.T) {
	for _, name := range []string{"OPENUEM_AGENT_DATABASE_URL", "OPENUEM_AGENT_DATABASE_URL_FILE", "ENCRYPTION_MASTER_KEY", "ENCRYPTION_MASTER_KEY_FILE", "OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE", "OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("OPENUEM_INDIVIDUAL_AGENT_MODE", "true")
	t.Setenv("OPENUEM_AGENT_BROKER_URLS", "tls://broker.internal:4222")
	t.Setenv("OPENUEM_AGENT_WORKER_KEY_FILE", "/private/worker.seed")
	databaseFile, masterFile := filepath.Join(t.TempDir(), "database.url"), filepath.Join(t.TempDir(), "encryption.key")
	database, key := "postgres://worker:synthetic%21password@database.internal/uem?sslmode=verify-full", strings.Repeat("x", 32)
	if keyfile.Create(databaseFile, []byte(database+"\n")) != nil || keyfile.Create(masterFile, []byte(key+"\r\n")) != nil {
		t.Fatal("cannot create protected worker fixtures")
	}
	t.Setenv("OPENUEM_AGENT_DATABASE_URL_FILE", databaseFile)
	t.Setenv("ENCRYPTION_MASTER_KEY_FILE", masterFile)
	worker := &Worker{}
	if configured, err := worker.ConfigureIndividualAgentService(); err != nil || !configured || worker.DBUrl != database || worker.EncryptionMasterKey != key {
		t.Fatal("protected service inputs were not selected", err)
	}
	for _, change := range []struct{ name, value string }{
		{"OPENUEM_AGENT_DATABASE_URL", database}, {"OPENUEM_AGENT_DATABASE_URL_FILE", databaseFile + ".missing"},
		{"ENCRYPTION_MASTER_KEY", key}, {"ENCRYPTION_MASTER_KEY_FILE", masterFile + ".missing"},
	} {
		t.Run(change.name, func(t *testing.T) {
			t.Setenv(change.name, change.value)
			worker := &Worker{DBUrl: "retained", EncryptionMasterKey: "retained"}
			if configured, err := worker.ConfigureIndividualAgentService(); configured || !errors.Is(err, servicecredentials.ErrConfiguration) || worker.DBUrl != "retained" || worker.EncryptionMasterKey != "retained" {
				t.Fatal("invalid source changed retained worker configuration", err)
			}
		})
	}
}

func runIndividualWorkerFixture(ctx context.Context, worker *Worker) error {
	binary := os.Getenv("OPENUEM_WORKER_TEST_BINARY")
	if binary == "" {
		return worker.RunIndividualAgentWorker(ctx)
	}
	command := exec.CommandContext(ctx, binary, "agents", "start")
	for _, name := range []string{"OPENUEM_INDIVIDUAL_AGENT_MODE", "OPENUEM_AGENT_DATABASE_URL_FILE", "ENCRYPTION_MASTER_KEY_FILE", "OPENUEM_AGENT_BROKER_URLS", "OPENUEM_AGENT_WORKER_KEY_FILE", "OPENUEM_AGENT_BROKER_CA_FILE"} {
		command.Env = append(command.Env, name+"="+os.Getenv(name))
	}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = 5 * time.Second
	err := command.Run()
	if ctx.Err() != nil && command.ProcessState != nil && command.ProcessState.Success() {
		return nil
	}
	return err
}
