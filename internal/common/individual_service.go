package common

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	openuem "github.com/open-uem/nats"
	"github.com/open-uem/nats/enrollment/servicecredentials"
	"github.com/open-uem/openuem-worker/internal/models"
)

// ConfigureIndividualAgentService handles the CLI and installed agent-worker
// service before any legacy INI/certificate configuration is loaded.
func (w *Worker) ConfigureIndividualAgentService() (bool, error) {
	switch os.Getenv("OPENUEM_INDIVIDUAL_AGENT_MODE") {
	case "", "false":
		return false, nil
	case "true":
	default:
		return false, errors.New("OPENUEM_INDIVIDUAL_AGENT_MODE must be true or false")
	}
	config := &openuem.ServiceConnection{
		Servers: os.Getenv("OPENUEM_AGENT_BROKER_URLS"), Name: "openuem-individual-agent-worker",
		KeyFile: os.Getenv("OPENUEM_AGENT_WORKER_KEY_FILE"), CAFile: os.Getenv("OPENUEM_AGENT_BROKER_CA_FILE"),
		CertificateFile: os.Getenv("OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE"), TLSKeyFile: os.Getenv("OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE"),
		Event: func(state string) { log.Printf("[INFO]: individual agent worker broker %s", state) },
	}
	rawDatabase, databaseFile := os.Getenv("OPENUEM_AGENT_DATABASE_URL"), os.Getenv("OPENUEM_AGENT_DATABASE_URL_FILE")
	if rawDatabase == "" && databaseFile == "" || !openuem.ValidServiceURLs(config.Servers) || config.KeyFile == "" {
		return false, errors.New("individual agent worker requires a database URL, explicit TLS broker URLs and a protected service key file")
	}
	dbURL, err := servicecredentials.DatabaseURL(rawDatabase, databaseFile)
	if err != nil {
		return false, err
	}
	master, err := servicecredentials.EncryptionKey(os.Getenv("ENCRYPTION_MASTER_KEY"), os.Getenv("ENCRYPTION_MASTER_KEY_FILE"))
	if err != nil {
		return false, err
	}
	w.DBUrl = dbURL
	w.NATSServers = config.Servers
	w.IndividualAgentService = config
	w.EncryptionMasterKey = master
	return true, nil
}

// RunIndividualAgentWorker owns the model and connection for a complete worker
// lifetime. Configuration and permission failures return to the service runner;
// transient disconnects reconnect using the same explicit TLS/NKey configuration.
func (w *Worker) RunIndividualAgentWorker(ctx context.Context) error {
	if w.IndividualAgentService == nil || w.DBUrl == "" {
		return errors.New("individual agent worker is not configured")
	}
	model, err := models.New(w.DBUrl)
	if err != nil {
		return errors.New("individual agent worker database startup failed")
	}
	defer model.Close()
	startup, cancel := context.WithTimeout(ctx, 5*time.Second)
	var initialized bool
	err = model.DB.QueryRowContext(startup, `SELECT EXISTS(SELECT 1 FROM uem_agent_migrations WHERE name='migrations/001_registry.sql')`).Scan(&initialized)
	cancel()
	if err != nil || !initialized {
		return errors.New("individual agent registry must be initialized before the worker starts")
	}
	failures := make(chan struct{}, 1)
	fail := func() {
		select {
		case failures <- struct{}{}:
		default:
		}
	}
	config := *w.IndividualAgentService
	config.ErrorHandler = func(*nats.Conn, *nats.Subscription, error) { fail() }
	config.Event = func(state string) {
		log.Printf("[INFO]: individual agent worker broker %s", state)
		if state == "closed" {
			fail()
		}
	}
	connection, err := openuem.ConnectService(config)
	if err != nil {
		return err
	}
	defer connection.Close()
	w.Model, w.NATSConnection = model, connection
	if err = w.SubscribeIndividualAgentQueues(); err != nil {
		return errors.New("individual agent worker subscriptions failed")
	}
	defer w.stopIndividualRequests()
	log.Print("[INFO]: individual agent worker subscriptions established")
	select {
	case <-ctx.Done():
		return nil
	case <-failures:
		return errors.New("individual agent worker broker permissions or messaging failed")
	}
}
