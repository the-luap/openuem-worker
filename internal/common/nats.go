package common

import (
	"errors"
	"log"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/open-uem/nats"
)

func (w *Worker) StartNATSConnectJob(queueSubscribe func() error) error {
	var err error
	if w.IndividualAgentService != nil {
		return errors.New("individual agent service requires its managed worker runtime")
	}

	w.NATSConnection, err = nats.ConnectWithNATS(w.NATSServers, w.ClientCertPath, w.ClientKeyPath, w.CACertPath, "")
	if err == nil {
		if err = queueSubscribe(); err == nil {
			return err
		}
		w.NATSConnection.Close()
		w.NATSConnection = nil
	}
	log.Print("[ERROR]: worker broker connection or subscription failed")

	w.NATSConnectJob, err = w.TaskScheduler.NewJob(
		gocron.DurationJob(
			time.Duration(time.Duration(2*time.Minute)),
		),
		gocron.NewTask(
			func() {
				if w.NATSConnection == nil {
					w.NATSConnection, err = nats.ConnectWithNATS(w.NATSServers, w.ClientCertPath, w.ClientKeyPath, w.CACertPath, "")
					if err != nil {
						log.Printf("[ERROR]: could not connect to NATS %v", err)
						return
					}
				}

				if err := queueSubscribe(); err != nil {
					return
				}

				if err := w.TaskScheduler.RemoveJob(w.NATSConnectJob.ID()); err != nil {
					return
				}
			},
		),
	)
	if err != nil {
		log.Fatalf("[FATAL]: could not start the NATS connect job: %v", err)
		return err
	}
	log.Printf("[INFO]: new NATS connect job has been scheduled every %d minutes", 2)
	return nil
}
