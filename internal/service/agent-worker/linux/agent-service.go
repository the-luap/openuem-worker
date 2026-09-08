//go:build linux

package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-co-op/gocron/v2"
	"github.com/open-uem/openuem-worker/internal/common"
)

func main() {
	var err error
	w := common.NewWorker("openuem-agent-worker")
	configured, err := w.ConfigureIndividualAgentService()
	if err != nil {
		log.Fatal(err)
	}
	if configured {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := w.RunIndividualAgentWorker(ctx); err != nil {
			log.Fatal(err)
		}
		return
	}

	// Start Task Scheduler
	w.TaskScheduler, err = gocron.NewScheduler()
	if err != nil {
		log.Fatalf("[FATAL]: could not create task scheduler, reason: %v", err)
		return
	}
	w.TaskScheduler.Start()
	log.Println("[INFO]: task scheduler has been started")

	// Get config for service
	if err := w.GenerateCommonWorkerConfig("agent-worker"); err != nil {
		log.Printf("[ERROR]: could not generate config for agent worker: %v", err)
		if err := w.StartGenerateWorkerConfigJob("agent-worker", true); err != nil {
			log.Fatalf("[FATAL]: could not start generate config for worker: %v", err)
			return
		}
	}

	w.StartWorker(w.SubscribeToAgentWorkerQueues)

	// Keep the connection alive
	done := make(chan os.Signal, 1)
	signal.Notify(done, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	log.Println("[INFO]: the Agent worker is ready and waiting for requests")
	<-done

	w.StopWorker()
}
