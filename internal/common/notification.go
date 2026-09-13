package common

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/nats-io/nats.go"
	openuem_nats "github.com/open-uem/nats"
	"github.com/open-uem/openuem-worker/internal/common/notifications"
)

func (w *Worker) SendConfirmEmailHandler(msg *nats.Msg) {
	notification := openuem_nats.Notification{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	settings, err := w.Model.GetSMTPSettings(ctx)
	if err != nil {
		log.Println("[ERROR]: no SMTP settings found, retry in 5 minutes")
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	err = json.Unmarshal(msg.Data, &notification)
	if err != nil {
		log.Printf("[ERROR]: could not unmarshal notification request, reason: %v", err.Error())
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	mailMessage, err := notifications.PrepareMessage(&notification, settings)
	if err != nil {
		log.Printf("[ERROR]: could not prepare notification message, reason: %v", err.Error())
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	client, cleanup, err := notifications.PrepareSMTPClient(ctx, settings, w.EncryptionMasterKey)
	if err != nil {
		log.Print("[ERROR]: SMTP client configuration is unavailable")
		msg.NakWithDelay(5 * time.Minute)
		return
	}
	defer cleanup()
	if err := client.DialAndSendWithContext(ctx, mailMessage); err != nil {
		log.Print("[ERROR]: SMTP delivery could not be confirmed")
		msg.NakWithDelay(5 * time.Minute)
		return
	}
}

func (w *Worker) SendUserCertificateHandler(msg *nats.Msg) {
	notification := openuem_nats.Notification{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	settings, err := w.Model.GetSMTPSettings(ctx)
	if err != nil {
		log.Println("[ERROR]: no SMTP settings found, retry in 5 minutes")
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	if err = json.Unmarshal(msg.Data, &notification); err != nil {
		log.Printf("[ERROR]: could not unmarshal notification request, reason: %v", err.Error())
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	mailMessage, err := notifications.PrepareMessage(&notification, settings)
	if err != nil {
		log.Printf("[ERROR]: could not prepare notification message, reason: %v", err.Error())
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	client, cleanup, err := notifications.PrepareSMTPClient(ctx, settings, w.EncryptionMasterKey)
	if err != nil {
		log.Print("[ERROR]: SMTP client configuration is unavailable")
		msg.NakWithDelay(5 * time.Minute)
		return
	}

	defer cleanup()
	err = client.DialAndSendWithContext(ctx, mailMessage)
	if err != nil {
		log.Print("[ERROR]: SMTP delivery could not be confirmed")
		msg.NakWithDelay(5 * time.Minute)
		return
	}
}

// Reload remains a compatibility probe for older consoles. Every notification
// reads a fresh bounded snapshot, so delivery never relies on this message.
func (w *Worker) ReloadSettingsHandler(msg *nats.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := w.Model.GetSMTPSettings(ctx); err != nil {
		log.Print("[ERROR]: SMTP settings are unavailable")
		return
	}
	log.Print("[INFO]: SMTP settings are available")
}
