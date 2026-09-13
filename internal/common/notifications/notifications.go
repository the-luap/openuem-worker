package notifications

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/open-uem/ent"
	smtpsettings "github.com/open-uem/ent/settings"
	"github.com/open-uem/nats"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/nats/smtptransport"
	"github.com/wneessen/go-mail"
)

func PrepareMessage(notification *nats.Notification, settings *ent.Settings) (*mail.Msg, error) {
	if notification.From == "" {
		if settings.MessageFrom != "" {
			notification.From = settings.MessageFrom
		} else {
			return nil, fmt.Errorf("from cannot be empty")
		}
	}

	m := mail.NewMsg()
	if err := m.From(settings.MessageFrom); err != nil {
		return nil, fmt.Errorf("failed to set From address: %v", err)
	}
	if err := m.To(notification.To); err != nil {
		return nil, fmt.Errorf("failed to set To address: %v", err)
	}

	m.Subject(notification.Subject)
	templateBuffer := new(bytes.Buffer)
	if err := EmailTemplate(notification).Render(context.Background(), templateBuffer); err != nil {
		return nil, fmt.Errorf("failed to set To address: %v", err)
	}
	m.SetBodyString(mail.TypeTextHTML, templateBuffer.String())

	if notification.MessageAttachFileName != "" {
		data, err := base64.StdEncoding.DecodeString(notification.MessageAttachFile)
		if err != nil {
			return nil, fmt.Errorf("failed to decode file content: %v", err)
		}
		reader := bytes.NewReader(data)
		err = m.AttachReader(notification.MessageAttachFileName, reader)
		if err != nil {
			return nil, fmt.Errorf("failed to attach file: %v", err)
		}
	}

	if notification.MessageAttachFileName2 != "" {
		data, err := base64.StdEncoding.DecodeString(notification.MessageAttachFile2)
		if err != nil {
			return nil, fmt.Errorf("failed to decode file content: %v", err)
		}
		reader := bytes.NewReader(data)
		err = m.AttachReader(notification.MessageAttachFileName2, reader)
		if err != nil {
			return nil, fmt.Errorf("failed to attach file: %v", err)
		}
	}
	return m, nil
}

func PrepareSMTPClient(ctx context.Context, settings *ent.Settings, encryptionMasterKey string) (*mail.Client, func(), error) {
	return prepareSMTPClient(ctx, settings, encryptionMasterKey, nil)
}

func prepareSMTPClient(ctx context.Context, settings *ent.Settings, encryptionMasterKey string, tlsOptions *tls.Config) (*mail.Client, func(), error) {
	noop := func() {}
	if settings == nil {
		return nil, noop, fmt.Errorf("SMTP settings are unavailable")
	}
	password, err := legacysecret.Open(settings.SMTPPassword, encryptionMasterKey)
	if err != nil {
		return nil, noop, err
	}
	if tlsOptions == nil {
		tlsOptions = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	tlsOptions = tlsOptions.Clone()
	tlsOptions.ServerName = strings.TrimSpace(settings.SMTPServer)
	var implicitTLS *tls.Config
	if settings.SMTPEncryptionType == smtpsettings.SMTPEncryptionTypeSmtps {
		implicitTLS = tlsOptions
	}
	transport := smtptransport.New(ctx, implicitTLS)
	options := []mail.Option{mail.WithPort(settings.SMTPPort), mail.WithTLSConfig(tlsOptions), mail.WithDialContextFunc(transport.DialContext)}
	if settings.SMTPAuth != "NOAUTH" {
		options = append(options, mail.WithSMTPAuth(mail.SMTPAuthType(settings.SMTPAuth)), mail.WithUsername(settings.SMTPUser), mail.WithPassword(password))
	}
	client, err := mail.NewClient(strings.TrimSpace(settings.SMTPServer), options...)
	if err != nil {
		transport.Close()
		return nil, noop, err
	}
	if implicitTLS != nil {
		client.SetSSL(true)
	} else {
		client.SetTLSPolicy(mail.TLSMandatory)
	}
	return client, transport.Close, nil
}
