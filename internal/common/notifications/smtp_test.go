package notifications

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-uem/ent"
	"github.com/open-uem/ent/settings"
	"github.com/open-uem/nats/legacysecret"
	"github.com/open-uem/utils"
	"github.com/wneessen/go-mail"
)

func TestSMTPClientDecryptsWithoutMutatingSettings(t *testing.T) {
	certSource := httptest.NewTLSServer(nil)
	cert := certSource.TLS.Certificates[0]
	roots := x509.NewCertPool()
	roots.AddCert(certSource.Certificate())
	certSource.Close()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(raw, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	key := strings.Repeat("k", 32)
	password := "owned-smtp-password"
	encrypted, err := utils.EncryptSensitiveField(password, key)
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan string, 2)
	failures := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := listener.Accept()
			if err != nil {
				failures <- err
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			reader := bufio.NewReader(conn)
			fmt.Fprint(conn, "220 owned.example ESMTP\r\n")
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				switch {
				case strings.HasPrefix(line, "EHLO "):
					fmt.Fprint(conn, "250-owned.example\r\n250 AUTH PLAIN\r\n")
				case strings.HasPrefix(line, "AUTH PLAIN "):
					encoded := strings.TrimSpace(strings.TrimPrefix(line, "AUTH PLAIN "))
					decoded, err := base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						conn.Close()
						failures <- fmt.Errorf("invalid owned authentication encoding")
						return
					}
					parts := strings.Split(string(decoded), "\x00")
					if len(parts) != 3 {
						conn.Close()
						failures <- fmt.Errorf("invalid owned authentication tuple")
						return
					}
					captured <- parts[2]
					fmt.Fprint(conn, "235 authenticated\r\n")
				case strings.HasPrefix(line, "QUIT"):
					fmt.Fprint(conn, "221 goodbye\r\n")
					conn.Close()
				default:
					fmt.Fprint(conn, "500 unsupported owned command\r\n")
				}
			}
			conn.Close()
		}
		failures <- nil
	}()
	configuration := &ent.Settings{SMTPServer: "127.0.0.1", SMTPPort: port, SMTPUser: "owned", SMTPPassword: encrypted, SMTPAuth: "PLAIN", SMTPEncryptionType: settings.SMTPEncryptionTypeSmtps}
	for i := 0; i < 2; i++ {
		client, cleanup, err := prepareSMTPClient(t.Context(), configuration, key, &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
		if err != nil {
			t.Fatal(err)
		}
		if err = client.SetTLSConfig(&tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		err = client.DialWithContext(ctx)
		cancel()
		if err != nil {
			t.Fatal("owned TLS SMTP authentication failed")
		}
		client.Close()
		cleanup()
		select {
		case actual := <-captured:
			if actual != password {
				t.Fatal("SMTP did not receive the decrypted password")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("owned SMTP capture timed out")
		}
		if configuration.SMTPPassword != encrypted {
			t.Fatal("SMTP client mutated stored ciphertext")
		}
	}
	if err := <-failures; err != nil {
		t.Fatal("owned SMTP fixture failed")
	}
}

func TestSMTPClientRejectsUnreadableCredentialsWithoutDialing(t *testing.T) {
	key := strings.Repeat("k", 32)
	stored, err := legacysecret.Seal("owned-password", key)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ value, key string }{{stored, ""}, {stored, strings.Repeat("z", 32)}, {strings.Repeat("a", 56), key}, {strings.Repeat("x", legacysecret.MaxPlainSize+1), key}} {
		configuration := &ent.Settings{SMTPServer: "smtp.example.invalid", SMTPPort: 587, SMTPUser: "owned", SMTPPassword: entry.value, SMTPAuth: "PLAIN"}
		client, cleanup, err := PrepareSMTPClient(t.Context(), configuration, entry.key)
		cleanup()
		if client != nil || err != legacysecret.ErrUnavailable {
			t.Fatal("invalid credential produced an SMTP client")
		}
		if configuration.SMTPPassword != entry.value {
			t.Fatal("invalid credential mutated settings")
		}
	}
	for _, plain := range []string{"", "aabb"} {
		configuration := &ent.Settings{SMTPServer: "smtp.example.invalid", SMTPPort: 587, SMTPUser: "owned", SMTPPassword: plain, SMTPAuth: "PLAIN"}
		if _, cleanup, err := PrepareSMTPClient(t.Context(), configuration, key); err != nil {
			t.Fatal("short legacy SMTP plaintext was rejected")
		} else {
			cleanup()
		}
	}
}

// Exercise the library's whole SMTP session, including phases after its
// dial-only context has already been canceled internally.
func TestSMTPClientCustomSTARTTLSPortAndOperationDeadlines(t *testing.T) {
	for _, scenario := range []struct{ name, encryption, stall string }{
		{"custom-starttls-port", "starttls", ""},
		{"legacy-default-requires-starttls", "none", ""},
		{"greeting-deadline", "starttls", "greeting"},
		{"starttls-deadline", "starttls", "starttls"},
		{"authentication-deadline", "smtps", "auth"},
		{"data-deadline", "smtps", "data"},
		{"quit-deadline", "smtps", "quit"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			certificate := httptest.NewTLSServer(nil)
			serverTLS := &tls.Config{Certificates: certificate.TLS.Certificates, MinVersion: tls.VersionTLS12}
			roots := x509.NewCertPool()
			roots.AddCert(certificate.Certificate())
			certificate.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			reached := make(chan struct{}, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))
				if scenario.encryption == "smtps" {
					conn = tls.Server(conn, serverTLS)
				}
				reader := bufio.NewReader(conn)
				stall := func(stage string) bool {
					if scenario.stall != stage {
						return false
					}
					reached <- struct{}{}
					_, _ = reader.ReadByte() // Cancellation must close the client socket.
					return true
				}
				if stall("greeting") {
					return
				}
				fmt.Fprint(conn, "220 owned.example ESMTP\r\n")
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "EHLO "):
						fmt.Fprint(conn, "250-owned.example\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n")
					case strings.HasPrefix(line, "STARTTLS"):
						if stall("starttls") {
							return
						}
						fmt.Fprint(conn, "220 begin TLS\r\n")
						conn = tls.Server(conn, serverTLS)
						reader = bufio.NewReader(conn)
					case strings.HasPrefix(line, "AUTH PLAIN "):
						if stall("auth") {
							return
						}
						fmt.Fprint(conn, "235 authenticated\r\n")
					case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"), strings.HasPrefix(line, "NOOP"), strings.HasPrefix(line, "RSET"):
						fmt.Fprint(conn, "250 accepted\r\n")
					case strings.HasPrefix(line, "DATA"):
						fmt.Fprint(conn, "354 send body\r\n")
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
						}
						if stall("data") {
							return
						}
						fmt.Fprint(conn, "250 queued\r\n")
					case strings.HasPrefix(line, "QUIT"):
						if stall("quit") {
							return
						}
						fmt.Fprint(conn, "221 goodbye\r\n")
						return
					default:
						fmt.Fprint(conn, "500 unsupported owned command\r\n")
					}
				}
			}()
			limit := 3 * time.Second
			if scenario.stall != "" {
				limit = 500 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), limit)
			defer cancel()
			configuration := &ent.Settings{SMTPServer: "127.0.0.1", SMTPPort: port, SMTPAuth: "PLAIN", SMTPUser: "owned", SMTPPassword: "owned-test", SMTPEncryptionType: settings.SMTPEncryptionType(scenario.encryption)}
			client, cleanup, err := prepareSMTPClient(ctx, configuration, "", &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12})
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			message := mail.NewMsg()
			if err = message.From("owned@example.invalid"); err != nil {
				t.Fatal(err)
			}
			if err = message.To("owned@example.invalid"); err != nil {
				t.Fatal(err)
			}
			message.Subject("Owned SMTP transport test")
			message.SetBodyString(mail.TypeTextPlain, "Owned fixture only.")
			start := time.Now()
			err = client.DialAndSendWithContext(ctx, message)
			if scenario.stall == "" {
				if err != nil {
					t.Fatal("owned STARTTLS message failed", err)
				}
			} else {
				select {
				case <-reached:
				default:
					t.Fatal("SMTP did not reach the stalled phase")
				}
				if time.Since(start) > 2*time.Second {
					t.Fatal("SMTP operation exceeded its context bound")
				}
				if scenario.stall != "quit" && err == nil {
					t.Fatal("stalled SMTP operation reported success")
				}
			}
			cleanup()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("owned SMTP connection did not close")
			}
		})
	}
}
