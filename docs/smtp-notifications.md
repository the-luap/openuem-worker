# Current SMTP configuration for account notifications

The notification worker reads one bounded global settings snapshot before each
account email or user-certificate email. It uses that snapshot for both message
construction and the SMTP client. Organization settings never substitute for a
missing or ambiguous global row. The reload-settings subject remains a
compatibility probe; saving SMTP settings no longer requires that message.

The shared `github.com/open-uem/nats/legacysecret` reader supports historical
AES-GCM hex ciphertext and bounded legacy plaintext. It authenticates plausible
ciphertext, rejects corrupt/oversized values and never changes the settings
object when decrypting. The raw master key must match the console. Deploy this
worker before the console's audited SMTP migration. There is no automatic
version negotiation or key rotation in this change.

SMTP follows the configured authentication selection. STARTTLS and legacy
`none` require TLS; `smtps` starts TLS immediately. Both verify the SMTP hostname
and require TLS 1.2 or newer. Custom ports are preserved. The shared
`smtptransport` lifecycle closes sockets on operation cancellation even after
the mail library finishes its dial-only context. Message handling is bounded to
30 seconds, including greeting, TLS, authentication, data and QUIT. Both
notification handlers release the transport, and configuration/delivery errors
are logged without provider details or secrets.

The separate console reminder pipeline has organization-aware settings and its
own transport. The console editor's durable test-attempt receipt is also a
separate flow. This change does not provide exactly-once account delivery or
replace existing queue acknowledgment/retry behavior.

Owned PostgreSQL tests check fresh snapshots, scope isolation, missing or
ambiguous globals and oversized configuration. Owned TLS SMTP tests verify actual
password authentication twice without mutating ciphertext, custom STARTTLS
ports, and cancellation during greeting, STARTTLS, authentication, data and QUIT.
No production mailbox delivery is claimed.
