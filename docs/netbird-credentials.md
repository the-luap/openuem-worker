# NetBird credentials and bounded provider requests

NetBird registration tasks decode access tokens with the shared bounded
`github.com/open-uem/nats/legacysecret` reader. Decryption uses a local value.
Successful decryption continues peer lookup and one-off key creation, then
preserves subsequent tasks. It does not return an empty successful configuration
or alter stored ciphertext. Output follows task order without sorting the input
slice in place.

Short legacy hex and ordinary plaintext remain readable. Plausible AES-GCM hex
must authenticate. Wrong/missing keys, corrupt/oversized values and empty tokens
fail before that registration task contacts the provider. Configuration reads
select bounded URL/token fields for exactly the task's organization; there is no
fallback or creation while reading. Generation has a 30-second overall context.

Provider calls use the shared `netbirdapi` package: verified HTTPS, five-second
requests, one MiB responses, encoded peer filters, checked success statuses and
no redirects. Returned peer names are checked. Setup keys use structured JSON
with one-off use, a one-day lifetime and usage limit one. Group input is validated
before constructing JSON. Numeric and string key IDs are supported; masked,
revoked and reusable responses are rejected. POST bodies cannot be replayed after
an ambiguous reused-connection failure, and there is no application retry.

Use compatible workers and matching master keys for the console's audited token
migration. Existing HTTP management URLs must be changed to HTTPS with a trusted
certificate before this upgrade. There is no automatic version negotiation or
master-key rotation.

Owned PostgreSQL and local TLS provider tests verify plaintext Authorization,
one-off policy, subsequent tasks, stable stored ciphertext and failure before
provider contact for unreadable tokens. Existing profile-order tests cover the
three configuration generators. Shared transport tests cover protocol/identity
validation, redirects, response bounds, cancellation and unretried creation.

Durable NetBird command admission/recovery and source/authority held throughout
provider operations remain open. A timeout can follow an actual remote mutation;
earlier setup-key effects are not rolled back if a later task fails. This is not
exactly-once registration or complete provider security. Production provider and
physical endpoint acceptance remain separate.
