# NetBird token compatibility in worker tasks

NetBird registration tasks now decode stored access tokens with the same bounded
`github.com/open-uem/nats/legacysecret` reader used for SMTP and legacy account
passwords. Decryption uses a local value. Successful decryption continues peer
lookup and one-off setup-key generation, then preserves subsequent tasks in the
configuration. It no longer returns an empty successful configuration early.

Short legacy hex and ordinary plaintext remain readable. Plausible AES-GCM hex
must authenticate; wrong or missing keys, corrupt/oversized values and empty
tokens fail before the registration task contacts the provider. Stored
ciphertext is unchanged. An error returns no partial task configuration.

Owned PostgreSQL and local HTTP provider tests verify actual plaintext
Authorization, one-off key requests, the following installation task, immutable
storage and failure without a provider call for unreadable tokens. Existing
profile-order tests cover the three configuration generators.

This change does not implement NetBird settings editing or migration. Existing
provider HTTP helpers, their timeout/redirect/response handling and durable
setup-key admission still need replacement. Earlier provider side effects are
not rolled back if a later task fails. This is not a claim of complete NetBird
provider security or production acceptance.
