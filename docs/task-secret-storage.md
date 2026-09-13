# Task secret storage and generator compatibility

The worker now consumes the shared tasksecrets package from the pinned
OpenUEM NATS module. It accepts legacy SSH plaintext and authenticated version-one
SSH envelopes. Local account passwords retain their historical AES-GCM hex
format. Damaged ciphertext, missing/wrong keys, unsupported SSH envelope versions
and oversized values return a generic error and no partial configuration.
Short hex passwords no longer enter the unsafe historical encryption probe.

Upgrade all workers to this change before starting a console that encrypts SSH
passphrases or migrates task secrets. Stop every old worker and old console during
the final transition. Old workers pass encrypted SSH storage bytes as literal
passphrases. They cannot safely resume against an upgraded database. Use the same
32-byte raw encryption master key in console and worker; protect and back it up
using the existing service credential mechanisms. This change does not rotate
keys or add a new agent protocol. Agents still receive the existing configuration
fields over the authenticated transport.

Both account generators now finish building their configuration after successful
password decryption and keep stored task fields unchanged. Ansible also decrypts
SSH passphrases and recognizes RemoveUnixLocalUser tasks. Repeated generation
uses the same stored source safely. Ordinary task ordering and task versions are
unchanged.

Tests cover independent historical password encryption, encrypted and legacy SSH
values, repeated generation without source mutation, account removal after the
secret-bearing task, and rejection without partial output. The Ansible cases run
with owned PostgreSQL agents for Linux and macOS. Windows configuration tests do
not require a physical endpoint. Shared codec tests separately cover format
compatibility, tampering, key failures, bounds and fuzzed decoder inputs. These
checks establish configuration generation; they do not claim device execution.
