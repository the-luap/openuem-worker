# Individual agent request boundary

Set `OPENUEM_INDIVIDUAL_AGENT_MODE=true` on the agent worker to subscribe only to
versioned individual-agent request subjects. Empty or `false` retains the legacy
subscriptions; any other value is a configuration error. The individual mode
requires the shared enrollment registry schema and a broker that authenticates
individual keys with device-specific subject permissions. Never mix shared-agent
credentials with this device account.

The worker validates the subject and private reply prefix before responding or
touching the database. It resolves current active enrollment on each request,
checks the body device ID and any supplied organization/site, and serializes the
checked payload before calling existing handlers. Missing report/config scope is
filled from the registry. Foreign scope, unsupported operations, unknown fields,
malformed JSON and oversized payloads are denied. Broker disconnection is separate:
requests already arriving on an open but revoked connection are also denied.

Existing desktop records must agree with enrollment scope. Profile lookups apply
the intersection of their explicit organization and site limits, including when
a caller supplies a profile ID. Assignment to all devices or to the device's tags
is still required. Task reports may reference only tasks belonging to the approved
profile. Startup schema creation no longer drops columns or indexes owned by a
newer component's additive migrations.

The module pins the published shared implementation from
`the-luap/openuem-nats` at `2d4a7c6e8561` using a Go module replacement. Its
[CI passed](https://github.com/the-luap/openuem-nats/actions/runs/34282835187), including
TLS/NKey reconnection and native Windows key-file ACL tests. Normal
builds and CI do not require a sibling checkout or a local `go.work` file.

## Mac hardware evidence

The individual worker accepts the separate version 1 `hardware` operation only
for active Mac identities. The body is limited to 16 KiB, has a matching device
ID, and contains normalized model, serial, platform UUID, optional provisioning
UDID and optional MDM binding proof. The ordinary inventory report is unchanged.
The registry commits evidence under the current organization/site and locks the
identity against concurrent revocation. It stores a hash of the binding token,
never its plaintext. The successful receipt is sent only after commit; unavailable
schema, invalid data and denied identities receive a generic denial.

The individual Mac configuration advertises `hardware_inventory_version: 1`
only when registry migration 003 is available. Legacy configuration and Windows
identities never advertise it. Configuration errors remain errors even when a
later setting lookup succeeds. Upgrade the registry/console and broker authorization
service before the worker, then reconnect agents to refresh broker permissions.
Update agents last. Broker service permissions must include the new operation.
An existing desktop record must agree with enrollment scope; first observations
may precede the ordinary inventory row. Neither a serial match nor this evidence
table creates an MDM association or grants additional administration rights.

The real-broker test covers both Windows and Mac enrollments, persisted proof
hashes, the capability disappearing when its schema is unavailable, foreign body
IDs and requests on a still-open connection after revocation. Native Mac linking
and proof lifecycle are implemented separately in the console.

## Private FileVault validation

Registry migration 004 adds the individual Mac `recovery` RPC. A successful Mac
configuration advertises `recovery_task_version: 1` only while all recovery tables
are available. Broker permissions must include this operation before the worker
starts. Missing subscriptions fail startup. Durable command filters are unchanged.

The worker binds canonical requests of at most 8 KiB to the authenticated subject,
current Mac identity and existing desktop inventory scope. The registry rechecks
the signing certificate and organization/site under transaction locks. Recipient
registration requires a signed server challenge. A task is encrypted for a separate
agent X25519 key; this path does not need the console's encryption master key.

Results authenticate the task, native Mac, recovery-key version, recipient epoch,
expiry, random nonce and exact outcome with the agent's RSA signature. Exact
duplicate acknowledgments are idempotent. Committing a result also commits its
audit record and erases the pending ciphertext. Revocation or recipient replacement
cancels older pending tasks. Every 30 seconds the worker erases up to 256 expired
or invalid envelopes, including offline agents, without waiting on active tasks.

The worker does not mark a FileVault key verified. The console must independently
check its current native/agent association, permissions, current recovery key and
the stored signed result. Integration tests exercise recipient registration,
encrypted delivery, signed negative outcomes, duplicate acknowledgments, schema
capability removal, Windows denial and revocation through the real TLS broker.

## Private FileVault rotation

Registry migration 005 adds the separate version 1 `rotation` RPC. Individual Mac
configuration advertises `rotation_task_version: 1` only when both the rotation
and recovery schemas are available. Legacy and Windows agents receive no rotation
capability. Deploy the shared registry and broker permissions before this worker.

Every rotation request holds current registry identity, inventory row, scope edges
and site ownership locks through task delivery or result commit. The lock order
matches console authorization. Concurrent inventory deletion, edge insertion or
removal, and site reassignment cannot invalidate a checked scope before commit.
The registry rechecks certificate lifetime after lock waits and reserves two minutes
after the execution deadline for receipt publication. No encrypted task or successful
acknowledgment leaves the worker before its database transaction commits.

The old PRK is encrypted for the agent recipient. Any returned candidate is encrypted
for a separate, per-attempt console key and signed by the current agent certificate.
The worker has neither decryption key. It accepts only a receipt for a task previously
delivered under that exact identity and recipient epoch, including an authentic late
receipt after the execution deadline. A result and its audit entry commit together;
an identical retry is acknowledged without duplicating the audit. Expiry maintenance
scrubs request ciphertext and preserves uncertainty after a delivered task expires.
It uses its own bounded context so validation maintenance cannot consume its timeout.

An uncertain attempt prevents another rotation. This transport does not resolve
uncertainty, authorize an administrator, store a native escrow key, or establish
which candidate is current. Those are console responsibilities. The protected agent
journal and OS lease independently prevent repeating an admitted mutation.

PostgreSQL tests exercise inventory locks and authorization after a waiting scope
change. The real TLS broker fixture covers encrypted delivery and result recovery,
undelivered and forged result denial, absent inventory scope, atomic audit rollback,
idempotent receipts, schema capability removal, Windows denial and revoked identities.
These fixtures never execute FileVault commands or change device encryption.

## Private service connection

Both `openuem-worker agents start` and the installed Linux/Windows agent-worker
services recognize individual mode before reading legacy certificate/INI settings.
Set these variables in the protected service environment:

| Variable | Purpose |
| --- | --- |
| `OPENUEM_INDIVIDUAL_AGENT_MODE=true` | Enable the individual runtime and versioned queues |
| `OPENUEM_AGENT_DATABASE_URL` | PostgreSQL URL for the existing console database and initialized enrollment registry |
| `OPENUEM_AGENT_BROKER_URLS` | Explicit comma-separated private `tls://` broker origins |
| `OPENUEM_AGENT_WORKER_KEY_FILE` | Protected NKey user seed assigned to the trusted agent worker |
| `OPENUEM_AGENT_BROKER_CA_FILE` | Optional private broker CA bundle; otherwise system roots |
| `OPENUEM_AGENT_BROKER_CLIENT_CERT_FILE` | Optional TLS client certificate if the private broker requires mutual TLS |
| `OPENUEM_AGENT_BROKER_CLIENT_KEY_FILE` | Matching protected TLS private key |
| `ENCRYPTION_MASTER_KEY` | Existing encrypted task-field key, when those tasks are used |

Private files must pass the library's Unix ownership/mode or Windows ACL checks.
The connection always verifies TLS and authenticates the service NKey; it cannot
discover a different broker, use cleartext, or fall back to shared certificates.
The worker requires registry initialization. Missing configuration, invalid files,
untrusted TLS and denied subscriptions stop startup. Asynchronous messaging or
permission failures return a service error, allowing supervised restart. Ordinary
broker disconnects reconnect with the same configured origins and restore queues.

Give this separate trusted user only the versioned request subscriptions
`uem.v1.agent.*.request.<operation>` listed by `enrollment.Operations()`. Deny normal
publishing and grant one temporary response per received request. Do not grant
this worker auth-callout, system-account or consumer-management access. Broker
service provisioning must keep its private seed out of endpoint packages.

Shutdown stops accepting requests and waits for in-flight handlers before closing
the database. Preflight identity/scope queries observe cancellation; some inherited
deployment/inventory handlers still use their original background contexts. A
strict time bound across every inherited handler is additional operational work.

On Linux, run the database and real-broker checks against an isolated database:

```sh
AGENT_ENROLLMENT_TEST_DATABASE_URL='<isolated PostgreSQL DSN>' go test -race -count=1 ./internal/common ./internal/models ./internal/commands
```

Tests create and drop unique schemas. They cover canonical body identity,
organization/site denial, profile selection, task ownership, preservation of
newer schema fields, and the production worker runtime connecting with a protected
service NKey to a real TLS NATS server. Messages reach the actual deployment
exclusion handler. Partial subscription permissions stop the runtime, and CLI
tests verify startup no longer requires legacy connection flags. Forged reply
addresses, foreign body IDs and a revoked sender
cannot mutate inventory. Linux and Windows cross-builds are also required.

This change implements the worker boundary and service runtime. The production
broker account configuration, console issuance UI, signed bootstrap/installers,
agent key storage and native-agent release integration are still being implemented.
The environment flag by itself is not a complete secure deployment.
