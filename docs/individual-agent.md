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
`the-luap/openuem-nats` at `2af211c88d57` using a Go module replacement. Normal
builds and CI do not require a sibling checkout or a local `go.work` file.

On Linux, run the database and real-broker checks against an isolated database:

```sh
AGENT_ENROLLMENT_TEST_DATABASE_URL='<isolated PostgreSQL DSN>' go test -race -count=1 ./internal/common ./internal/models
```

Tests create and drop unique schemas. They cover canonical body identity,
organization/site denial, profile selection, task ownership, preservation of
newer schema fields, and real NATS messages reaching the actual deployment
exclusion handler. Forged reply addresses, foreign body IDs and a revoked sender
cannot mutate inventory. Linux and Windows cross-builds are also required.

This change implements the worker boundary. The production NKey service connection,
broker account configuration, console issuance UI, signed bootstrap/installers,
agent key storage and native-agent release integration are still being implemented.
The environment flag by itself is not a complete secure deployment.
