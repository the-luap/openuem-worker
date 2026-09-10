# Individual agent worker container

Build the dedicated runtime locally:

```sh
docker build -f Dockerfile.individual -t openuem-individual-worker:local .
python3 scripts/check-individual-image.py openuem-individual-worker:local
```

The image uses a digest-pinned Go 1.26.8 builder and a scratch runtime containing
one static executable and its license. It runs as UID/GID 65532, exposes no port,
selects individual agent mode and starts `agents start` by default. The build
context excludes credentials, configuration files, tests and sibling checkouts.
It does not publish an image or install a host service.

Use the [individual service configuration](individual-agent.md#private-service-connection)
with a protected `OPENUEM_AGENT_DATABASE_URL_FILE`,
`OPENUEM_AGENT_WORKER_KEY_FILE`, `OPENUEM_AGENT_BROKER_CA_FILE` and, for encrypted
tasks, `ENCRYPTION_MASTER_KEY_FILE`. Mount only this worker's inputs read-only;
private files must be owned by the runtime account or a trusted administrator
with the library's required private permissions. Provide the public database CA
at the path named in the verify-full URL. The scratch image has no system CA
bundle, so the broker CA must be explicitly mounted. Keep individual mode enabled.
Database bootstrap and enrollment registry migration must finish before startup.

The runtime can run with `--read-only --cap-drop ALL --security-opt
no-new-privileges` and bounded memory/process resources. It needs outbound access
to its private PostgreSQL and TLS broker services; no host port is published.
The default individual path needs no PID file or writable working directory.
It does not use the legacy healthcheck command, which depends on legacy service
state. SIGTERM cancels the individual worker and joins its shutdown.

The offline image audit verifies the actual image configuration, exact permitted
filesystem, help output and rejected startup without credentials. CI builds and
audits the image on native Linux amd64 and arm64. The existing real-broker process
test runs the executable extracted from the distribution image against its
synthetic PostgreSQL schema. The console's combined database fixture supplies
generated private TLS and provisioned application credentials.

Complete service topology, ownership preparation, reference installation and
signed release publication remain separate unfinished deployment work.
