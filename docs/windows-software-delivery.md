# Individual Windows software RPC

The worker routes the canonical bounded `software` protocol on the authenticated
device's private request/reply subjects. It requires active individual enrollment,
Windows platform, matching payload identity and exactly one inventory site owned
by the enrolled organization. The registry identity lock precedes inventory/site
locks, and delivery/result/audit commit before any reply is sent.

New registration and polling require inventory status `Enabled` or `No contact`.
Devices awaiting admission or disabled devices cannot receive new tasks. Disabled
devices can still submit signed results for previously delivered work in their
unchanged authorized scope. Every result requires an additional proof from the
current certificate; an old broker connection is insufficient after renewal.

The worker advertises `software_task_version` only for Windows with the required
registry schema. Legacy configuration advertises zero. A joined maintenance loop
expires undelivered work and retains delivered timeout as uncertainty. Uncertain
and restart-required tasks remain reserved, with immutable original evidence.

The worker does not receive the enrollment CA signing key or construct executable
plans. Explicit console dispatch and the native agent executor remain separate
integration work. This RPC does not automatically promote console preparations.

Tests use the real worker, isolated PostgreSQL and authenticated WSS: admission,
registration, encrypted delivery, absent/disabled inventory denial, failed audit
rollback, exact receipt retry, disabled-device receipt recovery, missing current
proof and revocation. The injected result is protocol evidence, not installation
acceptance on a physical Windows endpoint.
