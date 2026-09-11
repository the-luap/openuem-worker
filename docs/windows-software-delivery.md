# Individual Windows software RPC

The worker routes canonical bounded execution and read-only reconciliation
protocols on the authenticated device's private `software` request/reply subjects.
Each grammar has a distinct mandatory protocol identifier. It requires active individual enrollment,
Windows platform, matching payload identity and exactly one inventory site owned
by the enrolled organization. The registry identity lock precedes inventory/site
locks, and delivery/result/audit commit before any reply is sent.

New registration and polling require inventory status `Enabled` or `No contact`.
Devices awaiting admission or disabled devices cannot receive new tasks. Disabled
devices can still submit signed results for previously delivered work in their
unchanged authorized scope. Every result requires an additional proof from the
current certificate; an old broker connection is insufficient after renewal.

The worker advertises `software_task_version` and the independent
`software_reconciliation_version` only for Windows with the complete registry
schema, including migration 013. Legacy configuration advertises zero for both.
A joined maintenance loop
expires undelivered work and retains delivered timeout as uncertainty. Uncertain
and restart-required tasks remain reserved, with immutable original evidence.
An explicitly queued reconciliation can read exact software state after a later
kernel boot. Only verified definite observation evidence releases that original
reservation; unknown, unavailable and same-boot observations leave it reserved.
The observation receipt, audit and any release commit together before reply.

The worker does not receive the enrollment CA signing key or construct executable
plans. The [console](https://github.com/the-luap/openuem-console/blob/3834fa9331f4a118504563126bb06937e1e798d9/docs/windows-software-requests.md)
now provides separately confirmed dispatch and read-only reconciliation, with
verified original-scope history and queued cancellation. The
[Windows service](https://github.com/the-luap/openuem-agent/blob/4157fb6583725d0e0fd20f03c94183dcc9e6c9c4/docs/windows-software-reconciliation.md)
joins native execution and read-only checks with protected receipt recovery.
This RPC does not automatically promote console preparations or queue another
installer after a definite reconciliation releases its original reservation.

Tests use the real worker, isolated PostgreSQL and authenticated WSS: admission,
registration, encrypted delivery, absent/disabled inventory denial, failed audit
rollback, exact receipt retry, disabled-device receipt recovery, missing current
proof and revocation. Reconciliation checks include independent capability
negotiation, missing schema, platform/scope/admission denial, delivery/report/release
audit rollback, retry after disabling inventory, original receipt immutability,
unknown-state reservation and verified release. The injected result is protocol evidence, not installation
acceptance on a physical Windows endpoint.
