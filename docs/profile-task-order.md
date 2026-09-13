# Deterministic task order in generated profiles

The worker now loads tasks for all four assigned-profile queries in stored order,
then task ID, with PostgreSQL's ascending NULL placement. This matches the console's
read-only task list. Profiles assigned to all devices or through tags, including
explicit profile-ID requests, use the same ordering.

The pinned Ent model represents the nullable order column as a plain integer.
After the ordered query, the worker therefore gives each loaded task a consecutive
position in memory. This prevents the existing WinGet, Ansible and NetBird
configuration generators from treating a stored NULL as zero and moving it ahead
of positively ordered tasks. Tied positions are resolved by ID. Disabled and
platform-ineligible tasks retain the relative order of the remaining generated
entries. No stored task order, version, configuration or profile assignment changes
when a profile is read or configuration is generated.

This is compatible with consecutive orders persisted by the console's reorder,
delete and clone actions. It also handles older zero, tied, gapped and NULL values
before such a mutation. There is no data migration or broker protocol change.

## Verification

A PostgreSQL regression test reproduced the previous unordered task result and
lost NULL placement. It now checks all four assigned-profile queries, runtime
positions and byte-for-byte equivalent stored task JSON before and after reads.
A separate PostgreSQL test runs the actual WinGet, Ansible and NetBird generators
on zero/tied/gapped/NULL positions with a disabled task. Generated task identifiers
follow the expected order and the database remains unchanged. The NetBird case
uses installation configuration and performs no provider request.

The full worker model and common-package PostgreSQL/race suites pass in 2.680
and 3.269 seconds respectively. The complete Linux build also passes.

These checks establish ordering of generated configuration, not physical-device
execution or WinGet dependency semantics. Broader profile revisions, concurrent
authority/assignment snapshots, runtime acceptance and hardware/provider checks
remain separate roadmap work.
