# NetBird observation persistence

The worker preserves the agent's structured NetBird profile identities through the
shared `netbirdstate` codec. ID and display label remain separate; commas and
duplicate labels with different IDs do not change selectable handles. Current
reports use versioned JSON in the existing profile text column. Legacy report
handle lists remain supported, including the old collector's single empty entry.

Failed observations with `Netbird.Error` and invalid profile identities are
rejected before upsert. Previously confirmed NetBird state remains stored; an
unconfirmed collection must not silently turn into an absent installation. The
model write has a ten-second context. This behavior requires a current agent to
emit the explicit failure field; old agents may still send misleading zero data.

Owned PostgreSQL tests exercise successful identity storage and confirm that
failure, duplicate handles and nil reports cannot replace prior installation and
profile data. This does not complete durable device/provider action execution,
authority/source locks, immutable observation history, provider-peer ownership or
real-provider/device acceptance.
