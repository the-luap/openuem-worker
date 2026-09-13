# NetBird profile migration and provider credentials

The managed NetBird connection-command migration rejects legacy NetBird profile
mutations. `GenerateNetbirdConfig` returns an explicit admission error for any
active install, uninstall or registration step before reading provider settings,
decrypting tokens, looking up peers or creating setup keys. Disabled steps and
profiles without NetBird mutations return an empty NetBird configuration.

Current dispatch callers withhold the entire profile after this error, including
its other task types. This temporary restriction prevents provider side effects
for tasks that the updated agent would reject. It does not represent completed
managed profile support. No saved tasks, order values or credentials are changed.
Deploy compatible console, agent and worker versions together; there is no
automatic protocol negotiation or fallback to legacy mutation messages.

Owned PostgreSQL and local TLS fixtures verify rejection without any provider
request for plaintext, encrypted, corrupt, missing-key and empty credentials.
The original stored credential value remains unchanged. Order regression tests
continue to exercise WinGet and Ansible generation and check stored-task
immutability when NetBird generation is rejected. Full model/common PostgreSQL
race suites pass in 2.861 and 3.560 seconds.

Staged managed installation/registration must persist admission, provider key
creation, delivery and cleanup evidence with current authority before this path
can be enabled. Lost provider responses must not cause another key creation.
Authoritative peer association, trusted installers and physical/provider
acceptance also remain open. Shared `netbirdapi` transport validation and its
owned tests remain available for the future integration; they alone do not
provide durable lifecycle semantics.
