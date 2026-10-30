# Contributing to SRG

Discuss new adapters and protocol changes in this repository's issues.
Keep deployment-specific inventories, URLs, fingerprints and secrets out of
portable examples and release archives. Never include production tokens in a
bug report. Report suspected credential exposure privately to the operator and
revoke affected credentials immediately; this project has no dedicated
security-response SLA.

A change must describe its operation, target scope, required backend privilege,
preconditions, verification, timeout and ambiguous-failure behavior. Tests must
prove denial and recovery behavior, not merely successful mocks. New resource
operations are not automatically routine: power, locks, alarms, storage, network
isolation and production deployments need explicit policy review. Do not add
arbitrary command, URL, image, compose-file, module or service-call parameters.

Run `python3 -m unittest discover -p 'test_*.py'` and `git diff --check`. Protocol
changes must update PROTOCOL.md and compatibility tests. Keep v1 read clients
working. Document limitations honestly; do not claim external standardization,
independent security review, exactly-once execution or immutable logging.
