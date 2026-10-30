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


## Development checks and releases

The gateway and CLI use only the standard library. Optional development tools
are pinned separately:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/ruff check .
.venv/bin/python ci/check-schemas.py
.venv/bin/python -m unittest discover -p 'test_*.py'
```

CI tests Python 3.11–3.14; passing on another interpreter does not establish
supported compatibility. Runtime modules added during refactors must also be
included in the release manifest, install commands and systemd smoke test.
Update `version.py` and CHANGELOG.md together. After CI succeeds, tag the release
`v<version>` on that tested commit. Build the archive with `make-release.py` and
verify its `.sha256` receipt. Reproducibility assumes the same source and build
toolchain; normalized metadata removes dependence on local paths/ownership/times. The included manifest is deliberately an allowlist;
never archive an entire operator checkout. Follow ROADMAP.md for deferred work.
