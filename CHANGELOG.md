# Changelog

## 0.2.0

### Migration

- Policies require explicit `read_grants` to expose resources. This tightening
  shipped before versioned releases; an absent map now grants no reads.
- Install **all** runtime modules together: gateway.py, control.py,
  action_adapters.py, audit.py, ledger.py and ssh_transport.py. Preserve identities,
  backend secrets and the existing SQLite ledger. Follow INSTALL.md.
- Custom adapters now receive `context` in `prepare(action, target, context)` and
  `execute(action, target, before, context)`. Use `context.request_id` and
  `context.audit`; adapter instances no longer carry mutable request state.
- The audit index is created automatically on existing ledgers. Hash encoding,
  audit records and the SRG/1 wire protocol are unchanged.

### Improvements

- Correct read-authorization documentation and add reference configuration and
  response schemas, validated examples and negative schema tests in CI.
- Reproducible archives with normalized metadata, no external source fallback,
  one distribution version and SHA256 sidecars.
- Shared SSH endpoint validation/command construction; independent ledger module;
  explicit immutable per-request adapter context; indexed per-client audit reads.
- Python 3.11–3.14 CI, full PR-range whitespace checks, focused lint checks,
  dependency updates and CLI/reader/release regression tests.

## Initial unversioned reference

- mTLS, explicit read/write grants, durable plans, scoped SSH/HA actions and auditing.
- Docker writes pin immutable IDs; corrupt audit ledgers block startup.
- Generic setup examples and real Linux/systemd installation smoke tests.
