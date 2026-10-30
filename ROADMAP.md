# Remaining improvements

Version 0.2.0 improves protocol documentation and schemas, reproducible release
packaging, adapter request isolation, shared SSH handling, ledger structure and
indexing, Python compatibility checks, linting and regression tests. The server
remains serial; request-local adapter context does not make SQLite or execution
concurrency safe. Reader tests already existed; malformed-response coverage was
expanded rather than treating the path as wholly untested.

## Next: onboarding and operational security

- Certificate signing/renewal commands and expiry warnings.
- Offline credential/CA/host-key checks plus opt-in, read-only backend probes.
- Exact Home Assistant entity read allowlists, with explicit migration semantics.
- Audit checkpoints verified against independently retained receipts. Printing
  a timestamp and hash alone provides no independent anchoring or truncation defense.
- Distinct executor busy outcomes, preserving one-attempt semantics and no
  automatic retries after uncertain execution.

## Agent integration

- Optional stdio MCP wrapper, using existing mTLS client authority and separate
  plan/apply tools. Preserve scope, audit correlation, uncertainty and replay rules.
  Keep core stdlib-only; assess the official SDK as an optional integration extra.

## Defer until needed

- Atomic policy reload, with invalid-config retention, revision checks and
  explicit behavior for in-flight operations. Restart-based revocation remains.
- Bounded configurable plan TTL and separately reviewed LXC operations.
- IPv6 listener, certificate SAN and integration-test support.
- Concurrent serving, only after separate database/execution isolation design.
- Broader formatting/style rules beyond the initial correctness-focused Ruff rules.

Changes to a public release are not automatic changes to a deployed gateway.
Release tagging/publishing follows successful CI; deployment is a separate step.
