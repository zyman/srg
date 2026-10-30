# Remaining improvements

The 0.2.0 work addresses review items 1–10 and 20–22 where applicable. The server
remains serial; request-local adapter context does not make SQLite or execution
concurrency safe. Reader tests already existed; malformed-response coverage was
expanded rather than treating the path as wholly untested.

## Next: onboarding and operational security

- Certificate signing/renewal commands and expiry warnings (review 13).
- Offline credential/CA/host-key checks plus opt-in, read-only backend probes (14).
- Exact Home Assistant entity read allowlists, with explicit migration semantics (15).
- Audit checkpoints verified against independently retained receipts (16). Printing
  a timestamp and hash alone provides no independent anchoring or truncation defense.
- Distinct executor busy outcomes (18), preserving one-attempt semantics and no
  automatic retries after uncertain execution.

## Agent integration

- Optional stdio MCP wrapper (11), using existing mTLS client authority and separate
  plan/apply tools. Preserve scope, audit correlation, uncertainty and replay rules.
  Keep core stdlib-only; assess the official SDK as an optional integration extra.

## Defer until needed

- Atomic policy reload (12), with invalid-config retention, revision checks and
  explicit behavior for in-flight operations. Restart-based revocation remains.
- Bounded configurable plan TTL and separately reviewed LXC operations (17).
- IPv6 listener, certificate SAN and integration-test support (19).
- Concurrent serving, only after separate database/execution isolation design.
- Broader formatting/style rules beyond the initial correctness-focused Ruff rules.

Changes to a public release are not automatic changes to a deployed gateway.
Release tagging/publishing follows successful CI; deployment is a separate step.
