# Security review — 2026-10-30

This is a maintainer code review with regression and installation tests, **not**
an independent penetration test or assurance that the software is vulnerability-free.
Scope: the public Python implementation, CLI, bootstrap, remote helper, example
policies, packaging and CI. No private deployment or real backend was accessed.

## Fixed in this review

| Finding | Change | Verification |
|---|---|---|
| All listed clients could discover/read every configured resource, despite separate write grants | Explicit per-client `read_grants`, denied by default, including discovery; generated policy grants only gateway health | mTLS tests with two CA-signed clients; verify denied reads never reach a backend |
| Container name could be reassigned after preview, directing a write at a replacement | Start/restart and health commands use the previewed full immutable container ID; post-check still verifies name/identity | Regression simulates replacement; only original ID is used for mutation and outcome fails closed |
| Corrupt audit ledger accepted on restart | Verify the full hash chain before accepting work | Tamper persisted audit data and assert controller startup fails |
| Example service failed without a write key even for initial read-only setup | Optional backend credential lines; bootstrap policy has explicit read grant and empty writes | Fresh provisioning and real systemd unit smoke test in Ubuntu CI |
| Incomplete onboarding left security-critical steps implicit | Full install/resource/credential/SSH examples, policy-only `--check`, revocation and upgrade guidance | Example policies validated; release archive tested separately; CLI/mTLS/service smoke test |
| Long idle socket timeout tied up the serial server | Reduce HTTP inactivity timeout from 120 to 10 seconds | Code review; does not claim to solve denial of service |

## Trust boundaries and remaining limitations

- Client keys authorize their exact grants; the gateway does not prove human intent
  or model identity. Destructive operations have no adapter; use a separately
  authorized administrative channel. An operator can still choose dangerous
  targets for nominally routine operations (e.g. a power switch or database restart).
- Adapters, gateway administrators and backend administrators are trusted. Backend
  credentials may be broader than gateway permissions. A compromised gateway host
  can bypass policy; use least-privilege backend roles and forced-command SSH keys.
- Read grants are resource-level, not per field/entity. Projection excludes many
  secret-bearing fields but names and state values can themselves be sensitive.
- The serial reference server is for a restricted management network, not hostile
  Internet traffic. No admission control, rate limiting or total request deadline
  is implemented; a slow client or backend can delay others. Backend subprocess
  output is checked after collection; OS limits are part of the containment.
- External changes can race checks. Docker writes now pin immutable IDs, but VM IDs
  and HA entity IDs have no comparable universal generation/CAS guarantee here.
  Never let other administrators replace targets during a planned operation.
- One plan gets at most one execution attempt. The remote SSH executor does not
  have a separate durable replay ledger; its dedicated key is itself authority
  within its root-owned allowlist. Do not distribute that key to agents.
- Audit persistence failure prevents further work, but failure after mutation may
  leave an uncertain result. Hash chains detect corruption, not administrator
  rewriting or unanchored tail truncation. Audit collection/retention/alerting and
  external anchoring remain operator responsibilities. This does not log actions
  performed through unrelated tools or private model reasoning.
- Certificates expire; renewal is documented but not automated. There is no CRL
  distribution service. Fingerprint removal plus service restart revokes client
  authorization. Preserve the ledger during certificate replacement.
- Tests fake Docker, Proxmox, Portainer and HA APIs. CI exercises Linux/systemd,
  bootstrap, TLS and the local metrics backend, not every backend version or OS.

## Operator upgrade checklist

1. Back up and verify the ledger; preserve identities and credentials.
2. Add explicit `read_grants` for each client before upgrading. Do not add broad
   grants merely to restore old behavior; review the intended resource scope.
3. Install gateway source and the updated remote `ssh_action.py` on SSH write
   targets. Updating only the gateway does not fix the remote container race.
4. Validate policy with `gateway.py --check`, restart, test allowed and denied reads,
   and inspect audit events. No changes to a private deployment are implied by a
   public repository update.

Report vulnerabilities privately using [SECURITY.md](SECURITY.md).
