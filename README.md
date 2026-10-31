# Scoped Resource Gateway (SRG)

A small, self-hosted framework for giving AI agents **explicit, auditable access
to infrastructure—without sharing administrator credentials**.

SRG exposes named capabilities rather than an unrestricted shell. Operators
choose the exact actions and targets each client may use. Changes require a
short-lived preview plan, are checked again before execution, and are recorded
in a persistent audit ledger.

**Status:** experimental v0.3.0 reference implementation, not an established
standard or independently audited security product. Gateway and CLI: Python
3.11+, standard library only. MCP uses optional dependencies. MIT licensed.

## What it provides

- Mutual TLS and explicit per-client read/write grants; no implicit write permissions.
- Plan/apply flow with expiry, state preconditions and durable replay protection.
- Fixed adapters for selected Docker, Proxmox and Home Assistant actions.
- Persistent, hash-chained auditing, plus remote command correlation.
- A documented protocol, JSON Schema, adapter contract and generic examples.
- No subscription, hosted control plane, vault export or arbitrary command API.

Destructive operations are deliberately absent. Read-only and routine-write
scope is configured by the operator. A client key is authority to exercise its
grants; SRG cannot prove that a human requested a particular agent action.

## Try the tests

```sh
git clone https://github.com/zyman/srg.git
cd srg
python3 -m unittest discover -p 'test_*.py'
```

The tests use temporary certificates and fake adapters. They do not contact or
modify real infrastructure. OpenSSL must be installed for certificate tests.

## Deploy and use

Follow the [step-by-step installation guide](INSTALL.md) to provision
client/server identities, credentials, allowlists and the systemd service.
Examples contain placeholders only; do not use the dummy fingerprint as a real
identity. Keep deployment configuration and private keys outside this repository.

```sh
python3 client.py --config /path/to/client.json --capabilities
python3 client.py --config /path/to/client.json --plan app-restart --target demo-app
# Inspect the preview, then use its returned plan ID:
python3 client.py --config /path/to/client.json --apply PLAN_ID
python3 client.py --config /path/to/client.json --status PLAN_ID
python3 client.py --config /path/to/client.json --audit
```

## Use from AI agents

The optional [MCP stdio bridge](MCP.md) exposes discovery, reads, capabilities,
plan/apply, status and audit using your existing client identity. Install it on
the agent computer; gateway restrictions and audit logging remain authoritative.
See [Codex setup and usage examples](MCP.md#codex-setup), the
[Codex TOML configuration](examples/codex-mcp.toml), or the
[generic host JSON configuration](examples/mcp-client.json).

## Documentation

- [Install, connect resources, revoke access and troubleshoot](INSTALL.md)
- [Architecture, adapters and audit operations](FRAMEWORK.md)
- [Security review, fixes and remaining limitations](SECURITY-REVIEW.md)
- [SRG/1 draft protocol](PROTOCOL.md), [protocol schema](srg.schema.json), and [reference configuration schema](gateway.schema.json)
- [Changelog and upgrade requirements](CHANGELOG.md), [remaining work](ROADMAP.md)
- [Generic configuration examples](examples/)
- [Contributing](CONTRIBUTING.md), [security reporting](SECURITY.md), [license](LICENSE)

GitHub Actions tests both the source checkout and an independently extracted
portable archive on Python 3.11–3.14, validates schemas/examples, and runs a fresh
systemd installation with the OS Python. Archives normalize ownership, timestamps
and gzip metadata, and include a SHA256 sidecar. To build that archive yourself:

```sh
python3 make-release.py --output /tmp/srg-reference.tar.gz
(cd /tmp && sha256sum -c srg-reference.tar.gz.sha256)
```

## Limits to understand

Execution is at most one attempt per plan, not exactly-once delivery. A crash or
network failure may leave the outcome uncertain; inspect the target before
creating another plan. The reference server handles requests serially.

Hash chaining detects corruption but does not make logs immutable against a
server administrator. Stronger assurance needs independently managed log
storage or anchored checkpoints. Audit logging covers gateway-mediated work,
not an agent's reasoning or actions taken through unrelated tools.

Backend permissions may be broader than gateway permissions. In particular,
a non-admin Home Assistant token is not inherently read-only. Keep credentials
server-side and review every installed adapter and target allowlist.
