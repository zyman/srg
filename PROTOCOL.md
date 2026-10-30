# SRG/1 protocol (draft)

This document defines the initial interoperable contract. `srg/1` is a local
version identifier, not a registered or standardized protocol name.
Machine-readable policy and request shapes are in [srg.schema.json](srg.schema.json).
Adapter-specific validation and cross-reference authorization remain server checks.

## Authentication and authorization

The HTTPS reference transport requires TLS 1.2+ and a client certificate signed
by the configured CA. SHA256 of its DER certificate is the client identity and
must be explicitly authorized. A trusted CA alone does not authorize a client.
The server certificate and hostname must also validate. Read permissions are
explicit per-client `read_grants`, denied by default; write permissions are explicit
per-client action-name grants. No grant implies deny. Protect the client key:
any process possessing it can exercise its granted capabilities.

## Routes

| Method/path | Body | Response |
|---|---|---|
| GET `/v1/resources` | none | Existing fixed read resource/operation catalog |
| GET `/v1/RESOURCE/OPERATION` | none | `{ "data": ... }`, projected read response |
| GET `/v1/capabilities` | none | Protocol version, policy revision, granted action descriptions and exact target lists |
| POST `/v1/plans` | `{ "action": "app-restart", "target": "demo-app" }` | Opaque plan ID, action/target, precondition snapshot, expiry, policy revision |
| POST `/v1/apply` | `{ "plan_id": "48 lowercase hexadecimal characters" }` | Plan status and verified projected result |
| GET `/v1/plans/PLAN_ID` | none | Own plan's action, target, status and result |
| GET `/v1/audit` | none | Most recent 100 audit events for the authenticated client |

POST bodies require exactly `Content-Type: application/json`, one Content-Length
header, a length from 1 to 8192 bytes, and no Transfer-Encoding. Unknown fields,
duplicate JSON keys, nonfinite numbers and malformed bodies are rejected. No
caller-supplied shell commands, paths, URLs, headers, credentials or extra
service parameters are accepted. GET requests do not mutate resources.

Example capability:

```json
{
  "protocol": "srg/1",
  "policy_revision": "SHA256_OF_CANONICAL_SERVER_POLICY",
  "actions": {
    "app-restart": {
      "description": "Restart the existing demo application",
      "targets": ["demo-app"],
      "risk": "routine"
    }
  }
}
```

A plan is bound to its authenticated creator, exact action and target, the
canonical policy digest, precondition snapshot and 120-second expiry. It is
not a human approval and cannot expand privileges. The server revalidates
scope and preconditions, then claims the plan durably before execution.
Remote executors recheck target policy and snapshot under a local lock where
supported. Never persist a plan for execution at an arbitrary later time.

## Status and recovery

`planned → running → succeeded | conflict | uncertain`.
A failed precondition after claiming yields `conflict`; a backend error or
unverified result yields `uncertain`. A process crash may leave `running`.
Expired or changed-policy plans remain visible but cannot be applied. An apply
request never re-executes a claimed plan, including after service restart.
Poll GET status after a lost connection. Inspect the target before deliberately
creating a fresh plan following `running` or `uncertain` outcomes.

Errors: 400 invalid body/framing, 403 unauthorized action/target/client/plan,
404 unknown route/read operation, 409 expired/claimed/stale plan, 502 failed or
uncertain backend action. Authentication can fail at TLS before HTTP. Responses
do not disclose raw backend exceptions or credentials. HTTP errors after a
mutation are not proof that the resource was unchanged.

## Audit contract

Audit a request and its authenticated principal, preview, plan creation,
execution request, backend steps, verification, result and rejections.
Audit persistence must succeed before execution. State snapshots/results in
plan storage are projected; audit entries use their SHA256 digests instead of
raw values. Trace each backend step with the plan ID. Retain uncertain states
and do not erase evidence to make a request retryable.

`/v1/audit` is a bounded client view, not a full administrative export. Sequence
numbers and chain parents may skip events belonging to other clients. Verify
the full ledger with the operator utility, not a filtered tail. HTTP summaries
are additionally emitted to stdout; TLS failures cannot carry an authenticated
client identity. Agent reasoning, other tools and administrative bootstrap
steps outside the gateway are outside this protocol's audit boundary.

## Reference read authorization

The HTTPS reference implementation uses `read_grants`, an object mapping each
listed client fingerprint to exact configured resource names. Missing grants
allow no reads. `/v1/resources` lists only granted resources; ungranted resource
routes return 404 without calling a backend. Each resource grant permits its
fixed read operations. Write grants remain independent. This is a tightening
from the initial reference implementation, where listed clients shared all reads;
operators upgrading must explicitly migrate their read policy.


## Schema validation

`srg.schema.json` defines the portable control policy and request/response shapes.
`gateway.schema.json` defines the built-in reference transport, resource kinds and
adapter settings. Cross-references resolve locally in `ci/check-schemas.py`; no
network schema retrieval is needed. Reference validation and runtime checks are
complementary: the runtime also verifies that grants refer to installed resources,
actions and authorized clients. Extension adapters need their own configuration
schema and runtime validator.
