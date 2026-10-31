# Use SRG from an MCP-compatible AI agent

SRG 0.3.0 provides an optional **local stdio MCP bridge**, built with the official
[Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk). The bridge
uses the same HTTPS/mTLS client identity and fixed operations as the CLI. The
gateway and CLI remain standard-library-only; the SDK is installed only on the
agent's computer. There is no hosted service, new inbound port or MCP HTTP server.

## Install and connect

First complete [INSTALL.md](INSTALL.md) and verify your identity using
`python3 client.py --config /absolute/path/to/client.json`. Keep its private key
and configuration outside the SRG checkout. Then, from the SRG checkout:

```sh
python3 -m venv .venv-mcp
.venv-mcp/bin/python -m pip install -r requirements-mcp.txt
.venv-mcp/bin/python mcp_server.py --help
```

Register this local stdio command with your AI application's MCP settings:

```text
Command: /absolute/path/to/srg/.venv-mcp/bin/python
Arguments: /absolute/path/to/srg/mcp_server.py --config /absolute/path/to/private/client.json
```

For hosts using the `mcpServers` JSON configuration shape, copy
[examples/mcp-client.json](examples/mcp-client.json) and replace all absolute paths.
Other hosts may have different configuration syntax; use the same executable and
argument list in their local MCP server settings. No credentials belong in that
JSON example or command-line arguments; the config contains paths to the existing
CA, client certificate and private key. No gateway backend token is needed.

The host launches this as a subprocess; do not run it as a separate daemon.
Launching it manually waits for MCP input. Stdout is exclusively protocol traffic;
redacted bridge events go to stderr. Do not redirect stderr into stdout. Set a
host tool-call timeout of at least 150 seconds for resource actions; the gateway
is serial and additional queued requests can take longer.

MCP support does not require changing gateway grants or issuing a more privileged
identity. It uses the existing SRG/1 HTTP contract. The bridge is tested with the
pinned SDK client and the legacy `2025-11-25` initialize/stdio wire format; this is
not a claim of certification against every application or MCP extension.

## Codex setup

Complete the installation above with a trusted SRG checkout and an already
provisioned client identity. Use a persistent virtual environment, not a temporary
folder. Registration does not provision a gateway or grant access to resources.

Register the local stdio server (replace all absolute paths):

```sh
codex mcp add srg -- \
  /absolute/path/to/srg/.venv-mcp/bin/python \
  /absolute/path/to/srg/mcp_server.py \
  --config /absolute/path/to/private/client.json
codex mcp get srg
```

Then edit the existing `[mcp_servers.srg]` table in `~/.codex/config.toml` to
match [examples/codex-mcp.toml](examples/codex-mcp.toml), including its 20-second
startup timeout, 180-second tool timeout and seven-tool allowlist. Alternatively,
merge that example table directly instead of running `codex mcp add`. Do not add
a duplicate table or replace the rest of your configuration. The tool timeout
allows for SRG's 130-second HTTP timeout; queued operations may still take longer.

Codex clients on the same host share this configuration. See the
[official Codex MCP documentation](https://developers.openai.com/codex/mcp/)
for current configuration options. This example preserves existing approval
settings. Server-side grants, target restrictions and audit logging still apply;
MCP tool visibility is not permission to execute an action. SRG's local stdio
bridge uses the configured client certificate, so it needs no MCP OAuth login or
backend API token in Codex configuration.

### Verify in the actual conversation

After configuring, start a fresh session. If the desktop retains the old tool
catalog, fully quit and reopen the app (Cmd+Q on macOS); closing a window may
leave its backend running. Then ask:

> Use the SRG MCP tools directly to list my granted resources and write
> capabilities. Perform one permitted health read and check its audit event.
> Do not plan or apply changes. Tell me if the tools are unavailable.

Success means Codex actually invokes `srg_resources`, `srg_capabilities`, a
permitted `srg_read`, and `srg_audit` in that conversation. `codex mcp get srg`
only confirms registration; a separate CLI/subprocess test alone does not prove
the active conversation loaded the tools. A shell fallback should be identified
as a fallback, not reported as direct MCP access.

If tools remain absent, inspect the active client's MCP startup diagnostics and
check the executable, dependencies, paths and current configuration. If the CLI
can read but the chat cannot see tools, investigate client loading before changing
gateway permissions. If discovery works but access is denied, inspect the intended
client's explicit grants; never broaden them merely to silence a failure.

### Usage examples

Use resource names and actions returned by discovery. The names below match the
repository's illustrative [policy](examples/policy.json); they are not defaults
or instructions to deploy that policy unchanged.

| Intent | Tool call |
|---|---|
| Discover permitted resources | `srg_resources({})` |
| Read the example gateway's health | `srg_read({"resource":"gateway","operation":"health"})` |
| Discover allowed actions/targets | `srg_capabilities({})` |
| Preview an owner-requested demo restart | `srg_plan({"action":"app-restart","target":"demo-app"})` |
| Apply the reviewed plan once | `srg_apply({"plan_id":"<returned plan ID>"})` |
| Check execution, including after a timeout | `srg_status({"plan_id":"<returned plan ID>"})` |
| Inspect recent client audit events | `srg_audit({})` |

Example read-only prompt: “Check the health of the resources I can access and
report failures without making changes.” Example write request: “Restart
`demo-app` using the granted `app-restart` action; review the preview, apply once,
and report its final status.” A plan is not human authorization. Do not execute
these example writes unless the owner actually requests the corresponding change.
After an uncertain apply, inspect status and resource state instead of retrying.

All forwarded requests retain the configured certificate's audit identity. See
[audit coverage](#audit-coverage) for local-validation and host-log limitations.
To remove just the integration, run `codex mcp remove srg` and reload the client.
This does not revoke the certificate or remove its gateway grants. For upgrades,
review the SRG release, update the trusted checkout and its virtual environment,
then repeat discovery and read checks; the registered command runs that checkout.

## Available tools

| Tool | Arguments | Behavior |
|---|---|---|
| `srg_resources` | None | Current resource names and read operations granted to this client |
| `srg_read` | `resource`, `operation` | One fixed gateway read |
| `srg_capabilities` | None | Current granted actions, exact targets and policy revision |
| `srg_plan` | `action`, `target` | Preview and persist a short-lived plan; no resource mutation |
| `srg_apply` | `plan_id` | One execution attempt against a reviewed plan |
| `srg_status` | `plan_id` | Own plan status and result, including uncertain outcomes |
| `srg_audit` | None | Latest 100 audit events for this client |

The tool names and descriptions are fixed. Discovery of actual permitted resources
and actions is fetched from the gateway, not cached into tool descriptions. A
read-only client can see the tool definitions but cannot gain write permissions.
This initial bridge exposes MCP tools; it does not implement MCP resource URIs,
background tasks, prompts, sampling or elicitation.

A typical interaction is: discover resources/capabilities, inspect the target,
request a plan, review its preconditions, then apply only when the owner requested
that change. Plan/apply are separate tool calls. A plan is not human approval,
and the bridge cannot prove human intent. The host's approval settings are a
separate layer; SRG still enforces access if those settings are permissive.

Tool annotations are conservative: apply is potentially destructive, and plan is
not advertised as read-only because it persists a plan. Annotations are hints,
not permissions. Read-only tools can still append server audit records. Resource
values and capability descriptions returned by the gateway remain untrusted data,
not instructions for the agent.

## Restrictions and failure recovery

- The operator selects exactly one client identity at startup. Tools cannot change
  URLs, credentials, CA trust, headers, timeouts, policy or SSH commands.
- Client certificate authentication, read/write grants, target allowlists,
  preconditions, expiry and replay protection remain enforced by the gateway.
- All arguments are validated and unknown fields rejected. Requests use fixed
  paths, verify TLS hostname/CA, and never follow redirects or use environment
  proxies. Responses are bounded to 2 MiB; raw backend errors are not forwarded.
- The bridge makes **no automatic retries**, and never automatically plans or
  applies. Use `srg_status` after any apply error. A lost response may mean the
  operation succeeded: inspect the target before deliberately creating a new plan.
- Calls within one bridge are serialized. Normal cancellation does not abandon
  an in-flight HTTP worker, but terminating the process or host can still lose
  the response. Gateway plan state is authoritative, not a host timeout.
- Errors use MCP `isError` with a structured `error` containing a stable `code`,
  safe `message` and optional HTTP status (`null` for local/transport failures).
  Apply errors also include recovery guidance. 403 means denied; 409 means an
  expired, stale or already-claimed plan; 502 means failed or uncertain execution.

## Audit coverage

Every forwarded read, plan, apply, status and audit request goes through the
existing gateway handlers and durable ledger under the same certificate
fingerprint. Plan IDs remain unchanged, so backend and executor events correlate
exactly as with CLI requests. Gateway audit failure still blocks execution.

Tool/schema listing does not access a resource. Invalid MCP arguments, unknown
tools and connection failures that never reach the gateway cannot appear in its
ledger. Bridge calls additionally produce redacted started/finished events on
stderr with a local call ID, operation and outcome, without argument values or
raw errors. These logs are retained only if the MCP host captures them; they are
not a second durable server ledger. Model reasoning and unrelated tools remain
outside the audit boundary. TLS failures cannot establish a server-side principal.

Use a separate authorized client certificate per agent if distinct attribution or
grant scopes are required. Sharing a certificate also shares its permissions and
audit identity. The process can read that client key, so run it only under a
trusted local account and protect the checkout and identity files.

## Verify or troubleshoot

```sh
.venv-mcp/bin/python -m unittest test_mcp test_gateway_client
```

Tests launch the actual bridge subprocess, communicate using MCP, and connect to
an ephemeral mTLS gateway with persistent SQLite and fake resource adapters. They
exercise scope denial, certificate validation, client isolation, expiry, stale
state, replay, audit failures and a lost response after successful execution.
They never contact your real resources.

If startup fails, check the interpreter has `requirements-mcp.txt` installed and
that the config points to readable, valid certificate files. Test the same config
with the CLI before changing MCP settings. If no resources appear, check explicit
read grants; installing the bridge does not grant access. Generic SDK diagnostics
are suppressed to prevent invalid caller input being echoed into logs; use the
bridge's redacted errors and server audit for investigation.
