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
