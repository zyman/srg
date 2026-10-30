# Install SRG and connect your resources

The gateway runs on Linux with Python 3.11+, OpenSSL, OpenSSH and systemd 247+
(`LoadCredential` support). Debian 12+ or Ubuntu 24.04 are suitable starting
points. Clients need Python 3.11+ and OpenSSL and may run on Linux or macOS.
The automated installation smoke test uses Ubuntu 24.04 and the real systemd
unit. No paid service or Python package installation is required.

Use a dedicated management host or VM. Permit TCP 9444 only from intended
clients on your management network/VPN. Do not expose the reference server to
the public Internet: it serializes requests and has no rate limiter. Ten-second
socket inactivity timeouts are not a defense against sustained denial of service.

## 1. Create a client identity (on the agent's computer)

Clone the public repository and test it. Keep identities **outside** the checkout.
Commands below assume a new installation; do not overwrite an existing key.

```sh
git clone https://github.com/zyman/srg.git
cd srg
python3 -m unittest discover -p 'test_*.py'
umask 077
mkdir -p "$HOME/.config/srg"
test ! -e "$HOME/.config/srg/client.key" && \
  openssl req -new -newkey rsa:3072 -nodes \
    -keyout "$HOME/.config/srg/client.key" \
    -out "$HOME/.config/srg/client.csr" -subj /CN=srg-client
```

Transfer **only `client.csr`** to the gateway using an authenticated administrative
channel. For example, copy it to `/tmp/srg-client.csr` via your existing SSH
account. Never copy the client private key to the gateway.

## 2. Provision the gateway (on the Linux gateway)

Install OS packages, clone this repository on the gateway, and run these commands
from its checkout. Replace `192.0.2.10` (documentation-only address) and
`gateway.example.internal` with your gateway's actual management IPv4 address
and DNS name. The address must belong to this host; DNS must resolve to it.
The reference listener is IPv4. Do not use `0.0.0.0` as a certificate identity.

```sh
sudo apt-get update
sudo apt-get install -y python3 openssl openssh-client
sudo python3 provision.py --openssl /usr/bin/openssl \
  --client-csr /tmp/srg-client.csr --directory /etc/srg \
  --bind 192.0.2.10 --hostname gateway.example.internal
sudo install -o root -g root -m 0644 \
  gateway.py control.py action_adapters.py audit.py /etc/srg/
python3 /etc/srg/gateway.py --config /etc/srg/policy.json --check
sudo install -o root -g root -m 0644 examples/srg.service /etc/systemd/system/srg.service
sudo systemctl daemon-reload
sudo systemctl enable --now srg
sudo systemctl status srg --no-pager
```

Provisioning refuses to replace an existing identity. The initial policy grants
only gateway health reads to this one client, with **no writes**. The service
uses `DynamicUser`, a persistent private state directory, and systemd credentials.
There is no mandatory SSH backend key. The CA signing key stays root-only under
`/etc/srg/ca`; it is not given to the service. Public policy is root-owned and
readable by the service; credentials must never be put in that policy.

Copy `/etc/srg/client.pem` and `/etc/srg/ca.pem` back to the client's
`~/.config/srg/` through the same trusted channel. Confirm you received the
correct gateway CA; trusting a certificate fetched from an unauthenticated
endpoint defeats TLS verification.

## 3. Connect the client

Create `~/.config/srg/client.json` with **absolute** local paths (`~` is not
expanded in JSON). Use [examples/client.json](examples/client.json) as a template:

```json
{
  "url": "https://gateway.example.internal:9444",
  "ca_file": "/absolute/path/to/ca.pem",
  "certificate": "/absolute/path/to/client.pem",
  "key": "/absolute/path/to/client.key"
}
```

From the client checkout:

```sh
python3 client.py
python3 client.py gateway health
python3 client.py --capabilities
python3 client.py --audit
```

Expected: the resource list contains `gateway`, health returns numeric metrics,
capabilities contains an empty `actions` object, and audit contains your reads.
Give the AI client access to this client configuration and key only. It does not
need any backend token, CA signing key, administrative SSH key or Bitwarden
session. There is no built-in MCP integration; an agent can invoke this CLI or
use the documented HTTPS API. Keep the checkout/code read-only to untrusted users.

## 4. Add a read resource

Edit `/etc/srg/policy.json` as root. Add a named resource under `resources`, and
add that name to the appropriate fingerprint's `read_grants` array. A missing
read grant means **no access**, including resource discovery. Each resource grant
permits all of that resource kind's fixed read operations; there is no per-entity
Home Assistant read filter. Do not grant HA reads to a client that must not see
entity states/names (which may themselves contain sensitive data).

Copy entries from [examples/resources.json](examples/resources.json); replace
origins, node names and paths. This file is a collection of resource entries,
not a complete policy. Supported integrations:

| Kind | Reads | Credential file content |
|---|---|---|
| `host` | Local Linux metrics | None |
| `https` | TLS-verified HTTP status | None |
| `ssh` | Remote Linux metrics via forced reader | Dedicated SSH private key |
| `proxmox` | Nodes and guests | `user@realm!tokenid=secret`, without `PVEAPIToken=` prefix |
| `proxmox_guest` | One QEMU VM's status and guest-agent OS info | Same Proxmox token format; OS info needs a working guest agent and appropriate backend permissions |
| `portainer` | Environments visible to the token | User API key; scope access using your Portainer edition's supported roles |
| `home_assistant` | Health, states and automations | Dedicated user's long-lived token |

For token-backed resources, create the token in the resource's own management
interface. Prefer a dedicated account and the narrowest backend permissions.
SRG does not create those accounts or emulate roles your backend does not offer.
An HA non-admin token can still control entities directly; the gateway is the
read/write restriction. Review the upstream permission model before granting it.

For a credential named `ha`, create `/etc/srg/secrets/ha` root-owned, mode 0600,
containing only the token, using your secure secret provisioning process. Do not
put tokens in shell arguments, history, policy, Git or chat. Then run
`sudo systemctl edit srg` and add:

```ini
[Service]
LoadCredential=ha:/etc/srg/secrets/ha
```

Use the same name in the resource's `credential` property. For a private backend
CA, install its **public certificate chain** as root-owned mode 0644, e.g.
`/etc/srg/backend-ca.pem`, and set `ca_file` to that path. Omit `ca_file` to use
system trust. Fix hostname/chain errors; there is no insecure TLS bypass.

For SSH health, install `reader.sh` on the target as root-owned executable
`/usr/local/libexec/srg-reader`. Use a dedicated account with no sudo and a
root-managed authorized-keys file containing:

```text
from="GATEWAY_IP",restrict,command="/usr/local/libexec/srg-reader" ssh-ed25519 PUBLIC_KEY
```

The account must have a valid shell for the forced command but no password login,
no unrestricted keys and no ability to replace its authorized-keys file. Install
the gateway private key as a systemd credential, and pin the target's host key
in `/etc/srg/known_hosts` (root-owned, mode 0644). Verify the host key fingerprint
through a trusted administrative channel before trusting it; `ssh-keyscan` alone
does not authenticate it. See the [OpenSSH authorized-keys documentation](https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT).

After policy/credential changes:

```sh
python3 /etc/srg/gateway.py --config /etc/srg/policy.json --check
sudo systemctl daemon-reload
sudo systemctl restart srg
sudo journalctl -u srg -n 30 --no-pager
```

`--check` validates policy structure and grants without contacting backends or
reading credentials. Verify the new resource from the client, e.g.
`python3 client.py ha health`. Audit those reads before granting writes.

## 5. Enable a narrow write capability

Read grants never imply writes. Add an action under `actions` and its name under
the client's `write_grants`. [examples/policy.json](examples/policy.json) shows
an SSH container restart; [examples/ha-action.json](examples/ha-action.json)
shows an HA light toggle. Merge these entries into your generated policy,
retaining the real fingerprint; do not replace it with a dummy fingerprint.
Choose low-impact targets: a switch could control heating, power or a door even
though its API domain looks harmless. No destructive operation is implemented.

For SSH writes, follow the [remote executor setup](FRAMEWORK.md#deploy-your-own-instance)
with a **separate** key/account from the reader. On the target, install the helper
and root-owned allowlist, and allow exactly this sudo command (no wildcards):

```sudoers
agentops ALL=(root) NOPASSWD: /usr/bin/python3 -I /usr/local/libexec/srg-action.py
```

Validate the sudoers drop-in with `visudo -cf` before installing it. Keep the
account out of the Docker group and root-manage its authorized keys and home
startup files. Never grant general `python3`, shell or Docker sudo access. The
force-command key restriction in FRAMEWORK.md is required, not optional.

Restart after `--check`, then on the client:

```sh
python3 client.py --capabilities
python3 client.py --plan app-restart --target demo-app
# Inspect the returned target, state and expiry before applying its plan ID.
python3 client.py --apply PLAN_ID
python3 client.py --status PLAN_ID
python3 client.py --audit
```

Plan IDs expire in 120 seconds and cannot be replayed. For failures or uncertain
outcomes inspect the actual resource before creating another plan. Docker restart
may kill the selected container after its graceful-stop timeout, as documented
by [Docker](https://docs.docker.com/reference/cli/docker/container/restart/).

## Operations and troubleshooting

- **Upgrade:** back up the ledger using `audit.py --backup`, review release changes,
  replace only source/unit files, validate policy, and restart. Preserve `/etc/srg`
  identities, backend secrets and `/var/lib/srg`. This change introduces explicit
  `read_grants`; older policies with no grants now expose no resources.
- **Revoke:** remove the client's fingerprint from `clients`, `read_grants` and
  `write_grants`, validate and restart. Old client certificates then fail authorization.
  Revoke leaked backend tokens at their issuer and replace the corresponding files.
- **Renew:** leaf certificates expire after one year. There is no automated renewal
  command yet. Use your PKI process to issue replacement serverAuth/clientAuth
  certificates; never enable CA capabilities on a leaf. Install the server cert/key
  securely, update client DER SHA256 fingerprints and grants for new client certs,
  distribute certificates through a trusted channel, then restart. Do not rerun
  bootstrap over an existing installation or discard the ledger to renew a cert.
- **Fingerprint:** `openssl x509 -in client.pem -outform DER | openssl dgst -sha256`
  yields the lowercase hex digest used in policy (without the output prefix).
- **TLS failure:** check DNS/SAN, certificate validity, system clock and complete CA
  chains. The client must present its signed certificate and matching key.
- **Empty resources / HTTP 404:** check the client's `read_grants`. HTTP 403 on a
  write means no matching grant/target. A CA-signed client must also be listed.
- **Service won't start:** inspect `journalctl -u srg`; missing `LoadCredential`
  files are fatal. Check policy, root-owned code, state permissions and CA paths.
  See [systemd credential and state-directory semantics](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
- **Corrupt audit chain:** startup fails closed. Preserve the database, investigate
  and recover from a verified backup. Never silently clear the audit table.
- **Storage:** monitor the ledger and free space. The example unit's 64 MiB file
  limit is a guardrail, not rotation; reaching it stops successful audit writes
  and therefore operations. Archive verified backups and set an appropriate limit.

See [audit operations and limitations](FRAMEWORK.md#audit-operations) and
[the security review](SECURITY-REVIEW.md) before expanding access.
