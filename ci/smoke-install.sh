#!/bin/sh
# Disposable Ubuntu CI runner only. Never run against an existing installation.
set -eu
if [ "$(uname -s)" != Linux ] || [ -e /etc/srg ] || [ -e /etc/systemd/system/srg.service ]; then
    echo 'Requires a disposable Linux/systemd host without SRG installed.' >&2
    exit 1
fi
srg_tmp=$(mktemp -d)
chmod 700 "$srg_tmp"
trap 'sudo systemctl stop srg 2>/dev/null || true; rm -rf "$srg_tmp"' EXIT
umask 077
openssl req -new -newkey rsa:2048 -nodes -keyout "$srg_tmp/client.key" \
    -out "$srg_tmp/client.csr" -subj /CN=ci-client 2>/dev/null
sudo python3 provision.py --openssl /usr/bin/openssl --client-csr "$srg_tmp/client.csr" \
    --directory /etc/srg --bind 127.0.0.1 --hostname localhost
sudo install -o root -g root -m 0644 gateway.py control.py action_adapters.py audit.py ledger.py ssh_transport.py /etc/srg/
python3 /etc/srg/gateway.py --config /etc/srg/policy.json --check
sudo install -o root -g root -m 0644 examples/srg.service /etc/systemd/system/srg.service
sudo systemctl daemon-reload
sudo systemctl start srg
cp /etc/srg/client.pem /etc/srg/ca.pem "$srg_tmp/"
python3 - "$srg_tmp" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
(p / 'client.json').write_text(json.dumps({'url': 'https://localhost:9444',
    'ca_file': str(p / 'ca.pem'), 'certificate': str(p / 'client.pem'), 'key': str(p / 'client.key')}))
PY
# systemd Type=simple becomes active before Python has bound its socket.
srg_attempt=0
until python3 client.py --config "$srg_tmp/client.json" gateway health > "$srg_tmp/health.json" 2>/dev/null; do
    srg_attempt=$((srg_attempt + 1))
    if [ "$srg_attempt" -ge 15 ]; then
        sudo journalctl -u srg --no-pager
        exit 1
    fi
    sleep 1
done
python3 client.py --config "$srg_tmp/client.json" --capabilities > "$srg_tmp/capabilities.json"
python3 client.py --config "$srg_tmp/client.json" --audit > "$srg_tmp/audit.json"
python3 - "$srg_tmp" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
assert json.loads((p / 'health.json').read_text())['data']['memory_total_kib'] > 0
assert json.loads((p / 'capabilities.json').read_text())['actions'] == {}
assert any(e['event'] == 'read.started' for e in json.loads((p / 'audit.json').read_text())['events'])
print('Fresh provision, systemd credentials, mTLS CLI and persistent audit passed.')
PY
sudo python3 audit.py --database /var/lib/srg/control.sqlite3
sudo systemctl restart srg
