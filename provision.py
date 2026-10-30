#!/usr/bin/env python3
"""One-time root bootstrap on a gateway server. Accepts a public client CSR, never its key."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--client-csr", required=True)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--hostname", default="localhost")
    parser.add_argument("--directory", default="/etc/srg")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run as root on the gateway host")
    root = Path(args.directory).resolve()
    import ipaddress, re
    try:
        address = ipaddress.IPv4Address(args.bind)
        if address.is_unspecified:
            raise ValueError("unspecified address")
    except ValueError:
        parser.error("--bind must be the gateway IPv4 address, not a wildcard")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", args.hostname):
        parser.error("invalid server hostname")
    if (root / "policy.json").exists() or (root / "ca").exists():
        parser.error("existing installation; refusing to replace identity or policy")
    os.umask(0o077)
    root.mkdir(mode=0o755, exist_ok=True)
    root.chmod(0o755)
    (root / "ca").mkdir(mode=0o700)
    (root / "secrets").mkdir(mode=0o700, exist_ok=True)
    def openssl(*argv):
        subprocess.run([args.openssl, *map(str, argv)], cwd=root, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-keyout", "ca/key", "-out", "ca/cert", "-subj", "/CN=SRG Gateway CA", "-days", "3650", "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl("req", "-newkey", "rsa:3072", "-nodes", "-keyout", "secrets/server-key", "-out", "server.csr", "-subj", "/CN=" + args.hostname)
    common = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n"
    for name, csr, purpose, output in (
        ("server", root / "server.csr", "serverAuth", "secrets/server-cert"),
        ("client", Path(args.client_csr).resolve(), "clientAuth", "client.pem"),
    ):
        extension = common + "extendedKeyUsage=" + purpose + "\n"
        if name == "server":
            extension += "subjectAltName=DNS:" + args.hostname + ",IP:" + args.bind + "\n"
        (root / "extensions").write_text(extension)
        openssl("x509", "-req", "-in", csr, "-CA", "ca/cert", "-CAkey", "ca/key", "-CAcreateserial", "-out", output, "-days", "365", "-extfile", "extensions")
    ca = (root / "ca/cert").read_bytes()
    (root / "secrets/client-ca").write_bytes(ca)
    (root / "ca.pem").write_bytes(ca)
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert((root / "client.pem").read_text())).hexdigest()
    (root / "policy.json").write_text(json.dumps({"bind": args.bind, "port": 9444, "clients": [fingerprint], "resources": {"gateway": {"kind": "host"}}, "read_grants": {fingerprint: ["gateway"]}, "actions": {}, "write_grants": {}, "state_database": "/var/lib/srg/control.sqlite3"}, indent=2) + "\n")
    for public in ("client.pem", "ca.pem", "policy.json"):
        (root / public).chmod(0o644)
    (root / "server.csr").unlink()
    (root / "extensions").unlink()
    print("Gateway identity provisioned; private CA and server keys remain on this host.")


if __name__ == "__main__":
    main()
