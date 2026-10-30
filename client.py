#!/usr/bin/env python3
"""Client identity permits only gateway operations; no upstream secrets."""
import argparse
import http.client
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=str(Path.home() / ".config/srg/client.json"))
    parser.add_argument("resource", nargs="?")
    parser.add_argument("operation", nargs="?")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--capabilities", action="store_true")
    mode.add_argument("--audit", action="store_true")
    mode.add_argument("--plan", metavar="ACTION")
    mode.add_argument("--apply", metavar="PLAN_ID")
    mode.add_argument("--status", metavar="PLAN_ID")
    parser.add_argument("--target")
    args = parser.parse_args()
    if any((args.capabilities, args.audit, args.plan, args.apply, args.status)) and (args.resource or args.operation):
        parser.error("control modes cannot be combined with resource reads")
    if bool(args.plan) != bool(args.target):
        parser.error("--plan requires --target, and --target requires --plan")
    if args.apply or args.status:
        if not re.fullmatch(r"[a-f0-9]{48}", args.apply or args.status):
            parser.error("invalid plan ID")
    if bool(args.resource) != bool(args.operation):
        parser.error("supply both resource and operation, or neither to list resources")
    if args.resource and not all(re.fullmatch(r"[a-z][a-z0-9-]{0,63}", x) for x in (args.resource, args.operation)):
        parser.error("invalid resource or operation")
    config = json.loads(Path(args.config).read_text())
    url = urlsplit(config["url"])
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
        parser.error("gateway URL must be an HTTPS origin")
    context = ssl.create_default_context(cafile=config["ca_file"])
    context.load_cert_chain(config["certificate"], config["key"])
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443, context=context, timeout=130)
    path = f"/v1/{args.resource}/{args.operation}" if args.resource else "/v1/resources"
    method, body, headers = "GET", None, {}
    if args.capabilities:
        path = "/v1/capabilities"
    elif args.audit:
        path = "/v1/audit"
    elif args.status:
        path = "/v1/plans/" + args.status
    elif args.plan or args.apply:
        method = "POST"
        path = "/v1/plans" if args.plan else "/v1/apply"
        body = json.dumps({"action": args.plan, "target": args.target} if args.plan else {"plan_id": args.apply})
        headers = {"Content-Type": "application/json"}
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("response too large")
        if response.status != 200:
            parser.exit(1, f"Gateway request failed (HTTP {response.status}).\n")
        print(json.dumps(json.loads(raw), indent=2))
    finally:
        connection.close()


if __name__ == "__main__":
    main()
