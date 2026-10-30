#!/usr/bin/env python3
"""Client identity permits only gateway operations; no upstream secrets."""
import argparse
import json
from pathlib import Path
import re
from gateway_client import GatewayClient, GatewayError


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
    operation, arguments = 'resources', {}
    if args.resource:
        operation, arguments = 'read', {'resource': args.resource, 'operation': args.operation}
    elif args.capabilities:
        operation = 'capabilities'
    elif args.audit:
        operation = 'audit'
    elif args.status:
        operation, arguments = 'status', {'plan_id': args.status}
    elif args.plan:
        operation, arguments = 'plan', {'action': args.plan, 'target': args.target}
    elif args.apply:
        operation, arguments = 'apply', {'plan_id': args.apply}
    try:
        result = GatewayClient(args.config).invoke(operation, arguments)
        print(json.dumps(result, indent=2, allow_nan=False))
    except GatewayError as error:
        recovery = ' Do not retry apply automatically; check plan status and inspect the target.' if operation == 'apply' else ''
        status = f' (HTTP {error.http_status})' if error.http_status is not None else ''
        parser.exit(1, f'{error}{status}{recovery}\n')



if __name__ == "__main__":
    main()
