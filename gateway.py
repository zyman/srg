#!/usr/bin/env python3
"""Scoped Resource Gateway: fixed reads and policy-granted plan/apply actions."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

from control import Controller, Denied, Conflict
from action_adapters import SSHAdapter, HomeAssistantAdapter

LIMIT = 2 * 1024 * 1024
OPERATIONS = {
    "host": {"health": (None, ())},
    "ssh": {"health": (None, ())},
    "https": {"health": ("/", ())},
    "home_assistant": {
        "health": ("/api/", ()),
        "states": ("/api/states", ("entity_id", "state", "last_changed", "last_updated")),
        "automations": ("/api/states", ("entity_id", "state", "last_changed", "last_updated")),
    },
    "proxmox": {
        "nodes": ("/api2/json/nodes", ("node", "status", "uptime", "cpu", "maxcpu", "mem", "maxmem")),
        "guests": ("/api2/json/cluster/resources?type=vm", ("vmid", "node", "type", "name", "status", "cpu", "mem", "maxmem", "uptime")),
    },
    "proxmox_guest": {
        "health": ("/api2/json/nodes/{node}/qemu/{vmid}/status/current", ("vmid", "name", "status", "uptime", "cpu", "cpus", "mem", "maxmem")),
        "osinfo": ("/api2/json/nodes/{node}/qemu/{vmid}/agent/get-osinfo", ("name", "id", "version", "version-id", "pretty-name", "kernel-release", "kernel-version", "machine")),
    },
    "portainer": {
        "environments": ("/api/endpoints", ("Id", "Name", "Type", "Status")),
    },
}


def validate(config):
    if not config.get("clients") or any(not re.fullmatch(r"[a-f0-9]{64}", x) for x in config["clients"]):
        raise ValueError("clients must contain SHA256 certificate fingerprints")
    for name, resource in config["resources"].items():
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", name):
            raise ValueError("invalid resource name")
        if resource["kind"] not in OPERATIONS:
            raise ValueError("unsupported resource kind")
        if resource["kind"] == "proxmox_guest":
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}", resource["node"]) or type(resource["vmid"]) is not int or not 100 <= resource["vmid"] <= 999999999:
                raise ValueError("invalid guest identity")
        if resource["kind"] == "host":
            continue
        if resource["kind"] == "ssh":
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}", resource["host"]):
                raise ValueError("invalid SSH host")
            if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", resource.get("user", "agentops")):
                raise ValueError("invalid SSH user")
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", resource["credential"]):
                raise ValueError("invalid SSH credential name")
            continue
        url = urlsplit(resource["url"])
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
            raise ValueError("resource URL must be an HTTPS origin")
        if resource["kind"] != "https" and not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", resource["credential"]):
            raise ValueError("invalid credential name")
    return config


def fetch(resource, operation, credentials):
    if operation not in OPERATIONS[resource["kind"]]:
        raise ValueError("operation not permitted")
    if resource["kind"] == "ssh":
        # The key is restricted server-side to the same reader on every host.
        # Ignore per-user SSH configs and agents; use only the managed trust file.
        command = ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
                   "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UserKnownHostsFile=" + resource["known_hosts"],
                   "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "-i", str(Path(credentials) / resource["credential"]),
                   resource.get("user", "agentops") + "@" + resource["host"], "health"]
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
                                    stderr=subprocess.DEVNULL, timeout=10, check=False)
            if result.returncode or output.tell() > LIMIT:
                raise ValueError("restricted reader unavailable")
            output.seek(0)
            data = json.load(output)
        fields = ("uptime_seconds", "load_average", "memory_total_kib", "memory_available_kib", "memory_available_estimated")
        if not isinstance(data, dict) or any(key not in data for key in fields):
            raise ValueError("invalid reader response")
        if any(type(data[k]) not in (int, float) for k in fields[:1] + fields[2:4]):
            raise ValueError("invalid reader metrics")
        if not isinstance(data["load_average"], list) or len(data["load_average"]) != 3 or any(type(x) not in (int, float) for x in data["load_average"]):
            raise ValueError("invalid reader load")
        if type(data["memory_available_estimated"]) is not bool:
            raise ValueError("invalid reader memory flag")
        return {key: data[key] for key in fields}
    if resource["kind"] == "host" and operation == "health":
        memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
        return {"uptime_seconds": float(Path("/proc/uptime").read_text().split()[0]),
                "load_average": list(os.getloadavg()),
                "memory_total_kib": int(memory["MemTotal"].split()[0]),
                "memory_available_kib": int(memory["MemAvailable"].split()[0]),
                "memory_available_estimated": False}
    path, fields = OPERATIONS[resource["kind"]][operation]
    if resource["kind"] == "proxmox_guest":
        path = path.format(node=resource["node"], vmid=resource["vmid"])
    headers = {"Accept": "application/json"}
    if resource["kind"] != "https":
        token = (Path(credentials) / resource["credential"]).read_text().strip()
        if not token or "\n" in token or "\r" in token:
            raise ValueError("invalid credential")
        if resource["kind"] in ("proxmox", "proxmox_guest"):
            headers["Authorization"] = "PVEAPIToken=" + token
        elif resource["kind"] == "home_assistant":
            headers["Authorization"] = "Bearer " + token
        else:
            headers["X-API-Key"] = token
    url = urlsplit(resource["url"])
    context = ssl.create_default_context(cafile=resource.get("ca_file"))
    connection = http.client.HTTPSConnection(url.hostname, url.port or 443, context=context, timeout=10)
    try:
        # No redirects, environment proxies, caller-selected URLs or caller headers.
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if resource["kind"] == "https":
            return {"http_status": response.status, "tls_verified": True,
                    "reachable": True, "authenticated": False}
        if response.status != 200:
            raise ValueError("upstream request failed")
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise ValueError("upstream response too large")
        data = json.loads(raw)
        if resource["kind"] == "home_assistant":
            if operation == "health":
                if not isinstance(data, dict) or data.get("message") != "API running.":
                    raise ValueError("invalid Home Assistant health response")
                return {"api_running": True, "authenticated": True, "tls_verified": True}
            if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
                raise ValueError("invalid Home Assistant states response")
            result = []
            for row in data:
                entity = row.get("entity_id")
                if not isinstance(entity, str) or not re.fullmatch(r"[a-z0-9_]+\.[a-z0-9_]+", entity):
                    raise ValueError("invalid entity identifier")
                if operation == "automations" and not entity.startswith("automation."):
                    continue
                item = {key: row[key] for key in fields if key in row and type(row[key]) is str}
                attributes = row.get("attributes", {})
                if not isinstance(attributes, dict):
                    raise ValueError("invalid entity attributes")
                item["attributes"] = {key: attributes[key] for key in
                    ("friendly_name", "unit_of_measurement", "device_class", "last_triggered")
                    if key in attributes and (attributes[key] is None or type(attributes[key]) is str)}
                result.append(item)
            return result
        if resource["kind"] in ("proxmox", "proxmox_guest"):
            data = data["data"]
        if resource["kind"] == "proxmox_guest":
            if operation == "osinfo":
                data = data["result"]
            if not isinstance(data, dict):
                raise ValueError("invalid guest response")
            return {key: data[key] for key in fields if key in data and (data[key] is None or type(data[key]) in (str, int, float, bool))}
        if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
            raise ValueError("invalid upstream response")
        # Do not return nested snapshots, configuration, environment variables or tokens.
        return [{key: row[key] for key in fields if key in row and
                 (row[key] is None or type(row[key]) in (str, int, float, bool))}
                for row in data]
    finally:
        connection.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "ScopedResourceGateway"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(120)

    def log_message(self, *_):
        pass  # No raw URLs, headers, bodies or upstream errors in logs.

    def send_error(self, code, message=None, explain=None):
        self.reply(code, {"error": "request rejected"})

    def reply(self, status, body, operation="rejected"):
        encoded = json.dumps(body, allow_nan=False).encode()
        fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        if getattr(self.server, "controller", None):
            self.server.controller.audit(fingerprint, "http.response", {"operation": operation, "status": status})
        print(json.dumps({"client": fingerprint, "operation": operation, "status": status}), flush=True)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)
        self.close_connection = True

    def do_GET(self):
        config = self.server.policy
        fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        if fingerprint not in config["clients"]:
            return self.reply(403, {"error": "client not authorized"})
        if self.headers.get("Transfer-Encoding") or self.headers.get("Content-Length", "0") != "0":
            return self.reply(400, {"error": "request body not accepted"})
        controller = getattr(self.server, "controller", None)
        if controller and self.path == "/v1/capabilities":
            return self.reply(200, controller.capabilities(fingerprint), "capabilities")
        if controller and self.path == "/v1/audit":
            return self.reply(200, {"events": controller.audit_tail(fingerprint)}, "audit")
        if controller and re.fullmatch(r"/v1/plans/[a-f0-9]{48}", self.path):
            try:
                return self.reply(200, controller.status(fingerprint, self.path.rsplit('/', 1)[1]), "plan-status")
            except Denied:
                return self.reply(403, {"error": "plan not available"})
        if self.path == "/v1/resources":
            return self.reply(200, {name: list(OPERATIONS[value["kind"]]) for name, value in config["resources"].items()}, "resources")
        match = re.fullmatch(r"/v1/([a-z][a-z0-9-]{0,63})/([a-z]+)", self.path)
        if not match:
            return self.reply(404, {"error": "operation not available"})
        name, operation = match.groups()
        resource = config["resources"].get(name)
        if resource is None or operation not in OPERATIONS[resource["kind"]]:
            return self.reply(404, {"error": "operation not available"})
        action = name + "/" + operation
        try:
            if controller:
                controller.audit(fingerprint, "read.started", {"resource": name, "operation": operation})
            data = fetch(resource, operation, self.server.credentials)
            # Validate serialization inside error boundary (e.g. nonfinite numbers).
            json.dumps(data, allow_nan=False)
        except Exception:
            return self.reply(502, {"error": "upstream unavailable or invalid response"}, action)
        self.reply(200, {"data": data}, action)

    def do_POST(self):
        controller = getattr(self.server, "controller", None)
        if controller is None or self.path not in ("/v1/plans", "/v1/apply"):
            return self.reply(404, {"error": "write route not available"})
        fingerprint = hashlib.sha256(self.connection.getpeercert(binary_form=True)).hexdigest()
        if fingerprint not in self.server.policy["clients"]:
            return self.reply(403, {"error": "client not authorized"})
        try:
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise Denied("invalid framing")
            length = int(self.headers["Content-Length"])
            if not 0 < length <= 8192 or self.headers.get("Content-Type") != "application/json":
                raise Denied("invalid content")
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise Denied("duplicate JSON key")
                    value[key] = item
                return value
            body = self.rfile.read(length)
            if len(body) != length:
                raise Denied("incomplete body")
            request = json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(Denied("invalid number")))
        except (ValueError, TypeError):
            return self.reply(400, {"error": "invalid JSON request"})
        operation = "plan" if self.path == "/v1/plans" else "apply"
        try:
            controller.audit(fingerprint, "http.request", {"operation": operation})
            result = controller.plan(fingerprint, request) if operation == "plan" else controller.apply(fingerprint, request)
        except Denied:
            return self.reply(403, {"error": "action or target not authorized"}, operation)
        except Conflict:
            return self.reply(409, {"error": "plan expired, already claimed, or target/policy changed"}, operation)
        except Exception:
            return self.reply(502, {"error": "action failed or outcome uncertain; inspect plan and target, do not retry blindly"}, operation)
        return self.reply(200, result, operation)


class Server(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        try:
            return self.tls.wrap_socket(connection, server_side=True), address
        except Exception:
            connection.close()
            raise

    def handle_error(self, request, client_address):
        print('{"event":"connection_failed"}', flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    config = validate(json.loads(Path(args.config).read_text()))
    credentials = os.environ["CREDENTIALS_DIRECTORY"]
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(Path(credentials) / "server-cert"), str(Path(credentials) / "server-key"))
    tls.load_verify_locations(cafile=str(Path(credentials) / "client-ca"))
    tls.verify_mode = ssl.CERT_REQUIRED
    server = Server((config["bind"], config.get("port", 9444)), Handler)
    server.tls, server.policy, server.credentials = tls, config, credentials
    database = config.get("state_database", "/var/lib/srg/control.sqlite3")
    server.controller = Controller(config, {"ssh": SSHAdapter(credentials), "home_assistant": HomeAssistantAdapter(credentials)}, database)
    server.serve_forever()


if __name__ == "__main__":
    main()
