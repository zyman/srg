"""Trusted SRG adapters. Endpoint, credentials and operations come from policy."""
import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

from control import Conflict, Denied


class SSHAdapter:
    operations = {"container-start", "container-restart", "vm-start", "vm-shutdown"}

    def __init__(self, credentials):
        self.credentials = Path(credentials)
        self.audit = lambda event, detail: None

    def validate(self, action):
        if action.get("operation") not in self.operations:
            raise ValueError("unsupported SSH action")
        for key, pattern in (("host", r"[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}"), ("credential", r"[a-z][a-z0-9-]{0,63}")):
            if not re.fullmatch(pattern, action.get(key, "")):
                raise ValueError("invalid SSH action endpoint")
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", action.get("user", "agentops")):
            raise ValueError("invalid SSH account")
        if not isinstance(action.get("targets"), list) or not action["targets"] or any(type(x) is not str or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}", x) for x in action["targets"]):
            raise ValueError("invalid SSH targets")
        if not Path(action.get("known_hosts", "")).is_absolute():
            raise ValueError("managed host keys required")

    def call(self, action, target, mode, before=None):
        command = ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                   "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
                   "-o", "UserKnownHostsFile=" + action["known_hosts"], "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
                   "-i", str(self.credentials / action["credential"]), action.get("user", "agentops") + "@" + action["host"], "action"]
        request = {"mode": mode, "operation": action["operation"], "target": target, "expected": before, "request_id": self.request_id}
        self.audit("backend.ssh.started", {"host": action["host"], "operation": action["operation"], "target": target, "mode": mode})
        with tempfile.TemporaryFile() as output:
            try:
                completed = subprocess.run(command, input=json.dumps(request).encode(), stdout=output, stderr=subprocess.DEVNULL, timeout=105)
            except Exception:
                self.audit("backend.ssh.uncertain", {"host": action["host"], "operation": action["operation"], "target": target, "mode": mode})
                raise
            self.audit("backend.ssh.returned", {"host": action["host"], "operation": action["operation"], "target": target, "mode": mode, "returncode": completed.returncode})
            if completed.returncode or output.tell() > 65536:
                raise ValueError("remote action failed; inspect before retry")
            output.seek(0)
            result = json.load(output)
            self.audit("backend.ssh.completed", {"host": action["host"], "operation": action["operation"], "target": target, "mode": mode})
            return result

    def prepare(self, action, target):
        return self.call(action, target, "prepare")

    def execute(self, action, target, before):
        return self.call(action, target, "execute", before)


class HomeAssistantAdapter:
    operations = {"turn-on", "turn-off"}
    domains = {"light", "switch", "fan", "input_boolean"}

    def __init__(self, credentials):
        self.credentials = Path(credentials)
        self.audit = lambda event, detail: None

    def validate(self, action):
        url = urlsplit(action.get("url", ""))
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.path not in ("", "/") or url.query or url.fragment:
            raise ValueError("HTTPS origin required")
        if action.get("operation") not in self.operations or not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", action.get("credential", "")):
            raise ValueError("invalid Home Assistant action")
        if not isinstance(action.get("targets"), list) or not action["targets"] or any(type(x) is not str or not re.fullmatch(r"(?:light|switch|fan|input_boolean)\.[a-z0-9_]+", x) for x in action["targets"]):
            raise ValueError("invalid entity targets")

    def call(self, action, method, path, body=None):
        url = urlsplit(action["url"])
        token = (self.credentials / action["credential"]).read_text().strip()
        if not token or '\n' in token or '\r' in token:
            raise ValueError("invalid token")
        self.audit("backend.http.started", {"method": method, "path": path})
        connection = http.client.HTTPSConnection(url.hostname, url.port or 443, context=ssl.create_default_context(cafile=action.get("ca_file")), timeout=10)
        try:
            connection.request(method, path, body=json.dumps(body) if body is not None else None,
                               headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
            response = connection.getresponse()
            self.audit("backend.http.completed", {"method": method, "path": path, "status": response.status})
            raw = response.read(2 * 1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 2 * 1024 * 1024:
                raise ValueError("Home Assistant action failed")
            return json.loads(raw)
        finally:
            connection.close()

    def prepare(self, action, target):
        data = self.call(action, "GET", "/api/states/" + target)
        if data.get("entity_id") != target or data.get("state") not in ("on", "off") or not isinstance(data.get("last_changed"), str):
            raise Denied("entity unavailable or unsupported")
        return {"entity_id": target, "state": data["state"], "last_changed": data["last_changed"]}

    def execute(self, action, target, before):
        if self.prepare(action, target) != before:
            raise Conflict("entity changed")
        desired = "on" if action["operation"] == "turn-on" else "off"
        if before["state"] != desired:
            domain = target.split('.')[0]
            self.call(action, "POST", "/api/services/" + domain + "/turn_" + desired, {"entity_id": target})
        for attempt in range(6):
            after = self.prepare(action, target)
            if after["state"] == desired:
                return {"changed": before["state"] != desired, "after": after}
            if attempt < 5:
                time.sleep(1)
        raise ValueError("entity state not verified")
