import contextlib
import hashlib
import http.client
import io
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

import gateway


class GatewayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=cls.root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=test-ca", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        for name, purpose in (("server", "serverAuth"), ("client", "clientAuth"), ("other", "clientAuth")):
            openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + name)
            (cls.root / "extensions").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\nsubjectAltName=DNS:localhost\nextendedKeyUsage=" + purpose + "\n")
            openssl("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", name + ".pem", "-days", "1", "-extfile", "extensions")
        cert = ssl.PEM_cert_to_DER_cert((cls.root / "client.pem").read_text())
        cls.fingerprint = hashlib.sha256(cert).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.server = gateway.Server(("127.0.0.1", 0), gateway.Handler)
        self.server.policy = gateway.validate({"clients": [self.fingerprint], "resources": {
            "pve": {"kind": "proxmox", "url": "https://localhost", "credential": "pve"}}})
        self.server.credentials = self.root
        self.server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.tls.load_cert_chain(self.root / "server.pem", self.root / "server.key")
        self.server.tls.load_verify_locations(self.root / "ca.pem")
        self.server.tls.verify_mode = ssl.CERT_REQUIRED
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, method="GET", identity="client", body=None, headers=None):
        tls = ssl.create_default_context(cafile=self.root / "ca.pem")
        if identity:
            tls.load_cert_chain(self.root / (identity + ".pem"), self.root / (identity + ".key"))
        connection = http.client.HTTPSConnection("localhost", self.server.server_port, context=tls, timeout=2)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_authorized_inventory(self):
        self.assertEqual(self.request("/v1/resources"), (200, {"pve": ["nodes", "guests"]}))

    def test_ca_signed_but_unlisted_client_is_denied(self):
        self.assertEqual(self.request("/v1/resources", identity="other")[0], 403)

    def test_no_client_certificate_is_denied(self):
        with self.assertRaises((ssl.SSLError, OSError)):
            self.request("/v1/resources", identity=None)

    def test_mutation_and_arbitrary_paths_never_reach_upstream(self):
        with patch.object(gateway, "fetch") as fetch:
            for path in ("/v1/pve/guests?url=https://evil", "/v1/pve/../nodes", "/v1/pve/%6eodes", "/v1/missing/nodes", "/v1/pve/delete"):
                self.assertEqual(self.request(path)[0], 404)
            self.assertEqual(self.request("/v1/pve/nodes", method="POST")[0], 404)
            self.assertEqual(self.request("/v1/pve/nodes", body="payload")[0], 400)
            fetch.assert_not_called()

    def test_upstream_error_redacted_from_response_and_audit(self):
        output = io.StringIO()
        with patch.object(gateway, "fetch", side_effect=ValueError("SECRET")), contextlib.redirect_stdout(output):
            status, response = self.request("/v1/pve/nodes")
        self.assertEqual(status, 502)
        self.assertNotIn("SECRET", json.dumps(response) + output.getvalue())

    def test_fixed_upstream_request_and_projection(self):
        (self.root / "pve").write_text("test-token")
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({"data": [{"node": "node-a", "status": "online", "password": "SECRET", "mem": {"secret": "SECRET"}}]}).encode()
            data = gateway.fetch(self.server.policy["resources"]["pve"], "nodes", self.root)
            self.assertEqual(data, [{"node": "node-a", "status": "online"}])
            connection.return_value.request.assert_called_once_with("GET", "/api2/json/nodes", headers={"Accept": "application/json", "Authorization": "PVEAPIToken=test-token"})
            response.status = 302
            with self.assertRaises(ValueError):
                gateway.fetch(self.server.policy["resources"]["pve"], "nodes", self.root)

    def test_reject_unsafe_origins_and_credential_paths(self):
        for url in ("http://localhost", "https://user:pass@localhost", "https://localhost/api", "https://localhost?x=1"):
            with self.assertRaises(ValueError):
                gateway.validate({"clients": [self.fingerprint], "resources": {"pve": {"kind": "proxmox", "url": url, "credential": "pve"}}})
        self.server.policy["resources"]["pve"]["credential"] = "../secret"
        with self.assertRaises(ValueError):
            gateway.validate(self.server.policy)

    def test_host_health_reads_only_metrics(self):
        with patch.object(gateway.Path, "read_text", side_effect=["MemTotal: 100 kB\nMemAvailable: 40 kB", "123.4 90"]), patch.object(gateway.os, "getloadavg", return_value=(1, 2, 3)):
            result = gateway.fetch({"kind": "host"}, "health", self.root)
        self.assertEqual(result, {"uptime_seconds": 123.4, "load_average": [1, 2, 3], "memory_total_kib": 100, "memory_available_kib": 40, "memory_available_estimated": False})

    def test_ssh_reader_has_fixed_command_and_strict_trust(self):
        metrics = {"uptime_seconds": 5, "load_average": [0, 0, 0], "memory_total_kib": 100, "memory_available_kib": 50, "memory_available_estimated": False, "secret": "filtered"}
        def run(command, **kwargs):
            self.assertEqual(command[-2:], ["agentops@worker.example.internal", "health"])
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("IdentityAgent=none", command)
            self.assertNotIn("shell", kwargs)
            kwargs["stdout"].write(json.dumps(metrics).encode())
            return subprocess.CompletedProcess(command, 0)
        with patch.object(gateway.subprocess, "run", side_effect=run):
            data = gateway.fetch({"kind": "ssh", "host": "worker.example.internal", "credential": "ssh-reader", "known_hosts": "/trusted/known_hosts"}, "health", self.root)
        self.assertNotIn("secret", data)

    def test_ssh_rejects_option_and_path_injection(self):
        for host in ("-oProxyCommand=id", "host;id", "host/path", "host\nother"):
            with self.assertRaises(ValueError):
                gateway.validate({"clients": [self.fingerprint], "resources": {"test": {"kind": "ssh", "host": host, "credential": "ssh-reader"}}})

    def test_reader_rejects_arbitrary_remote_commands(self):
        reader = Path(__file__).with_name("reader.sh")
        if not reader.exists():
            reader = Path(__file__).parents[2] / "ansible/roles/access_reader/files/reader.sh"
        for command in ("id", "health; id", "scp -t /tmp/file", ""):
            result = subprocess.run(["/bin/sh", str(reader)], env={"SSH_ORIGINAL_COMMAND": command}, capture_output=True)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout, b"")

    def test_https_health_never_sends_a_credential_or_follows_redirect(self):
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 302
            result = gateway.fetch({"kind": "https", "url": "https://localhost"}, "health", self.root)
            self.assertEqual(result["http_status"], 302)
            connection.return_value.request.assert_called_once_with("GET", "/", headers={"Accept": "application/json"})
            response.read.assert_not_called()

    def test_guest_projection_and_fixed_path(self):
        (self.root / "pve").write_text("test-token")
        resource = {"kind": "proxmox_guest", "url": "https://localhost", "node": "node-a", "vmid": 105, "credential": "pve"}
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps({"data": {"result": {"name": "HAOS", "secret": "SECRET", "version": {"nested": "SECRET"}}}}).encode()
            self.assertEqual(gateway.fetch(resource, "osinfo", self.root), {"name": "HAOS"})
            self.assertEqual(connection.return_value.request.call_args.args[:2], ("GET", "/api2/json/nodes/node-a/qemu/105/agent/get-osinfo"))
        for field, value in (("node", "node-a/../../access"), ("vmid", "105/agent/exec"), ("vmid", True)):
            with self.assertRaises(ValueError):
                gateway.validate({"clients": [self.fingerprint], "resources": {"haos": {**resource, field: value}}})

    def test_portainer_excludes_snapshots_and_credentials(self):
        (self.root / "portainer").write_text("test-token")
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps([{"Id": 1, "Name": "demo-app", "Type": 1, "Status": 1, "Snapshots": [{"password": "SECRET"}], "TLSConfig": {"key": "SECRET"}}]).encode()
            data = gateway.fetch({"kind": "portainer", "url": "https://localhost", "credential": "portainer"}, "environments", self.root)
            self.assertEqual(data, [{"Id": 1, "Name": "demo-app", "Type": 1, "Status": 1}])

    def test_home_assistant_projection_and_automation_filter(self):
        (self.root / "ha").write_text("test-ha-token")
        resource = {"kind": "home_assistant", "url": "https://localhost", "credential": "ha"}
        rows = [
            {"entity_id": "sensor.temperature", "state": "21", "context": {"user_id": "SECRET"}, "attributes": {"friendly_name": "Temperature", "unit_of_measurement": "C", "latitude": 54, "token": "SECRET"}},
            {"entity_id": "automation.lights", "state": "on", "attributes": {"last_triggered": None, "action": "SECRET"}},
        ]
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = json.dumps(rows).encode()
            data = gateway.fetch(resource, "states", self.root)
            self.assertEqual(len(data), 2)
            self.assertNotIn("SECRET", json.dumps(data))
            self.assertNotIn("latitude", json.dumps(data))
            connection.return_value.request.assert_called_once_with("GET", "/api/states", headers={"Accept": "application/json", "Authorization": "Bearer test-ha-token"})
            self.assertEqual(gateway.fetch(resource, "automations", self.root), [{"entity_id": "automation.lights", "state": "on", "attributes": {"last_triggered": None}}])

    def test_home_assistant_health_requires_expected_response(self):
        (self.root / "ha").write_text("test-ha-token")
        resource = {"kind": "home_assistant", "url": "https://localhost", "credential": "ha"}
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b'{"message":"API running."}'
            self.assertTrue(gateway.fetch(resource, "health", self.root)["authenticated"])
            response.read.return_value = b'{"message":"unexpected"}'
            with self.assertRaises(ValueError):
                gateway.fetch(resource, "health", self.root)

    def test_home_assistant_writes_and_arbitrary_paths_rejected(self):
        self.server.policy["resources"]["ha"] = {"kind": "home_assistant", "url": "https://localhost", "credential": "ha"}
        with patch.object(gateway, "fetch") as fetch:
            for path in ("/v1/ha/services", "/v1/ha/states?entity_id=light.test", "/v1/ha/automations/trigger"):
                self.assertEqual(self.request(path)[0], 404)
            self.assertEqual(self.request("/v1/ha/states", method="POST")[0], 404)
            fetch.assert_not_called()

    def test_control_transport_plan_apply_audit_and_framing(self):
        from control import Controller
        from test_control import FakeAdapter
        adapter = FakeAdapter()
        policy = self.server.policy
        policy["actions"] = {"restart": {"adapter": "fake", "operation": "restart", "risk": "routine", "description": "test", "targets": ["app"]}}
        policy["write_grants"] = {self.fingerprint: ["restart"]}
        self.server.controller = Controller(policy, {"fake": adapter}, ":memory:")
        try:
            headers = {"Content-Type": "application/json"}
            status, plan = self.request("/v1/plans", "POST", body=json.dumps({"action": "restart", "target": "app"}), headers=headers)
            self.assertEqual(status, 200)
            self.assertEqual(adapter.calls, 0)
            status, result = self.request("/v1/apply", "POST", body=json.dumps({"plan_id": plan["plan_id"]}), headers=headers)
            self.assertEqual((status, result["status"]), (200, "succeeded"))
            self.assertEqual(self.request("/v1/apply", "POST", body=json.dumps({"plan_id": plan["plan_id"]}), headers=headers)[0], 409)
            self.assertEqual(self.request("/v1/plans", "POST", body='{"action":"restart","action":"delete","target":"app"}', headers=headers)[0], 400)
            self.assertEqual(self.request("/v1/plans", "POST", body='{}')[0], 400)
            self.assertEqual(self.request("/v1/plans", "POST", body=json.dumps({"action": "restart", "target": "other"}), headers=headers)[0], 403)
            self.assertEqual(self.request("/v1/plans/" + plan["plan_id"])[1]["status"], "succeeded")
            self.assertTrue(self.request("/v1/audit")[1]["events"])
            self.assertEqual(adapter.calls, 1)
        finally:
            self.server.controller.db.close()
            self.server.controller = None

    def test_oversize_upstream_rejected(self):
        (self.root / "pve").write_text("test-token")
        with patch.object(gateway.http.client, "HTTPSConnection") as connection:
            response = connection.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b"x" * (gateway.LIMIT + 1)
            with self.assertRaises(ValueError):
                gateway.fetch(self.server.policy["resources"]["pve"], "nodes", self.root)


if __name__ == "__main__":
    unittest.main()
