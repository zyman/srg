"""Offline setup checks; real Linux/systemd install is exercised by CI."""
import json
from pathlib import Path
import subprocess
import os
import sys
import unittest
import tempfile

import gateway
from control import validate_policy
from action_adapters import SSHAdapter, HomeAssistantAdapter

ROOT = Path(__file__).resolve().parent


class InstallationTests(unittest.TestCase):
    def test_documented_examples_validate(self):
        policy = json.loads((ROOT / 'examples/policy.json').read_text())
        policy['resources'].update(json.loads((ROOT / 'examples/resources.json').read_text()))
        policy['actions'].update(json.loads((ROOT / 'examples/ha-action.json').read_text()))
        gateway.validate(policy)
        validate_policy(policy, {'ssh': SSHAdapter('/unused'), 'home_assistant': HomeAssistantAdapter('/unused')})

    def test_check_works_without_credentials_or_running_backends(self):
        result = subprocess.run([sys.executable, str(ROOT / 'gateway.py'), '--config', str(ROOT / 'examples/policy.json'), '--check'], capture_output=True, text=True, env={key: value for key, value in os.environ.items() if key != 'CREDENTIALS_DIRECTORY'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Policy valid', result.stdout)

    def test_check_rejects_invalid_policy_without_echoing_values(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            policy = json.loads((ROOT / 'examples/policy.json').read_text())
            policy['read_grants'] = {policy['clients'][0]: ['SECRET_UNKNOWN_RESOURCE']}
            path.write_text(json.dumps(policy))
            result = subprocess.run([sys.executable, str(ROOT / 'gateway.py'), '--config', str(path), '--check'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('SECRET', result.stdout + result.stderr)

    def test_service_requires_only_provisioned_credentials(self):
        service = (ROOT / 'examples/srg.service').read_text()
        names = [line.split('=', 1)[1].split(':')[0] for line in service.splitlines() if line.startswith('LoadCredential=')]
        self.assertEqual(set(names), {'server-cert', 'server-key', 'client-ca'})
        self.assertIn('StateDirectory=srg', service)
        self.assertIn('DynamicUser=yes', service)
