"""Invalid CLI invocations fail before opening identity files or a connection."""
from pathlib import Path
import subprocess
import sys
import unittest


class ClientTests(unittest.TestCase):
    def test_invalid_arguments_rejected_before_identity_access(self):
        cases = [['--plan', 'start'], ['--target', 'app'], ['--apply', 'bad'],
                 ['--status', 'bad'], ['host'], ['host', 'health', '--audit'],
                 ['--audit', '--capabilities'], ['host/evil', 'health']]
        for args in cases:
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, str(Path(__file__).with_name('client.py')), '--config', '/nonexistent-srg-test-identity', *args], capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn('Traceback', result.stderr)
                self.assertNotIn('FileNotFoundError', result.stderr)
