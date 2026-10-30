"""Real MCP subprocess -> mTLS SRG -> controller tests; no infrastructure touched."""
import asyncio
from contextlib import asynccontextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import ssl
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import gateway
import test_gateway as gateway_tests
import test_control as control_tests
from control import Controller
from ledger import verify

MCP_AVAILABLE = importlib.util.find_spec('mcp') is not None
ROOT = Path(__file__).resolve().parent


@unittest.skipUnless(MCP_AVAILABLE, 'optional MCP dependencies not installed')
class MCPIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        gateway_tests.GatewayTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        gateway_tests.GatewayTests.tearDownClass.__func__(cls)

    async def asyncSetUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.adapter = control_tests.FakeAdapter()
        self.other = hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.root / 'other.pem').read_text())).hexdigest()
        self.policy = {'clients': [self.fingerprint, self.other],
                       'resources': {'demo': {'kind': 'https', 'url': 'https://example.invalid'},
                                     'hidden': {'kind': 'https', 'url': 'https://hidden.invalid'}},
                       'read_grants': {self.fingerprint: ['demo']},
                       'actions': {'restart': {'adapter': 'fake', 'operation': 'restart', 'risk': 'routine',
                                              'description': 'Test action', 'targets': ['app']}},
                       'write_grants': {self.fingerprint: ['restart']}}
        self.server = gateway.Server(('127.0.0.1', 0), gateway.Handler)
        self.server.policy, self.server.credentials = gateway.validate(self.policy), self.root
        self.server.controller = Controller(self.policy, {'fake': self.adapter}, str(Path(self.work.name) / 'ledger.sqlite3'))
        self.server.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.tls.load_cert_chain(self.root / 'server.pem', self.root / 'server.key')
        self.server.tls.load_verify_locations(self.root / 'ca.pem')
        self.server.tls.verify_mode = ssl.CERT_REQUIRED
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.logs = []

    async def asyncTearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server.controller.db.close()
        self.work.cleanup()

    def config(self, identity):
        path = Path(self.work.name) / (identity + '.json')
        path.write_text(json.dumps({'url': 'https://localhost:' + str(self.server.server_port),
                                   'ca_file': str(self.root / 'ca.pem'), 'certificate': str(self.root / (identity + '.pem')),
                                   'key': str(self.root / (identity + '.key'))}))
        return path

    @asynccontextmanager
    async def bridge(self, identity='client', config=None):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        with tempfile.TemporaryFile(mode='w+') as errors:
            params = StdioServerParameters(command=sys.executable, args=[str(ROOT / 'mcp_server.py'), '--config', str(config or self.config(identity))])
            try:
                async with stdio_client(params, errlog=errors) as (incoming, outgoing):
                    async with ClientSession(incoming, outgoing, read_timeout_seconds=15) as session:
                        await session.initialize()
                        yield session
            finally:
                errors.seek(0)
                self.logs.append(errors.read())

    async def test_discovery_reads_writes_replay_and_audit(self):
        with patch.object(gateway, 'fetch', return_value={'healthy': True}) as fetch:
            async with self.bridge() as session:
                tools = (await session.list_tools()).tools
                self.assertEqual({t.name for t in tools}, {'srg_resources', 'srg_read', 'srg_capabilities', 'srg_plan', 'srg_apply', 'srg_status', 'srg_audit'})
                self.assertTrue(next(t for t in tools if t.name == 'srg_apply').annotations.destructive_hint)
                catalog = await session.call_tool('srg_resources', {})
                self.assertEqual(catalog.structured_content, {'demo': ['health']})
                read = await session.call_tool('srg_read', {'resource': 'demo', 'operation': 'health'})
                self.assertEqual(read.structured_content, {'data': {'healthy': True}})
                denied = await session.call_tool('srg_read', {'resource': 'hidden', 'operation': 'health'})
                self.assertTrue(denied.is_error)
                self.assertEqual(denied.structured_content['error']['http_status'], 404)
                self.assertEqual(fetch.call_count, 1)
                capabilities = await session.call_tool('srg_capabilities', {})
                self.assertEqual(set(capabilities.structured_content['actions']), {'restart'})
                plan = (await session.call_tool('srg_plan', {'action': 'restart', 'target': 'app'})).structured_content
                self.assertEqual(self.adapter.calls, 0)
                applied = await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})
                self.assertFalse(applied.is_error)
                self.assertEqual(applied.structured_content['status'], 'succeeded')
                replay = await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})
                self.assertEqual(replay.structured_content['error']['http_status'], 409)
                self.assertEqual(self.adapter.calls, 1)
                status = await session.call_tool('srg_status', {'plan_id': plan['plan_id']})
                self.assertEqual(status.structured_content['status'], 'succeeded')
                events = (await session.call_tool('srg_audit', {})).structured_content['events']
                self.assertTrue(any(e['event'] == 'execute.verified' and e['detail']['plan_id'] == plan['plan_id'] for e in events))
                self.assertTrue(any(e['event'] == 'read.started' for e in events))
        self.assertGreater(verify(self.server.controller.db)['records'], 0)
        self.assertIn('mcp.call.finished', self.logs[0])

    async def test_read_only_identity_cannot_read_or_claim_other_clients_plan(self):
        plan = self.server.controller.plan(self.fingerprint, {'action': 'restart', 'target': 'app'})
        async with self.bridge('other') as session:
            self.assertEqual((await session.call_tool('srg_resources', {})).structured_content, {})
            self.assertEqual((await session.call_tool('srg_capabilities', {})).structured_content['actions'], {})
            for tool, args in [('srg_plan', {'action': 'restart', 'target': 'app'}),
                               ('srg_apply', {'plan_id': plan['plan_id']}), ('srg_status', {'plan_id': plan['plan_id']})]:
                result = await session.call_tool(tool, args)
                self.assertEqual(result.structured_content['error']['http_status'], 403)
            self.policy['clients'].remove(self.other)
            denied = await session.call_tool('srg_resources', {})
            self.assertEqual(denied.structured_content['error']['http_status'], 403)
        self.assertEqual(self.adapter.calls, 0)
        self.assertEqual(self.server.controller.status(self.fingerprint, plan['plan_id'])['status'], 'planned')

    async def test_rejections_and_uncertainty_do_not_retry_or_leak(self):
        async with self.bridge() as session:
            before = verify(self.server.controller.db)['records']
            for tool, args in [('srg_read', {'resource': 'demo/../../SECRET', 'operation': 'health'}),
                               ('srg_resources', {'url': 'https://SECRET'}),
                               ('srg_apply', {'plan_id': 'invalid-SECRET'}),
                               ('unknown_SECRET', {})]:
                result = await session.call_tool(tool, args)
                self.assertTrue(result.is_error)
                self.assertNotIn('SECRET', result.model_dump_json())
            self.assertEqual(verify(self.server.controller.db)['records'], before)
            denied = await session.call_tool('srg_plan', {'action': 'restart', 'target': 'not-allowed'})
            self.assertEqual(denied.structured_content['error']['http_status'], 403)
            plan = (await session.call_tool('srg_plan', {'action': 'restart', 'target': 'app'})).structured_content
            self.adapter.fail = True
            result = await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})
            self.assertTrue(result.is_error)
            self.assertEqual(result.structured_content['error']['http_status'], 502)
            self.assertIn('Do not retry', result.structured_content['error']['recovery'])
            self.assertNotIn('SECRET', result.model_dump_json())
            self.assertEqual(self.adapter.calls, 1)
            status = await session.call_tool('srg_status', {'plan_id': plan['plan_id']})
            self.assertEqual(status.structured_content['status'], 'uncertain')
        self.assertNotIn('SECRET', ''.join(self.logs))

    async def test_expiry_stale_state_and_audit_failure_preserve_boundary(self):
        async with self.bridge() as session:
            args = {'action': 'restart', 'target': 'app'}
            plan = (await session.call_tool('srg_plan', args)).structured_content
            self.server.controller.db.execute('UPDATE plans SET expires=0 WHERE id=?', (plan['plan_id'],))
            self.server.controller.db.commit()
            self.assertEqual((await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})).structured_content['error']['http_status'], 409)
            plan = (await session.call_tool('srg_plan', args)).structured_content
            self.adapter.state['generation'] += 1
            self.assertEqual((await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})).structured_content['error']['http_status'], 409)
            plan = (await session.call_tool('srg_plan', args)).structured_content
            with patch.object(self.server.controller, 'audit', side_effect=OSError('SECRET disk error')):
                result = await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})
            self.assertTrue(result.is_error)
            self.assertNotIn('SECRET', result.model_dump_json())
            self.assertEqual(self.adapter.calls, 0)

    async def test_lost_apply_response_does_not_repeat_execution(self):
        original = gateway.Handler.reply
        def drop_success(handler, status, body, operation='rejected'):
            if operation == 'apply' and status == 200:
                handler.close_connection = True
                handler.connection.shutdown(socket.SHUT_RDWR)
                handler.connection.close()
                return
            return original(handler, status, body, operation)
        async with self.bridge() as session:
            plan = (await session.call_tool('srg_plan', {'action': 'restart', 'target': 'app'})).structured_content
            with patch.object(gateway.Handler, 'reply', drop_success):
                result = await session.call_tool('srg_apply', {'plan_id': plan['plan_id']})
            self.assertTrue(result.is_error)
            self.assertEqual(result.structured_content['error']['code'], 'connection_failure')
            self.assertEqual(self.adapter.calls, 1)
            status = await session.call_tool('srg_status', {'plan_id': plan['plan_id']})
            self.assertEqual(status.structured_content['status'], 'succeeded')
            self.assertEqual(self.adapter.calls, 1)

    async def test_tls_trust_and_hostname_cannot_be_bypassed(self):
        for field, value in [('ca_file', str(self.root / 'other.pem')),
                             ('url', 'https://127.0.0.1:' + str(self.server.server_port))]:
            config = self.config('client')
            data = json.loads(config.read_text()); data[field] = value
            config.write_text(json.dumps(data))
            async with self.bridge(config=config) as session:
                result = await session.call_tool('srg_resources', {})
                self.assertTrue(result.is_error)
                self.assertEqual(result.structured_content['error']['code'], 'connection_failure')
        self.assertEqual(verify(self.server.controller.db)['records'], 0)

    async def test_legacy_stdio_protocol_has_no_stdout_logging(self):
        # Exercise the legacy wire format used by existing MCP hosts, independently
        # of the current SDK client's modern per-request envelope negotiation.
        with tempfile.TemporaryFile(mode='w+') as errors:
            process = await asyncio.create_subprocess_exec(sys.executable, str(ROOT / 'mcp_server.py'), '--config', str(self.config('client')),
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=errors)
            async def exchange(message):
                process.stdin.write((json.dumps(message) + '\n').encode())
                await process.stdin.drain()
                return json.loads(await asyncio.wait_for(process.stdout.readline(), 15))
            try:
                init = await exchange({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25', 'capabilities': {}, 'clientInfo': {'name': 'legacy-test', 'version': '1'}}})
                self.assertIn('result', init)
                process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
                result = await exchange({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 'srg_resources', 'arguments': {}}})
                self.assertEqual(result['id'], 2)
                self.assertEqual(result['result']['structuredContent'], {'demo': ['health']})
                self.assertFalse(result['result'].get('isError', False))
            finally:
                process.stdin.close()
                try:
                    await asyncio.wait_for(process.wait(), 5)
                except TimeoutError:
                    process.kill()
                    await process.wait()
