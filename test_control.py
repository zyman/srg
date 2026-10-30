import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from control import Controller, Conflict, Denied, ActionContext
from action_adapters import SSHAdapter, HomeAssistantAdapter
import ssh_action

CLIENT = 'a' * 64
OTHER = 'b' * 64


class FakeAdapter:
    def __init__(self):
        self.state = {'status': 'running', 'generation': 1}
        self.calls = 0
        self.fail = False

    def validate(self, action):
        pass

    def prepare(self, action, target, context):
        return self.state.copy()

    def execute(self, action, target, before, context):
        self.calls += 1
        if self.fail:
            raise RuntimeError('SECRET backend failure')
        self.state['generation'] += 1
        return self.state.copy()


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / 'control.sqlite3')
        self.now = 1000
        self.adapter = FakeAdapter()
        self.policy = {'clients': [CLIENT, OTHER], 'actions': {'restart': {'adapter': 'fake', 'operation': 'restart', 'risk': 'routine', 'description': 'restart allowlisted app', 'targets': ['app']}}, 'write_grants': {CLIENT: ['restart']}}
        self.controller = Controller(self.policy, {'fake': self.adapter}, self.path, lambda: self.now)

    def tearDown(self):
        self.controller.db.close()
        self.temp.cleanup()

    def plan(self):
        return self.controller.plan(CLIENT, {'action': 'restart', 'target': 'app'})

    def test_preview_does_not_execute_and_replay_never_executes_twice(self):
        plan = self.plan()
        self.assertEqual(self.adapter.calls, 0)
        result = self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        self.assertEqual(result['status'], 'succeeded')
        with self.assertRaises(Conflict):
            self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        self.assertEqual(self.adapter.calls, 1)
        events = [x['event'] for x in self.controller.audit_tail(CLIENT)]
        self.assertIn('execute.started', events)
        self.assertIn('execute.verified', events)

    def test_read_only_client_target_scope_extra_fields_and_arbitrary_actions(self):
        for request in ({'action': 'delete', 'target': 'app'}, {'action': 'restart', 'target': 'database'}, {'action': 'restart', 'target': 'app', 'shell': 'id'}):
            with self.assertRaises(Denied):
                self.controller.plan(CLIENT, request)
        with self.assertRaises(Denied):
            self.controller.plan(OTHER, {'action': 'restart', 'target': 'app'})
        plan = self.plan()
        with self.assertRaises(Denied):
            self.controller.apply(OTHER, {'plan_id': plan['plan_id']})
        self.assertEqual(self.controller.capabilities(OTHER)['actions'], {})
        self.assertEqual(self.adapter.calls, 0)

    def test_expiry_and_changed_target_fail_closed(self):
        plan = self.plan()
        self.now += 121
        with self.assertRaises(Conflict):
            self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        plan = self.plan()
        self.adapter.state['generation'] += 1
        with self.assertRaises(Conflict):
            self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        self.assertEqual(self.adapter.calls, 0)

    def test_policy_change_and_restart_preserve_replay_boundary(self):
        plan = self.plan()
        policy = copy.deepcopy(self.policy)
        policy['actions']['restart']['description'] = 'new revision'
        restarted = Controller(policy, {'fake': self.adapter}, self.path, lambda: self.now)
        with self.assertRaises(Conflict):
            restarted.apply(CLIENT, {'plan_id': plan['plan_id']})
        restarted.db.close()
        self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        restarted = Controller(self.policy, {'fake': self.adapter}, self.path, lambda: self.now)
        with self.assertRaises(Conflict):
            restarted.apply(CLIENT, {'plan_id': plan['plan_id']})
        restarted.db.close()
        self.assertEqual(self.adapter.calls, 1)

    def test_ambiguous_failure_not_retried_and_error_redacted(self):
        plan = self.plan()
        self.adapter.fail = True
        with self.assertRaises(RuntimeError):
            self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        result = self.controller.status(CLIENT, plan['plan_id'])
        self.assertEqual(result['status'], 'uncertain')
        self.assertNotIn('SECRET', json.dumps(result))
        with self.assertRaises(Conflict):
            self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        self.assertEqual(self.adapter.calls, 1)

    def test_audit_failure_prevents_execution(self):
        plan = self.plan()
        with patch.object(self.controller, 'audit', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.controller.apply(CLIENT, {'plan_id': plan['plan_id']})
        self.assertEqual(self.adapter.calls, 0)

    def test_request_context_retains_client_identity_across_later_plans(self):
        contexts = []
        def prepare(action, target, context):
            contexts.append(context)
            return {'status': 'running'}
        self.controller.policy['write_grants'][OTHER] = ['restart']
        with patch.object(self.adapter, 'prepare', side_effect=prepare):
            first = self.plan()
            second = self.controller.plan(OTHER, {'action': 'restart', 'target': 'app'})
        contexts[0].audit('late.first', {})
        contexts[1].audit('late.second', {})
        first_events = self.controller.audit_tail(CLIENT)
        second_events = self.controller.audit_tail(OTHER)
        self.assertTrue(any(e['event'] == 'late.first' and e['detail']['plan_id'] == first['plan_id'] for e in first_events))
        self.assertTrue(any(e['event'] == 'late.second' and e['detail']['plan_id'] == second['plan_id'] for e in second_events))
        self.assertFalse(any(e['event'] == 'late.second' for e in first_events))

    def test_existing_ledger_index_migration_preserves_records(self):
        from ledger import verify
        self.plan()
        original = verify(self.controller.db)
        self.controller.db.execute('DROP INDEX audit_client_seq')
        self.controller.db.commit()
        restarted = Controller(self.policy, {'fake': self.adapter}, self.path)
        try:
            self.assertEqual(verify(restarted.db), original)
            query = restarted.db.execute('EXPLAIN QUERY PLAN SELECT seq FROM audit WHERE client=? ORDER BY seq DESC LIMIT 100', (CLIENT,)).fetchall()
            self.assertTrue(any('audit_client_seq' in row[-1] for row in query))
        finally:
            restarted.db.close()

    def test_corrupt_ledger_blocks_restart(self):
        self.plan()
        self.controller.db.execute("UPDATE audit SET detail='{}' WHERE seq=1")
        self.controller.db.commit()
        with self.assertRaises(ValueError):
            Controller(self.policy, {'fake': self.adapter}, self.path)
        self.assertEqual(self.adapter.calls, 0)

    def test_destructive_risk_cannot_be_installed(self):
        policy = copy.deepcopy(self.policy)
        policy['actions']['restart']['risk'] = 'destructive'
        with self.assertRaises(ValueError):
            Controller(policy, {'fake': self.adapter}, ':memory:')


class BoundaryTests(unittest.TestCase):
    def test_remote_helper_rejects_shell_options_extra_fields_and_ungated_targets(self):
        policy = {'container-start': ['app']}
        valid = {'mode': 'prepare', 'operation': 'container-start', 'target': 'app', 'expected': None, 'request_id': 'a' * 48}
        self.assertEqual(ssh_action.validate_request(valid, policy), ('prepare', 'container-start', 'app'))
        for request in ({**valid, 'target': '-v'}, {**valid, 'target': 'app;id'}, {**valid, 'target': 'database'}, {**valid, 'operation': 'container-delete'}, {**valid, 'command': 'id'}, {**valid, 'mode': 'execute'}):
            with self.assertRaises(ValueError):
                ssh_action.validate_request(request, policy)

    def test_adapters_reject_untrusted_origins_commands_and_entity_domains(self):
        ssh = SSHAdapter('/creds')
        ha = HomeAssistantAdapter('/creds')
        with self.assertRaises(ValueError):
            ssh.validate({'operation': 'shell', 'host': 'host', 'targets': ['app']})
        for url, targets in [('http://host', ['light.room']), ('https://host', ['lock.front_door']), ('https://host/path', ['light.room'])]:
            with self.assertRaises(ValueError):
                ha.validate({'url': url, 'operation': 'turn-on', 'credential': 'ha', 'targets': targets})

    def test_docker_mutation_uses_previewed_id_even_if_name_is_reassigned(self):
        before = {'status': 'running', 'id': 'a' * 64, 'image': 'sha256:old'}
        replacement = {**before, 'id': 'b' * 64}
        with patch.object(ssh_action, 'run', return_value='none') as run, patch.object(ssh_action, 'snapshot', return_value=replacement):
            with self.assertRaises(ValueError):
                ssh_action.execute('container-restart', 'app', before)
        self.assertEqual(run.call_args_list[0].args[0], ['/usr/bin/docker', 'restart', '--timeout', '30', 'a' * 64])
        self.assertEqual(run.call_count, 1)
        with patch.object(ssh_action, 'run') as run:
            with self.assertRaises(ValueError):
                ssh_action.execute('container-start', 'app', {'status': 'exited', 'id': '--help'})
            run.assert_not_called()

    def test_vm_shutdown_never_force_stops(self):
        before = {'status': 'running'}
        with patch.object(ssh_action, 'run', return_value='') as run, patch.object(ssh_action, 'snapshot', return_value={'status': 'stopped'}):
            ssh_action.execute('vm-shutdown', '101', before)
        self.assertEqual(run.call_args.args[0], ['/usr/sbin/qm', 'shutdown', '101', '--timeout', '60', '--forceStop', '0'])

    def test_home_assistant_noop_does_not_call_service(self):
        adapter = HomeAssistantAdapter('/creds')
        before = {'entity_id': 'switch.quiet', 'state': 'on', 'last_changed': 'now'}
        with patch.object(adapter, 'prepare', return_value=before), patch.object(adapter, 'call') as call:
            result = adapter.execute({'operation': 'turn-on'}, 'switch.quiet', before, ActionContext('a' * 48, lambda *args: None))
        self.assertFalse(result['changed'])
        call.assert_not_called()

class AuditTests(unittest.TestCase):
    def test_chain_detects_tampering(self):
        from audit import verify
        controller = Controller({'clients': [CLIENT], 'resources': {}}, {}, ':memory:')
        controller.audit(CLIENT, 'request', {'operation': 'health'})
        controller.audit(CLIENT, 'response', {'status': 200})
        self.assertEqual(verify(controller.db)['records'], 2)
        controller.db.execute("UPDATE audit SET detail='{}' WHERE seq=1")
        controller.db.commit()
        with self.assertRaises(ValueError):
            verify(controller.db)
        controller.db.close()
