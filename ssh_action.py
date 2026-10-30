#!/usr/bin/python3
"""Root-owned SRG remote action executor. No arbitrary commands, paths or flags."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import syslog
import time

POLICY = Path('/etc/srg-actions.json')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
REQUEST_ID = None
OPERATIONS = {'container-start', 'container-restart', 'vm-start', 'vm-shutdown'}


def run(argv, timeout=15):
    syslog.syslog(syslog.LOG_NOTICE, json.dumps({"event": "command.started", "request_id": REQUEST_ID, "argv": argv}))
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=ENV, timeout=timeout)
    syslog.syslog(syslog.LOG_NOTICE, json.dumps({"event": "command.completed", "request_id": REQUEST_ID, "argv": argv, "returncode": result.returncode}))
    if result.returncode:
        raise ValueError('command failed')
    if len(result.stdout) > 65536:
        raise ValueError('response too large')
    return result.stdout.decode()


def snapshot(operation, target):
    if operation.startswith('container-'):
        # Emit only identity/state fields. Never read container env or mounts.
        data = json.loads(run(['/usr/bin/docker', 'inspect', '--type', 'container', '--format',
            '{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},"status":{{json .State.Status}},"started":{{json .State.StartedAt}}}', target]))
        if data['name'] != '/' + target or data['status'] not in ('running', 'exited', 'created'):
            raise ValueError('unexpected container identity or state')
        # Health may fluctuate independently of an administrative change.
        return data
    if not re.fullmatch(r'[1-9][0-9]{2,8}', target):
        raise ValueError('invalid VM')
    status = run(['/usr/sbin/qm', 'status', target]).strip()
    if status not in ('status: running', 'status: stopped'):
        raise ValueError('unexpected VM state')
    config = run(['/usr/sbin/qm', 'config', target])
    return {'vmid': target, 'status': status.split(': ')[1], 'config_sha256': hashlib.sha256(config.encode()).hexdigest()}


def validate_request(request, policy):
    if not isinstance(request, dict) or set(request) != {'mode', 'operation', 'target', 'expected', 'request_id'}:
        raise ValueError('invalid request fields')
    if not isinstance(request['request_id'], str) or not re.fullmatch(r'[a-f0-9]{48}', request['request_id']):
        raise ValueError('invalid request id')
    mode, operation, target = (request[x] for x in ('mode', 'operation', 'target'))
    if mode not in ('prepare', 'execute') or operation not in OPERATIONS or type(target) is not str:
        raise ValueError('unsupported request')
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', target) or target not in policy.get(operation, []):
        raise ValueError('target denied')
    if mode == 'prepare' and request['expected'] is not None:
        raise ValueError('unexpected precondition')
    if mode == 'execute' and not isinstance(request['expected'], dict):
        raise ValueError('missing precondition')
    return mode, operation, target


def execute(operation, target, before):
    # Names can be reassigned by external Docker clients after the snapshot.
    # Mutate and health-check only the immutable identity that was previewed.
    identity = before.get('id') if operation.startswith('container-') else target
    if operation.startswith('container-') and (type(identity) is not str or not re.fullmatch(r'[a-f0-9]{64}', identity)):
        raise ValueError('invalid container identity')
    if operation == 'container-start':
        if before['status'] != 'running':
            run(['/usr/bin/docker', 'start', identity], timeout=40)
    elif operation == 'container-restart':
        if before['status'] != 'running':
            raise ValueError('restart requires a running container')
        run(['/usr/bin/docker', 'restart', '--timeout', '30', identity], timeout=45)
    elif operation == 'vm-start':
        if before['status'] != 'running':
            run(['/usr/sbin/qm', 'start', target], timeout=60)
    elif operation == 'vm-shutdown':
        if before['status'] != 'stopped':
            run(['/usr/sbin/qm', 'shutdown', target, '--timeout', '60', '--forceStop', '0'], timeout=70)
    desired = 'stopped' if operation == 'vm-shutdown' else 'running'
    for attempt in range(10):
        after = snapshot(operation, target)
        if after['status'] == desired:
            if operation.startswith('vm-') and after.get('config_sha256') != before.get('config_sha256'):
                raise ValueError('VM configuration changed during operation')
            if operation.startswith('container-'):
                if after['id'] != before['id'] or after['image'] != before['image']:
                    raise ValueError('container identity changed')
                health = run(['/usr/bin/docker', 'inspect', '--format', '{{if index .State "Health"}}{{index (index .State "Health") "Status"}}{{else}}none{{end}}', identity]).strip()
                if health not in ('none', 'healthy'):
                    if attempt < 9:
                        time.sleep(1)
                        continue
                    raise ValueError('container health not verified')
            return {'changed': after != before, 'after': after}
        if attempt < 9:
            time.sleep(1)
    raise ValueError('target state not verified')


def main():
    global REQUEST_ID
    syslog.openlog('srg-action', syslog.LOG_PID, syslog.LOG_AUTHPRIV)
    if os.geteuid() != 0 or len(sys.argv) != 1:
        raise ValueError('root executor with no arguments required')
    stat = POLICY.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise ValueError('unsafe policy permissions')
    raw = sys.stdin.buffer.read(8193)
    if len(raw) > 8192:
        raise ValueError('request too large')
    request = json.loads(raw)
    mode, operation, target = validate_request(request, json.loads(POLICY.read_text()))
    REQUEST_ID = request['request_id']
    syslog.syslog(syslog.LOG_NOTICE, json.dumps({'event': 'request.validated', 'request_id': REQUEST_ID, 'mode': mode, 'operation': operation, 'target': target}))
    # Serialize across all remote calls, including calls outside this gateway.
    with open('/run/lock/srg-actions.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(operation, target)
        if mode == 'prepare':
            result = before
        else:
            if before != request['expected']:
                raise ValueError('target changed')
            result = execute(operation, target, before)
        syslog.syslog(syslog.LOG_NOTICE, json.dumps({"event": "request.verified", "request_id": REQUEST_ID, "mode": mode}))
        print(json.dumps(result, allow_nan=False))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        syslog.syslog(syslog.LOG_ERR, json.dumps({'event': 'request.failed', 'request_id': REQUEST_ID}))
        print('{"error":"action denied, failed, or unverified"}')
        sys.exit(1)
