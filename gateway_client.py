"""Standard-library SRG client transport shared by the CLI and optional MCP bridge."""
import http.client
import json
from pathlib import Path
import re
import ssl
from urllib.parse import urlsplit

LIMIT = 2 * 1024 * 1024
NAME = r'[a-z][a-z0-9-]{0,63}'
PLAN_ID = r'[a-f0-9]{48}'
FIELDS = {'resources': (), 'capabilities': (), 'audit': (),
          'read': ('resource', 'operation'), 'plan': ('action', 'target'),
          'apply': ('plan_id',), 'status': ('plan_id',)}


class GatewayError(Exception):
    """Only constant, safe messages cross the client/agent boundary."""
    def __init__(self, code, message, http_status=None):
        super().__init__(message)
        self.code = code
        self.http_status = http_status


def route(operation, arguments):
    if operation not in FIELDS or not isinstance(arguments, dict) or set(arguments) != set(FIELDS[operation]):
        raise GatewayError('invalid_arguments', 'Unknown operation or invalid argument fields.')
    for key, value in arguments.items():
        if type(value) is not str:
            raise GatewayError('invalid_arguments', 'Arguments must be strings.')
        pattern = PLAN_ID if key == 'plan_id' else r'[a-z]+' if key == 'operation' else NAME
        if key == 'target':
            if not 1 <= len(value) <= 128 or any(ord(c) < 32 for c in value):
                raise GatewayError('invalid_arguments', 'Invalid target.')
        elif not re.fullmatch(pattern, value):
            raise GatewayError('invalid_arguments', 'Invalid identifier.')
    if operation == 'read':
        return 'GET', '/v1/' + arguments['resource'] + '/' + arguments['operation'], None
    if operation == 'status':
        return 'GET', '/v1/plans/' + arguments['plan_id'], None
    if operation in ('plan', 'apply'):
        return 'POST', '/v1/' + ('plans' if operation == 'plan' else 'apply'), arguments
    return 'GET', '/v1/' + operation, None


class GatewayClient:
    def __init__(self, config_file):
        try:
            config = json.loads(Path(config_file).read_text())
            url = urlsplit(config['url'])
            if url.scheme != 'https' or not url.hostname or url.username or url.password or url.path not in ('', '/') or url.query or url.fragment:
                raise ValueError('origin')
            self.host, self.port = url.hostname, url.port if url.port is not None else 443
            if not 1 <= self.port <= 65535:
                raise ValueError('port')
            self.context = ssl.create_default_context(cafile=config['ca_file'])
            self.context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.context.load_cert_chain(config['certificate'], config['key'])
        except Exception:
            raise GatewayError('configuration_error', 'Unable to load the SRG client identity. Check configuration, certificate trust and file permissions.') from None

    def invoke(self, operation, arguments=None):
        method, path, body = route(operation, {} if arguments is None else arguments)
        connection = http.client.HTTPSConnection(self.host, self.port, context=self.context, timeout=130)
        try:
            connection.request(method, path, body=json.dumps(body, allow_nan=False) if body is not None else None,
                               headers={'Content-Type': 'application/json'} if body is not None else {})
            response = connection.getresponse()
            if response.status != 200:
                # Never echo an upstream error body, redirect location or exception.
                code = {400: 'invalid_request', 403: 'access_denied', 404: 'not_available',
                        409: 'plan_conflict', 502: 'gateway_failure'}.get(response.status, 'gateway_failure')
                raise GatewayError(code, 'Gateway rejected the request or could not verify its result.', response.status)
            raw = response.read(LIMIT + 1)
            if len(raw) > LIMIT:
                raise GatewayError('invalid_response', 'Gateway response exceeded the size limit.')
            result = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite')))
            if not isinstance(result, dict):
                raise GatewayError('invalid_response', 'Invalid gateway response.')
            return result
        except GatewayError:
            raise
        except Exception:
            raise GatewayError('connection_failure', 'Gateway connection failed or returned an invalid response.') from None
        finally:
            connection.close()
