"""Shared client transport rejects injection, redirects and automatic retries."""
import http.client
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from gateway_client import GatewayClient, GatewayError, route, LIMIT


class TransportTests(unittest.TestCase):
    def client(self):
        client = GatewayClient.__new__(GatewayClient)
        client.host, client.port, client.context = 'gateway.example.internal', 9444, object()
        return client

    def test_unknown_fields_types_paths_and_operations_never_connect(self):
        cases = [('shell', {}), ('read', {'resource': '../private', 'operation': 'health'}),
                 ('read', {'resource': 'site', 'operation': 'health?url=https://evil'}),
                 ('apply', {'plan_id': 'a' * 48, 'approved': True}),
                 ('resources', {'url': 'https://evil'}), ('plan', {'action': [], 'target': 'app'}),
                 ('plan', {'action': 'start', 'target': 'bad\nvalue'})]
        with patch('gateway_client.http.client.HTTPSConnection') as connection:
            for operation, args in cases:
                with self.subTest(operation=operation), self.assertRaises(GatewayError):
                    self.client().invoke(operation, args)
            connection.assert_not_called()
        self.assertEqual(route('apply', {'plan_id': 'a' * 48}), ('POST', '/v1/apply', {'plan_id': 'a' * 48}))

    def test_connection_failure_does_not_retry_and_redacts_exception(self):
        with patch('gateway_client.http.client.HTTPSConnection') as connection:
            connection.return_value.getresponse.side_effect = http.client.RemoteDisconnected('SECRET')
            with self.assertRaises(GatewayError) as caught:
                self.client().invoke('apply', {'plan_id': 'a' * 48})
            self.assertNotIn('SECRET', str(caught.exception))
            connection.return_value.request.assert_called_once()
            connection.return_value.close.assert_called_once()

    def test_redirect_and_backend_errors_never_forward_raw_body(self):
        for status in (302, 400, 403, 404, 409, 502):
            with self.subTest(status=status), patch('gateway_client.http.client.HTTPSConnection') as connection:
                response = connection.return_value.getresponse.return_value
                response.status = status
                response.read.return_value = b'SECRET'
                with self.assertRaises(GatewayError) as caught:
                    self.client().invoke('resources')
                self.assertEqual(caught.exception.http_status, status)
                self.assertNotIn('SECRET', str(caught.exception))
                response.read.assert_not_called()
                connection.return_value.request.assert_called_once()

    def test_invalid_or_large_success_payload_is_rejected(self):
        for raw in (b'not-json', b'[]', b'{"data":NaN}', b'x' * (LIMIT + 1)):
            with self.subTest(size=len(raw)), patch('gateway_client.http.client.HTTPSConnection') as connection:
                response = connection.return_value.getresponse.return_value
                response.status, response.read.return_value = 200, raw
                with self.assertRaises(GatewayError):
                    self.client().invoke('resources')

    def test_configuration_errors_do_not_expose_contents_or_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'SECRET.json'
            path.write_text(json.dumps({'url': 'https://user:SECRET@gateway'}))
            with self.assertRaises(GatewayError) as caught:
                GatewayClient(path)
            self.assertNotIn('SECRET', str(caught.exception))
