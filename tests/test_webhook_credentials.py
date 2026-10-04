"""WebhookNode takes its auth secret from a stored credential.

The composed tests run the real path end to end: a credential created
through the API, a node deployed through the API, a request sent by the
deployed node to a local HTTP server that records the headers it received.
"""

import base64
import http.server
import threading

import pytest

from pynode.credential_store import CREDENTIAL_TYPES, CredentialStore
from pynode.nodes.WebhookNode.webhook_node import WebhookNode
from pynode.workflow_engine import WorkflowEngine

SECRET = 'tok-SHOULD-NEVER-LEAK-123'


@pytest.fixture
def capture_server():
    """A local HTTP endpoint; yields (url, list of received auth headers)."""
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length', 0)))
            received.append({'authorization': self.headers.get('Authorization'),
                             'x-api-key': self.headers.get('X-API-Key')})
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{server.server_address[1]}/hook', received
    server.shutdown()
    server.server_close()


def _create_credential(client, value=SECRET):
    resp = client.post('/api/credentials',
                       json={'name': 'hook auth', 'type': 'secret', 'fields': {'value': value}})
    assert resp.status_code == 200
    return resp.get_json()['credential']['id']


def _deploy_webhook(client, url, config):
    """Create a WebhookNode in a new workflow and deploy it; returns the deployed node."""
    wid = client.post('/api/workflows', json={'name': 'webhook creds'}).get_json()['id']
    node_config = {'url': url, 'method': 'POST', 'async': False, 'retries': 0, 'timeout': 5}
    node_config.update(config)
    resp = client.post(f'/api/nodes?workflow={wid}',
                       json={'type': 'WebhookNode', 'name': 'hook', 'config': node_config})
    assert resp.status_code == 201
    node_id = resp.get_json()['id']
    assert client.post('/api/workflow/save').status_code == 200
    return wid, client.manager.deployed_engines[wid].get_node(node_id)


def test_bearer_header_comes_from_the_credential(api_client, capture_server):
    url, received = capture_server
    cred_id = _create_credential(api_client)
    _, node = _deploy_webhook(api_client, url, {
        'authType': 'bearer', 'credential': cred_id, 'authCredentials': 'legacy-token'})
    node.on_input({'payload': {'n': 1}})
    assert received == [{'authorization': f'Bearer {SECRET}', 'x-api-key': None}]


def test_basic_and_apikey_from_the_credential(api_client, capture_server):
    url, received = capture_server
    cred_id = _create_credential(api_client, value='user:pw')
    _, basic = _deploy_webhook(api_client, url, {'authType': 'basic', 'credential': cred_id})
    basic.on_input({'payload': 1})
    _, apikey = _deploy_webhook(api_client, url, {
        'authType': 'apikey', 'credential': cred_id, 'apiKeyHeader': 'X-API-Key'})
    apikey.on_input({'payload': 1})
    assert received[0]['authorization'] == 'Basic ' + base64.b64encode(b'user:pw').decode()
    assert received[1]['x-api-key'] == 'user:pw'


def test_legacy_auth_credentials_still_work(api_client, capture_server):
    url, received = capture_server
    _, node = _deploy_webhook(api_client, url, {
        'authType': 'bearer', 'authCredentials': 'legacy-token'})
    node.on_input({'payload': 1})
    assert received[0]['authorization'] == 'Bearer legacy-token'


# Review Focus 4
def test_missing_credential_sends_nothing(api_client, capture_server):
    url, received = capture_server
    _, node = _deploy_webhook(api_client, url, {
        'authType': 'bearer', 'credential': 'gone', 'authCredentials': 'legacy-token'})
    node.on_input({'payload': 1})
    assert received == []
    assert node._error_count == 1


# Review Focus 4
def test_missing_credential_is_reported_at_start(tmp_path):
    engine = WorkflowEngine()
    engine.register_node_type(WebhookNode)
    engine.credential_store = CredentialStore(str(tmp_path / 'credentials.json'), environ={})
    node = engine.create_node('WebhookNode', config={
        'url': 'http://127.0.0.1:9/x', 'authType': 'bearer', 'credential': 'gone'})
    errors = []
    node.report_error = errors.append
    node.on_start()
    node.on_stop()
    assert len(errors) == 1
    assert 'not found' in errors[0]


def test_credential_of_another_type_fails_loudly(api_client, capture_server, monkeypatch):
    monkeypatch.setitem(CREDENTIAL_TYPES, 'pair-test', {
        'type': 'pair-test', 'label': 'Pair',
        'fields': [{'name': 'user', 'label': 'User', 'secret': False},
                   {'name': 'pw', 'label': 'Password', 'secret': True}]})
    store = api_client.application.extensions['credential_store']
    cred = store.create('pair', 'pair-test', {'user': 'u', 'pw': SECRET})
    url, received = capture_server
    _, node = _deploy_webhook(api_client, url, {'authType': 'bearer', 'credential': cred['id']})
    errors = []
    node.report_error = errors.append
    node.on_input({'payload': 1})
    assert received == []
    assert node._error_count == 1
    assert any("has no 'value' field" in e for e in errors)
    assert not any(SECRET in e for e in errors)


def test_secret_stays_out_of_workflow_json_and_api(api_client, capture_server):
    url, _ = capture_server
    cred_id = _create_credential(api_client)
    wid, _ = _deploy_webhook(api_client, url, {'authType': 'bearer', 'credential': cred_id})
    exported = api_client.get(f'/api/workflow?workflow={wid}').get_data(as_text=True)
    assert cred_id in exported
    assert SECRET not in exported
    with open(api_client.manager.workflow_file, encoding='utf-8') as f:
        on_disk = f.read()
    assert cred_id in on_disk
    assert SECRET not in on_disk
    assert SECRET not in api_client.get('/api/credentials').get_data(as_text=True)
