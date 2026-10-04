"""Tests for the credential store API (pynode.api.credentials).

Runs on the sandboxed create_app fixture: credentials.json and the generated
key live in tmp_path. The leak checks inspect raw response bodies, because
"never returns a secret" must hold for every byte, not only parsed fields.
"""

import os

import pytest

from pynode.nodes.base_node import BaseNode

SECRET = 'tok-SHOULD-NEVER-LEAK-123'


class _CredNode(BaseNode):
    """Minimal node with a credential property, for usage counting."""
    properties = [{'name': 'cred', 'label': 'Credential', 'type': 'credential',
                   'credentialType': 'secret'}]


def _create(client, name='Pushover', value=SECRET):
    return client.post('/api/credentials',
                       json={'name': name, 'type': 'secret', 'fields': {'value': value}})


def _create_id(client):
    resp = _create(client)
    assert resp.status_code == 200
    return resp.get_json()['credential']['id']


def _store(client):
    return client.application.extensions['credential_store']


def _use_in_workflow(client, cred_id):
    """Reference the credential from a node in a new workflow's working engine."""
    wid = client.manager.create_new_workflow(name='uses cred')
    engine = client.manager.working_engines[wid]
    engine.register_node_type(_CredNode)
    engine.create_node('_CredNode', config={'cred': cred_id})


class TestCredentialTypes:

    def test_lists_the_core_secret_type(self, api_client):
        resp = api_client.get('/api/credential-types')
        assert resp.status_code == 200
        types = {t['type']: t for t in resp.get_json()['types']}
        assert types['secret']['fields'] == [{'name': 'value', 'label': 'Secret', 'secret': True}]


class TestCredentialCrud:

    def test_create_returns_the_public_view_only(self, api_client):
        resp = _create(api_client)
        assert resp.status_code == 200
        assert SECRET not in resp.get_data(as_text=True)
        cred = resp.get_json()['credential']
        assert cred['name'] == 'Pushover'
        assert cred['type'] == 'secret'
        assert cred['fields'] == {}
        assert cred['secretsSet'] == ['value']
        assert cred['inUse'] == 0

    def test_list_never_contains_the_secret(self, api_client):
        cred_id = _create_id(api_client)
        resp = api_client.get('/api/credentials')
        assert resp.status_code == 200
        assert SECRET not in resp.get_data(as_text=True)
        assert [c['id'] for c in resp.get_json()['credentials']] == [cred_id]

    def test_secret_is_encrypted_on_disk(self, api_client):
        _create_id(api_client)
        with open(_store(api_client).path, encoding='utf-8') as f:
            assert SECRET not in f.read()

    def test_put_without_secret_keeps_it(self, api_client):
        cred_id = _create_id(api_client)
        resp = api_client.put(f'/api/credentials/{cred_id}', json={'name': 'Renamed'})
        assert resp.status_code == 200
        assert resp.get_json()['credential']['name'] == 'Renamed'
        resp = api_client.put(f'/api/credentials/{cred_id}', json={'fields': {'value': ''}})
        assert resp.status_code == 200
        assert _store(api_client).resolve(cred_id) == {'value': SECRET}

    def test_put_replaces_the_secret(self, api_client):
        cred_id = _create_id(api_client)
        resp = api_client.put(f'/api/credentials/{cred_id}', json={'fields': {'value': 'new-token'}})
        assert resp.status_code == 200
        assert 'new-token' not in resp.get_data(as_text=True)
        assert _store(api_client).resolve(cred_id) == {'value': 'new-token'}

    def test_unknown_id_is_404(self, api_client):
        assert api_client.put('/api/credentials/nope', json={'name': 'x'}).status_code == 404
        assert api_client.delete('/api/credentials/nope').status_code == 404

    @pytest.mark.parametrize('body', [
        {'type': 'secret', 'fields': {'value': 'x'}},
        {'name': 'A', 'type': 'nope', 'fields': {'value': 'x'}},
        {'name': 'A', 'type': 'secret', 'fields': {}},
        {'name': 'A', 'type': 'secret', 'fields': {'value': 'x', 'other': 'y'}},
        {'name': 'A', 'type': 'secret', 'fields': ['x']},
        {'name': 'A', 'type': ['secret'], 'fields': {'value': 'x'}},
        {'name': 'A', 'type': {'a': 1}, 'fields': {'value': 'x'}},
    ])
    def test_create_validation_is_400(self, api_client, body):
        resp = api_client.post('/api/credentials', json=body)
        assert resp.status_code == 400
        assert resp.get_json()['success'] is False

    def test_invalid_json_body_is_400(self, api_client):
        resp = api_client.post('/api/credentials', data='{bad', content_type='application/json')
        assert resp.status_code == 400

    def test_delete_unused(self, api_client):
        cred_id = _create_id(api_client)
        resp = api_client.delete(f'/api/credentials/{cred_id}')
        assert resp.status_code == 200
        assert api_client.get('/api/credentials').get_json()['credentials'] == []


class TestCredentialUsage:

    def test_in_use_count_and_delete_conflict(self, api_client):
        cred_id = _create_id(api_client)
        _use_in_workflow(api_client, cred_id)
        listed = api_client.get('/api/credentials').get_json()['credentials']
        assert listed[0]['inUse'] == 1
        resp = api_client.delete(f'/api/credentials/{cred_id}')
        assert resp.status_code == 409
        assert _store(api_client).get(cred_id) is not None


class TestCredentialApiFailures:

    def test_requires_the_api_key_when_configured(self, api_app, api_client):
        api_app.config['PYNODE_API_KEY'] = 'k'
        assert api_client.get('/api/credentials').status_code == 401
        assert api_client.get('/api/credentials', headers={'X-API-Key': 'k'}).status_code == 200

    # Review Focus 1, through the API
    def test_locked_store_is_500_and_file_untouched(self, api_client):
        cred_id = _create_id(api_client)
        store = _store(api_client)
        os.remove(store.key.default_key_file)
        with open(store.path, encoding='utf-8') as f:
            before = f.read()
        resp = api_client.put(f'/api/credentials/{cred_id}', json={'fields': {'value': 'other'}})
        assert resp.status_code == 500
        assert 'locked' in resp.get_json()['error']
        with open(store.path, encoding='utf-8') as f:
            assert f.read() == before

    # Review Focus 3, through the app
    def test_corrupt_store_does_not_stop_the_app(self, tmp_path, monkeypatch):
        from pynode.server import create_app

        monkeypatch.delenv('PYNODE_CREDENTIAL_KEY', raising=False)
        monkeypatch.delenv('PYNODE_CREDENTIAL_KEY_FILE', raising=False)
        workflows = tmp_path / 'workflows'
        workflows.mkdir()
        (workflows / 'credentials.json').write_text('{not json')
        app = create_app({
            'WORKFLOWS_DIR': str(workflows),
            'WORKFLOW_FILE': str(workflows / 'workflow.json'),
            'UPLOAD_BASE_DIR': str(tmp_path),
            'TESTING': True,
        })
        try:
            with app.test_client() as client:
                resp = client.get('/api/credentials')
                assert resp.status_code == 500
                assert 'credentials.json' in resp.get_json()['error']
                assert client.get('/api/workflows').status_code == 200
        finally:
            app.extensions['workflow_manager'].shutdown()
        assert (workflows / 'credentials.json').read_text() == '{not json'
