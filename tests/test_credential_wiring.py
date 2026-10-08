"""The credential store is owned per app and reaches nodes through their engine.

Uses the sandboxed api_app/manager fixtures; credentials.json and its key
live under tmp_path.
"""

import os

import pytest

from pynode.nodes.base_node import BaseNode, CredentialError
from pynode.workflow_manager import WorkflowManager


class _CredNode(BaseNode):
    """Minimal node with a credential property."""
    properties = [{'name': 'cred', 'label': 'Credential', 'type': 'credential',
                   'credentialType': 'secret'}]


class _DynamicCredNode(BaseNode):
    """Builds its properties dynamically and counts how often it is asked."""
    calls = 0

    @classmethod
    def get_properties(cls):
        cls.calls += 1
        return [{'name': 'cred', 'label': 'Credential', 'type': 'credential',
                 'credentialType': 'secret'}]


class _BrokenPropsNode(BaseNode):
    """A node whose dynamic properties fail (e.g. a device probe raising)."""

    @classmethod
    def get_properties(cls):
        raise RuntimeError('probe failed')


def _store(api_app):
    return api_app.extensions['credential_store']


def test_store_lives_next_to_workflow_json(api_app, manager):
    store = _store(api_app)
    assert os.path.dirname(store.path) == manager.workflows_dir
    assert os.path.basename(store.path) == 'credentials.json'
    assert manager.credential_store is store


def test_manager_engines_carry_the_store(api_app, api_client):
    wid = api_client.post('/api/workflows', json={'name': 'wired'}).get_json()['id']
    store = _store(api_app)
    assert api_client.manager.working_engines[wid].credential_store is store
    assert api_client.manager.deployed_engines[wid].credential_store is store


def test_get_credential_resolves_through_the_engine(api_app, manager):
    cred = _store(api_app).create('A', 'secret', {'value': 'tok'})
    wid = manager.create_new_workflow(name='wf')
    engine = manager.working_engines[wid]
    engine.register_node_type(_CredNode)
    node = engine.create_node('_CredNode', config={'cred': cred['id']})
    assert node.get_credential(node.config['cred']) == {'value': 'tok'}


def test_get_credential_errors(manager, engine):
    wid = manager.create_new_workflow(name='wf')
    wired = manager.working_engines[wid].create_node('InjectNode', config={})
    with pytest.raises(CredentialError, match='no credential selected'):
        wired.get_credential('')
    with pytest.raises(CredentialError, match='not found'):
        wired.get_credential('does-not-exist')
    # An ad-hoc engine (not built by a manager) has no store.
    loose = engine.create_node('_SourceNode')
    with pytest.raises(CredentialError, match='no credential store'):
        loose.get_credential('anything')


def test_credential_usage_counts_each_node_once(api_app, manager):
    cred = _store(api_app).create('A', 'secret', {'value': 'tok'})
    wid_a = manager.create_new_workflow(name='a')
    wid_b = manager.create_new_workflow(name='b')
    for engine in (manager.working_engines[wid_a], manager.deployed_engines[wid_a],
                   manager.working_engines[wid_b]):
        engine.register_node_type(_CredNode)
    # The same node in the working and deployed engines counts once...
    manager.working_engines[wid_a].create_node('_CredNode', 'n1', config={'cred': cred['id']})
    manager.deployed_engines[wid_a].create_node('_CredNode', 'n1', config={'cred': cred['id']})
    assert manager.credential_usage([cred['id']]) == {cred['id']: 1}
    # ...and a node in another workflow adds one.
    manager.working_engines[wid_b].create_node('_CredNode', 'n2', config={'cred': cred['id']})
    assert manager.credential_usage([cred['id']]) == {cred['id']: 2}


def test_credential_usage_never_asks_nodes_for_their_properties(api_app, manager):
    # Some nodes build their properties dynamically (device probes); usage
    # must not depend on that, or on it succeeding.
    _DynamicCredNode.calls = 0
    cred = _store(api_app).create('A', 'secret', {'value': 'tok'})
    wid = manager.create_new_workflow(name='dynamic')
    engine = manager.working_engines[wid]
    engine.register_node_type(_DynamicCredNode)
    engine.create_node('_DynamicCredNode', 'd1', config={'cred': cred['id']})
    engine.create_node('_DynamicCredNode', 'd2', config={'cred': cred['id']})
    assert manager.credential_usage([cred['id']]) == {cred['id']: 2}
    assert _DynamicCredNode.calls == 0


def test_credential_usage_counts_a_node_whose_properties_cannot_be_read(api_app, manager):
    # Fail closed: a reference still counts, so the delete guard holds.
    cred = _store(api_app).create('A', 'secret', {'value': 'tok'})
    wid = manager.create_new_workflow(name='broken')
    engine = manager.working_engines[wid]
    engine.register_node_type(_BrokenPropsNode)
    engine.create_node('_BrokenPropsNode', 'b1', config={'cred': cred['id']})
    assert manager.credential_usage([cred['id']]) == {cred['id']: 1}


def test_credential_usage_finds_references_in_nested_values(api_app, manager):
    cred = _store(api_app).create('A', 'secret', {'value': 'tok'})
    wid = manager.create_new_workflow(name='nested')
    engine = manager.working_engines[wid]
    engine.register_node_type(_CredNode)
    engine.create_node('_CredNode', 'n1', config={'auth': {'tokens': ['other', cred['id']]}})
    assert manager.credential_usage([cred['id']]) == {cred['id']: 1}


def test_credential_usage_counts_placeholder_nodes_of_missing_types(api_app, manager):
    # A node whose type isn't installed keeps its config and still counts.
    cred = _store(api_app).create('A', 'secret', {'value': 'tok'})
    wid = manager.create_new_workflow(name='missing type')
    manager.working_engines[wid].import_workflow({
        'nodes': [{'id': 'u1', 'type': 'NotInstalledNode', 'config': {'cred': cred['id']}}],
        'connections': [],
    })
    assert manager.credential_usage([cred['id']]) == {cred['id']: 1}


def test_credential_usage_reports_only_the_requested_ids(api_app, manager):
    store = _store(api_app)
    wanted = store.create('A', 'secret', {'value': 'one'})
    other = store.create('B', 'secret', {'value': 'two'})
    wid = manager.create_new_workflow(name='two creds')
    engine = manager.working_engines[wid]
    engine.register_node_type(_CredNode)
    engine.create_node('_CredNode', 'n1', config={'cred': wanted['id'], 'spare': other['id']})
    assert manager.credential_usage([wanted['id']]) == {wanted['id']: 1}


def test_credential_usage_tolerates_odd_config_values(manager):
    wid = manager.create_new_workflow(name='odd values')
    engine = manager.working_engines[wid]
    engine.register_node_type(_CredNode)
    engine.create_node('_CredNode', 'n1', config={'cred': ['not', 'an', 'id']})
    engine.create_node('_CredNode', 'n2', config={'cred': '', 'n': 3, 'x': None, 'd': {'k': 1.5}})
    assert manager.credential_usage(['f' * 32]) == {}


def test_manager_without_store(tmp_path):
    mgr = WorkflowManager(workflows_dir=str(tmp_path / 'workflows'))
    try:
        wid = mgr.create_new_workflow(name='wf')
        assert mgr.working_engines[wid].credential_store is None
        assert mgr.credential_usage([]) == {}
    finally:
        mgr.shutdown()
