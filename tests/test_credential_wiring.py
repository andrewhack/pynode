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
    assert manager.credential_usage() == {cred['id']: 1}
    # ...and a node in another workflow adds one.
    manager.working_engines[wid_b].create_node('_CredNode', 'n2', config={'cred': cred['id']})
    assert manager.credential_usage() == {cred['id']: 2}


def test_manager_without_store(tmp_path):
    mgr = WorkflowManager(workflows_dir=str(tmp_path / 'workflows'))
    try:
        wid = mgr.create_new_workflow(name='wf')
        assert mgr.working_engines[wid].credential_store is None
        assert mgr.credential_usage() == {}
    finally:
        mgr.shutdown()
