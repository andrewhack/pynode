"""Tests for the encrypted credential store (pynode.credential_store).

Every file lives under tmp_path and the environment is passed in as a plain
dict, so these tests never read the developer's real env vars or key files.
"""

import os
import stat
import sys

import pytest
from cryptography.fernet import Fernet

from pynode.credential_store import (
    CREDENTIAL_TYPES,
    KEY_FILE_NAME,
    CredentialError,
    CredentialKey,
    CredentialStore,
    list_credential_types,
    register_credential_type,
)


def _key_file(tmp_path):
    return str(tmp_path / 'workflows' / KEY_FILE_NAME)


def _write_default_key(tmp_path, key):
    os.makedirs(tmp_path / 'workflows', exist_ok=True)
    with open(_key_file(tmp_path), 'w') as f:
        f.write(key)


class TestCredentialKey:

    def test_env_key_wins_over_default_file(self, tmp_path):
        env_key = Fernet.generate_key().decode()
        _write_default_key(tmp_path, Fernet.generate_key().decode())
        resolver = CredentialKey(_key_file(tmp_path), {'PYNODE_CREDENTIAL_KEY': env_key})
        token = Fernet(env_key).encrypt(b'x')
        assert resolver.get().decrypt(token) == b'x'

    def test_non_ascii_env_key_is_a_credential_error(self, tmp_path):
        resolver = CredentialKey(_key_file(tmp_path), {'PYNODE_CREDENTIAL_KEY': 'ключ-not-ascii'})
        with pytest.raises(CredentialError, match='PYNODE_CREDENTIAL_KEY does not hold a valid Fernet key'):
            resolver.get()

    def test_invalid_env_key_names_the_variable_not_the_value(self, tmp_path):
        resolver = CredentialKey(_key_file(tmp_path), {'PYNODE_CREDENTIAL_KEY': 'not-a-real-key-123'})
        with pytest.raises(CredentialError) as exc:
            resolver.get()
        assert 'PYNODE_CREDENTIAL_KEY' in str(exc.value)
        assert 'not-a-real-key-123' not in str(exc.value)

    def test_key_file_env(self, tmp_path):
        key = Fernet.generate_key().decode()
        path = tmp_path / 'elsewhere.key'
        path.write_text(key + '\n')
        resolver = CredentialKey(_key_file(tmp_path), {'PYNODE_CREDENTIAL_KEY_FILE': str(path)})
        token = Fernet(key).encrypt(b'x')
        assert resolver.get().decrypt(token) == b'x'

    def test_missing_key_file_env_is_an_error_even_with_create(self, tmp_path):
        missing = tmp_path / 'missing.key'
        resolver = CredentialKey(_key_file(tmp_path), {'PYNODE_CREDENTIAL_KEY_FILE': str(missing)})
        with pytest.raises(CredentialError, match='not found'):
            resolver.get(create=True)
        assert not missing.exists()
        assert not os.path.exists(_key_file(tmp_path))

    def test_no_key_without_create_is_locked(self, tmp_path):
        resolver = CredentialKey(_key_file(tmp_path), {})
        with pytest.raises(CredentialError, match='locked'):
            resolver.get()
        assert not os.path.exists(_key_file(tmp_path))

    def test_create_generates_the_default_key_once(self, tmp_path):
        resolver = CredentialKey(_key_file(tmp_path), {})
        token = resolver.get(create=True).encrypt(b'x')
        # The second call reads the same file instead of generating again.
        assert resolver.get().decrypt(token) == b'x'
        assert os.path.isfile(_key_file(tmp_path))

    @pytest.mark.skipif(sys.platform == 'win32', reason='POSIX permission bits')
    def test_generated_key_file_is_owner_only(self, tmp_path):
        CredentialKey(_key_file(tmp_path), {}).get(create=True)
        assert stat.S_IMODE(os.stat(_key_file(tmp_path)).st_mode) == 0o600

    def test_existing_default_key_file_is_never_overwritten(self, tmp_path):
        key = Fernet.generate_key().decode()
        _write_default_key(tmp_path, key)
        token = Fernet(key).encrypt(b'x')
        assert CredentialKey(_key_file(tmp_path), {}).get(create=True).decrypt(token) == b'x'
        with open(_key_file(tmp_path)) as f:
            assert f.read() == key


SECRET = 'tok-SHOULD-NEVER-LEAK-123'

_MQTT_LIKE = {
    'type': 'mqtt-test',
    'label': 'MQTT test',
    'fields': [
        {'name': 'username', 'label': 'Username', 'secret': False},
        {'name': 'password', 'label': 'Password', 'secret': True},
    ],
}


def _store(tmp_path, environ=None):
    return CredentialStore(str(tmp_path / 'workflows' / 'credentials.json'), environ=environ or {})


def _raw(store):
    with open(store.path, encoding='utf-8') as f:
        return f.read()


class TestCredentialTypes:

    def test_core_secret_type(self):
        types = {t['type']: t for t in list_credential_types()}
        assert types['secret']['fields'] == [{'name': 'value', 'label': 'Secret', 'secret': True}]

    def test_listing_returns_copies(self):
        list_credential_types()[0]['fields'].clear()
        assert CREDENTIAL_TYPES['secret']['fields']

    def test_duplicate_field_names_rejected(self):
        with pytest.raises(ValueError):
            register_credential_type('dup', 'Dup', [{'name': 'a'}, {'name': 'a'}])
        assert 'dup' not in CREDENTIAL_TYPES


class TestCredentialStore:

    def test_construction_touches_no_files(self, tmp_path):
        store = _store(tmp_path)
        assert store.list() == []
        assert not (tmp_path / 'workflows').exists()

    def test_create_encrypts_and_resolves(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('Pushover', 'secret', {'value': SECRET})
        assert cred == {'id': cred['id'], 'name': 'Pushover', 'type': 'secret',
                        'fields': {}, 'secretsSet': ['value']}
        assert SECRET not in _raw(store)
        assert store.resolve(cred['id']) == {'value': SECRET}

    def test_public_views_never_contain_the_secret(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('Pushover', 'secret', {'value': SECRET})
        assert SECRET not in repr(store.list())
        assert SECRET not in repr(store.get(cred['id']))

    def test_persists_across_instances(self, tmp_path):
        cred = _store(tmp_path).create('A', 'secret', {'value': SECRET})
        assert _store(tmp_path).resolve(cred['id']) == {'value': SECRET}

    def test_update_keeps_secret_when_blank_or_missing(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('A', 'secret', {'value': SECRET})
        store.update(cred['id'], name='B')
        store.update(cred['id'], fields={'value': ''})
        assert store.get(cred['id'])['name'] == 'B'
        assert store.resolve(cred['id']) == {'value': SECRET}
        store.update(cred['id'], fields={'value': 'new-token'})
        assert store.resolve(cred['id']) == {'value': 'new-token'}

    def test_update_and_delete_missing_id(self, tmp_path):
        store = _store(tmp_path)
        assert store.update('nope', name='x') is None
        assert store.delete('nope') is False

    def test_delete(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('A', 'secret', {'value': SECRET})
        assert store.delete(cred['id']) is True
        assert store.get(cred['id']) is None
        with pytest.raises(CredentialError, match='not found'):
            store.resolve(cred['id'])

    @pytest.mark.parametrize('name, type_name, fields', [
        ('', 'secret', {'value': 'x'}),
        ('A', 'nope', {'value': 'x'}),
        ('A', 'secret', {}),
        ('A', 'secret', {'value': ''}),
        ('A', 'secret', {'value': 'x', 'extra': 'y'}),
        ('A', 'secret', {'value': 123}),
        ('A', 'secret', ['value']),
        ('A', ['secret'], {'value': 'x'}),
    ])
    def test_create_rejects_invalid_input(self, tmp_path, name, type_name, fields):
        store = _store(tmp_path)
        with pytest.raises(ValueError):
            store.create(name, type_name, fields)
        assert not os.path.exists(store.path)

    def test_type_without_secrets_needs_no_key(self, tmp_path, monkeypatch):
        monkeypatch.setitem(CREDENTIAL_TYPES, 'plain-test', {
            'type': 'plain-test', 'label': 'Plain',
            'fields': [{'name': 'host', 'label': 'Host', 'secret': False}]})
        store = _store(tmp_path)
        cred = store.create('A', 'plain-test', {'host': 'example.org'})
        assert store.resolve(cred['id']) == {'host': 'example.org'}
        assert not os.path.exists(store.key.default_key_file)

    # Wrong key: reads and writes refused, file untouched
    def test_wrong_key_fails_loudly_and_leaves_file_untouched(self, tmp_path):
        key_a = Fernet.generate_key().decode()
        key_b = Fernet.generate_key().decode()
        cred = _store(tmp_path, {'PYNODE_CREDENTIAL_KEY': key_a}).create('A', 'secret', {'value': SECRET})
        store_b = _store(tmp_path, {'PYNODE_CREDENTIAL_KEY': key_b})
        before = _raw(store_b)
        with pytest.raises(CredentialError, match='does not match'):
            store_b.resolve(cred['id'])
        with pytest.raises(CredentialError, match='does not match'):
            store_b.create('B', 'secret', {'value': 'other'})
        with pytest.raises(CredentialError, match='does not match'):
            store_b.update(cred['id'], fields={'value': 'other'})
        assert _raw(store_b) == before

    # Lost key file: locked, no new key generated, file untouched
    def test_lost_key_file_locks_the_store_without_regenerating(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('A', 'secret', {'value': SECRET})
        os.remove(store.key.default_key_file)
        before = _raw(store)
        with pytest.raises(CredentialError, match='locked'):
            store.resolve(cred['id'])
        with pytest.raises(CredentialError, match='locked'):
            store.create('B', 'secret', {'value': 'other'})
        assert not os.path.exists(store.key.default_key_file)
        assert _raw(store) == before

    def test_key_errors_name_the_credential(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('Pushover', 'secret', {'value': SECRET})
        os.remove(store.key.default_key_file)
        with pytest.raises(CredentialError, match=r"Credential 'Pushover' \(") as exc:
            store.resolve(cred['id'])
        assert 'locked' in str(exc.value)
        assert SECRET not in str(exc.value)

    def test_deleting_the_last_secret_lets_a_lost_key_store_start_over(self, tmp_path):
        store = _store(tmp_path)
        cred = store.create('A', 'secret', {'value': SECRET})
        os.remove(store.key.default_key_file)
        assert store.delete(cred['id']) is True
        fresh = store.create('B', 'secret', {'value': 'fresh'})
        assert store.resolve(fresh['id']) == {'value': 'fresh'}

    def test_key_check_stays_while_secrets_remain(self, tmp_path):
        store = _store(tmp_path)
        first = store.create('A', 'secret', {'value': 'one'})
        store.create('B', 'secret', {'value': 'two'})
        os.remove(store.key.default_key_file)
        store.delete(first['id'])
        with pytest.raises(CredentialError, match='locked'):
            store.create('C', 'secret', {'value': 'three'})

    # Corrupt file: fails loudly, never overwritten
    def test_corrupt_file_fails_loudly_and_is_never_overwritten(self, tmp_path):
        store = _store(tmp_path)
        os.makedirs(os.path.dirname(store.path))
        with open(store.path, 'w') as f:
            f.write('{not json')
        with pytest.raises(CredentialError, match='Cannot read'):
            store.list()
        with pytest.raises(CredentialError, match='Cannot read'):
            store.create('A', 'secret', {'value': SECRET})
        assert _raw(store) == '{not json'

    # Hand-edited file with the wrong shape: fails loudly, never overwritten
    @pytest.mark.parametrize('content', [
        '[]',
        '{"credentials": {}}',
        '{"credentials": ["not-a-dict"]}',
        '{"credentials": [{"id": "a", "type": "secret", "fields": {}, "secrets": {}}]}',
        '{"credentials": [{"id": "a", "name": "A", "type": "secret", "secrets": ["x"]}]}',
        '{"credentials": [{"id": "a", "name": "A", "type": "secret", "secrets": "hunter2"}]}',
        '{"credentials": [{"id": "a", "name": "A", "type": "secret", "fields": {"user": 1}}]}',
        '{"keyCheck": 5, "credentials": []}',
    ])
    def test_hand_edited_file_with_wrong_shape_fails_loudly(self, tmp_path, content):
        store = _store(tmp_path)
        os.makedirs(os.path.dirname(store.path))
        with open(store.path, 'w') as f:
            f.write(content)
        with pytest.raises(CredentialError, match='unexpected format') as exc:
            store.list()
        assert 'hunter2' not in str(exc.value)
        with pytest.raises(CredentialError, match='unexpected format'):
            store.create('A', 'secret', {'value': SECRET})
        assert _raw(store) == content

    # Uninstalled credential type: listing still hides secrets
    def test_uninstalled_type_still_hides_secrets(self, tmp_path, monkeypatch):
        monkeypatch.setitem(CREDENTIAL_TYPES, 'mqtt-test', _MQTT_LIKE)
        store = _store(tmp_path)
        cred = store.create('Broker', 'mqtt-test', {'username': 'u', 'password': SECRET})
        monkeypatch.delitem(CREDENTIAL_TYPES, 'mqtt-test')
        listed = store.list()
        assert listed[0]['fields'] == {'username': 'u'}
        assert listed[0]['secretsSet'] == ['password']
        assert SECRET not in repr(listed)
        assert store.resolve(cred['id']) == {'username': 'u', 'password': SECRET}
