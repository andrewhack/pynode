"""Tests for the encrypted credential store (pynode.credential_store).

Every file lives under tmp_path and the environment is passed in as a plain
dict, so these tests never read the developer's real env vars or key files.
"""

import os
import stat
import sys

import pytest
from cryptography.fernet import Fernet

from pynode.credential_store import KEY_FILE_NAME, CredentialError, CredentialKey


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
