"""Encrypted credential store.

Node config never holds secrets. It holds a credential ID, and the secret
lives in ``credentials.json`` next to ``workflow.json``, encrypted with
Fernet (from ``cryptography``). Only fields that a credential type marks as
secret are encrypted, so listing credentials never needs the key.

The key is resolved in this order (first match wins):

1. ``PYNODE_CREDENTIAL_KEY``: a Fernet key,
2. ``PYNODE_CREDENTIAL_KEY_FILE``: the path to a file holding one,
3. ``<workflows dir>/.credential_key``: generated on first use, but only
   while the store holds no encrypted data yet.

The store fails loudly instead of guessing. A missing or wrong key raises
``CredentialError``, and ``credentials.json`` is never rewritten in that
state, so a new key can never be mixed into an existing store.
"""

import logging
import os
from typing import Mapping, Optional

from cryptography.fernet import Fernet

from pynode.config import ENV_CREDENTIAL_KEY, ENV_CREDENTIAL_KEY_FILE

logger = logging.getLogger(__name__)

# File names inside the workflows directory.
CREDENTIALS_FILE_NAME = 'credentials.json'
KEY_FILE_NAME = '.credential_key'


class CredentialError(Exception):
    """A credential cannot be stored or resolved.

    Raised for a missing credential, a locked store (no key), a wrong key or
    an unreadable store file. Messages name the credential or file and the
    cause, and never contain a secret value or a key.
    """


def _fernet(key_text: str, source: str) -> Fernet:
    """Build a Fernet from key text. On failure, name ``source``, never the key."""
    try:
        return Fernet(key_text.strip().encode('ascii'))
    except ValueError:
        raise CredentialError(f"{source} does not hold a valid Fernet key") from None


def _read_key_file(path: str) -> str:
    try:
        with open(path, 'r', encoding='ascii') as f:
            return f.read()
    except (OSError, UnicodeDecodeError) as e:
        raise CredentialError(
            f"Cannot read credential key file {path}: {e.__class__.__name__}") from None


class CredentialKey:
    """Resolves the Fernet key for one credential store.

    Nothing is cached, so a key supplied after start-up (env var or key file)
    is picked up by the next call.
    """

    def __init__(self, default_key_file: str, environ: Optional[Mapping[str, str]] = None):
        self.default_key_file = default_key_file
        # None = read os.environ at call time (tests pass a plain dict).
        self._environ = environ

    def get(self, create: bool = False) -> Fernet:
        """Return the active key.

        Args:
            create: allow generating the default key file when no key exists.
                Only the store passes True, and only while it holds no
                encrypted data; otherwise a fresh key would orphan every
                stored secret.

        Raises:
            CredentialError: the key is missing, unreadable or malformed.
        """
        environ = os.environ if self._environ is None else self._environ

        env_key = (environ.get(ENV_CREDENTIAL_KEY) or '').strip()
        if env_key:
            return _fernet(env_key, ENV_CREDENTIAL_KEY)

        key_file = (environ.get(ENV_CREDENTIAL_KEY_FILE) or '').strip()
        if key_file:
            key_file = os.path.abspath(os.path.expanduser(key_file))
            if not os.path.isfile(key_file):
                raise CredentialError(
                    f"Credential key file not found: {key_file} (set by {ENV_CREDENTIAL_KEY_FILE})")
            return _fernet(_read_key_file(key_file), key_file)

        if os.path.isfile(self.default_key_file):
            return _fernet(_read_key_file(self.default_key_file), self.default_key_file)

        if not create:
            raise CredentialError(
                f"Credential store is locked: no key. Set {ENV_CREDENTIAL_KEY} or "
                f"{ENV_CREDENTIAL_KEY_FILE}, or restore {self.default_key_file}")
        return _fernet(self._generate_default_key_file(), self.default_key_file)

    def _generate_default_key_file(self) -> str:
        """Create the default key file, owner-only where the OS supports it.

        O_EXCL guarantees an existing key file is never overwritten, even if
        another process creates one between the caller's check and this call.
        """
        directory = os.path.dirname(self.default_key_file)
        if directory:
            os.makedirs(directory, exist_ok=True)
        key = Fernet.generate_key().decode('ascii')
        try:
            fd = os.open(self.default_key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return _read_key_file(self.default_key_file)
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(key)
        logger.warning(
            f"Generated credential key at {self.default_key_file}. Back it up together "
            f"with {CREDENTIALS_FILE_NAME}: without it the stored secrets cannot be "
            f"decrypted. Set {ENV_CREDENTIAL_KEY} or {ENV_CREDENTIAL_KEY_FILE} to keep "
            f"the key outside the data directory.")
        return key
