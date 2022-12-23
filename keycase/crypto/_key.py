"""Module for the handling of cryptographic keying material."""
from typing import Protocol, Union

import hashlib
import secrets


class Key(Protocol):
    """Interface that must be implemented by key material.

    This interface primarily exists so that the cryptography module
    does not have to accept raw bytes, which is easy to misuse.
    """

    def key_bytes(self) -> bytes:
        raise NotImplementedError


class RawKey(object):
    """RawKey defines a key constructed from raw bytes.

    Generally, this module attempts to provide better alternatives
    to using this class directly, e.g., `random_key()` provides a new
    random key generated with the system's secure random number generator
    and `password_key(password: str, salt: bytes)` generating a key
    from a password.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError('Keys must be 256 bits in length.')

        self.key = key

    def key_bytes(self) -> bytes:
        return self.key


def random_key() -> 'Key':
    """Get a secure random key suitable for cryptographic usage."""
    return RawKey(secrets.token_bytes(32))


def password_key(
    secret: Union[str, bytes],
    salt: bytes,
    strict: bool = True,
) -> 'Key':
    """Generate a secure password-derived key.

    Args:
        secret: a user-provided secret such as a password or passphrase.
        salt: a byte source, preferably random, to guard against rainbow
            table attacks being used to guess the secret.
        strict: whether it shall be considered an error if salt is smaller
            than the recommended 128 bits (default: True).

    Returns:
        a `Key` object representing the password-derived key.

    Raises:
        ValueError if salt is not at least 16 bytes and `strict` is True.
    """
    if strict and len(salt) < 16:
        raise ValueError('Salt must be at least 16 bytes.')
    if isinstance(secret, str):
        secret = secret.encode('utf-8')
    return RawKey(
        hashlib.scrypt(
            password=secret,
            salt=salt,
            n=2**14,
            r=14,
            p=1,
            dklen=32,
        ))
