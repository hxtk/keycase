"""Safe, opinionated defaults for AEAD encryption.

This module provides a means to encrypt and decrypt arbitrary
UTF-8-encodable data using AES256-GCM.

Typical usage example:

    >>> from keycase import crypto
    >>> key = crypto.get_key()
    >>> ciphertext = crypto.encrypt("foo", "bar", key)
    >>> crypto.decrypt(ciphertext, "baz", key)
    Traceback (most recent call last):
    ...
    keycase.crypto._exceptions.AuthenticationError: Decrypted ...
    >>> crypto.decrypt(ciphertext, "bar", key)
    b'foo'
"""

import secrets as _secrets
from keycase.crypto import _crypto, _exceptions


def get_key() -> bytes:
    """Get a random key suitable for use with encrypt and decrypt."""
    return _secrets.token_bytes(32)


encrypt = _crypto.encrypt
decrypt = _crypto.decrypt
AuthenticationError = _exceptions.AuthenticationError
