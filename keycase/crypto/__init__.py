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

from keycase.crypto import _crypto, _exceptions, _key

# Explicitly re-export desired names.
encrypt = _crypto.encrypt
decrypt = _crypto.decrypt

random_key = _key.random_key
password_key = _key.password_key

AuthenticationError = _exceptions.AuthenticationError
Key = _key.Key

__all__ = [
    'encrypt',
    'decrypt',
    'password_key',
    'random_key',
    'AuthenticationError',
    'Key',
]
