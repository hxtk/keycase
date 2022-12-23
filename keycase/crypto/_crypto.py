"""Implementation for encryption and decryption functions."""
from typing import Union

import datetime
import secrets
import struct

from cryptography.hazmat.primitives.ciphers import aead as _aead
from cryptography import exceptions

from keycase.v1alpha1 import crypto_pb2
from keycase.crypto import _exceptions, _key


def _get_nonce() -> bytes:
    """Retrieve a 256-bit nonce suitable for AES256-GCM.

    The exact makeup of the nonce shall be considered an implementation
    detail, but it shall consist of at least 96 bits of randomness and
    may make use of non-random components to guard against collisions.

        >>> len(_get_nonce())
        32

    Returns:
        bytes-like object whose length shall be exactly 32.
    """
    randomness = secrets.token_bytes(24)
    timestamp = struct.pack('<d', datetime.datetime.utcnow().timestamp())
    res = randomness + timestamp
    assert len(res) == 32
    return res


def encrypt(
    plaintext: Union[str, bytes],
    associated_data: Union[str, bytes],
    key: _key.Key,
) -> bytes:
    """Encrypt the given plaintext with key and associated_data.

    Uses AES-256-GCM encryption with a securely-chosen nonce consisting
    of both random and non-random components. This function claims to choose
    a safe set of parameters for AES-256-GCM, however, the security guarantees
    provided by this module cannot exceed the theoretical limitations of
    AES-256-GCM regarding properties such as the maximum number of encrypted
    bytes, messages, etc.

    Args:
        plaintext: a `bytes` or UTF-8-encodable `str` object to be encrypted.
        associated_data: some non-secret data that will be required for
            decryption.
        key: A cryptographic key object.

    Returns:
        a bytes object which may be passed into `decrypt` as a ciphertext.
        This bytes object is guaranteed to securely guard the value of
        `plaintext`, but permit an attacker to trivially recover the nonce
        used.

        For details on the wire format, see `keycase.v1alpha1.crypto_pb2`.
    """
    kb = key.key_bytes()

    if isinstance(plaintext, str):
        plaintext = plaintext.encode(encoding='utf-8')
    if isinstance(associated_data, str):
        associated_data = associated_data.encode(encoding='utf-8')

    cipher = _aead.AESGCM(kb)
    nonce = _get_nonce()

    ct = cipher.encrypt(nonce, plaintext, associated_data)
    return crypto_pb2.CipherText(
        nonce=nonce,
        ciphertext=ct[:-16],
        authn_tag=ct[-16:],
    ).SerializeToString()


def decrypt(
    ciphertext: bytes,
    associated_data: Union[str, bytes],
    key: _key.Key,
) -> bytes:
    """Decrypt a cyphertext with associated data.

    Args:
        ciphertext: a bytestream in the wire format produced by `encrypt`.
            See `keycase.v1alpha1.crypto.CipherText` for details.
        associated_data: a bytes or UTF-8-encodable str object encoding the
            same associated data with which the plaintext was originally
            encrypted.
        key: a cryptographic key object whose `key_bytes` member is identical
            to the one originally passed to `encrypt`.

    Returns:
        a bytes object equivalent to the original plaintext passed into
        `encrypt`.

    Raises:
        keycase.crypto.AuthenticationError: if the key or associated data
            do not match those passed into `encrypt`.
    """
    kb = key.key_bytes()

    if isinstance(associated_data, str):
        associated_data = associated_data.encode(encoding='utf-8')

    ct = crypto_pb2.CipherText()
    ct.ParseFromString(ciphertext)

    cipher = _aead.AESGCM(kb)

    try:
        return cipher.decrypt(
            ct.nonce,
            ct.ciphertext + ct.authn_tag,
            associated_data,
        )
    except exceptions.InvalidTag as e:
        raise _exceptions.AuthenticationError(
            'Decrypted data could not be authenticated.') from e
