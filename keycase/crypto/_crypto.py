from typing import Union

import datetime
import secrets
import struct

from cryptography.hazmat.primitives.ciphers import aead as _aead
from cryptography import exceptions

from keycase.v1alpha1 import crypto_pb2
from keycase.crypto import _exceptions


def _get_nonce() -> bytes:
    randomness = secrets.token_bytes(24)
    timestamp = struct.pack('<d', datetime.datetime.utcnow().timestamp())
    res = randomness + timestamp
    assert (len(res) == 32)
    return res


def encrypt(
    plaintext: Union[str, bytes],
    associated_data: Union[str, bytes],
    key: bytes,
) -> bytes:
    if len(key) != 32:
        raise ValueError('256-bit key length is required.')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode(encoding='utf-8')
    if isinstance(associated_data, str):
        associated_data = associated_data.encode(encoding='utf-8')

    cipher = _aead.AESGCM(key)
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
    key: bytes,
) -> bytes:
    if len(key) != 32:
        raise ValueError('256-bit key length is required.')
    if isinstance(associated_data, str):
        associated_data = associated_data.encode(encoding='utf-8')

    ct = crypto_pb2.CipherText()
    ct.ParseFromString(ciphertext)

    cipher = _aead.AESGCM(key)

    try:
        return cipher.decrypt(
            ct.nonce,
            ct.ciphertext + ct.authn_tag,
            associated_data,
        )
    except exceptions.InvalidTag as e:
        raise _exceptions.AuthenticationError(
            'Decryption could not be authenticated.',
            e,
        )
