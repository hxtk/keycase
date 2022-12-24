"""Implementation for encryption and decryption functions.

This implementation is essentially unused (it is not publicly exported
by the parent module) and exists as a parallel implementation for the express
purpose of sanity-checking the main implementation in `keycase.crypto._crypto`:
the two implementations are intended to be functionally interchangeable.
"""
from typing import Union

from Crypto.Cipher import AES
from Crypto.Cipher import _mode_gcm  # pylint: disable=protected-access

from keycase.crypto import _exceptions
from keycase.crypto import _key
from keycase.crypto import _nonce
from keycase.v1alpha1 import crypto_pb2


def _get_cipher(key: _key.Key, nonce: bytes) -> _mode_gcm.GcmMode:
    cipher = AES.new(key.key_bytes(), AES.MODE_GCM, nonce)
    assert isinstance(cipher, _mode_gcm.GcmMode)
    return cipher


def encrypt(
    plaintext: Union[str, bytes],
    associated_data: Union[str, bytes],
    key: _key.Key,
) -> bytes:
    if isinstance(plaintext, str):
        plaintext = plaintext.encode(encoding='utf-8')
    if isinstance(associated_data, str):
        associated_data = associated_data.encode(encoding='utf-8')

    nonce = _nonce.get_nonce()
    cipher = _get_cipher(key, nonce)

    cipher.update(associated_data)

    ct, tag = cipher.encrypt_and_digest(plaintext)
    return crypto_pb2.CipherText(
        nonce=nonce,
        ciphertext=ct,
        authn_tag=tag,
    ).SerializeToString()


def decrypt(
    ciphertext: bytes,
    associated_data: Union[str, bytes],
    key: _key.Key,
) -> bytes:
    if isinstance(associated_data, str):
        associated_data = associated_data.encode(encoding='utf-8')

    ct = crypto_pb2.CipherText()
    ct.ParseFromString(ciphertext)

    cipher = _get_cipher(key, ct.nonce)
    cipher.update(associated_data)

    try:
        return cipher.decrypt_and_verify(
            ct.ciphertext,
            ct.authn_tag,
        )
    except ValueError as e:
        raise _exceptions.AuthenticationError(
            'Decrypted data could not be authenticated.') from e
