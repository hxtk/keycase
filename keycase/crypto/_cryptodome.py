"""Implementation for encryption and decryption functions."""
from typing import Union

from Crypto.Cipher import _mode_gcm, AES

from keycase.crypto import _crypto, _exceptions
from keycase.v1alpha1 import crypto_pb2


def _get_cipher(key: bytes, nonce: bytes) -> _mode_gcm.GcmMode:
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    assert isinstance(cipher, _mode_gcm.GcmMode)
    return cipher


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

    nonce = _crypto._get_nonce()  # pylint: disable=protected-access
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
    key: bytes,
) -> bytes:
    if len(key) != 32:
        raise ValueError('256-bit key length is required.')
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
