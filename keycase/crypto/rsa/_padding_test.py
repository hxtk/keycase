"""Unit tests for padding module"""
import secrets

from absl.testing import absltest

from cryptography.hazmat.primitives import hashes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Math import Numbers

from keycase.crypto.rsa import _padding

_KEY_SIZE = 2048


class TestStripPadding(absltest.TestCase):
    """Unit tests for the `strip_padding` function."""

    def test_strip_padding(self):
        message = secrets.token_bytes(32)
        key: RSA.RsaKey = RSA.generate(_KEY_SIZE, secrets.token_bytes)
        ct = PKCS1_OAEP.new(
            key.public_key(),
            hashAlgo=SHA256,
        ).encrypt(message)

        # pylint: disable=protected-access
        padded_message_int: int = key._decrypt(
            Numbers.Integer.from_bytes(ct, byteorder='big'),)
        encoded = padded_message_int.to_bytes(_KEY_SIZE // 8, byteorder='big')
        assert len(encoded) == _KEY_SIZE // 8
        got = _padding.strip_padding(
            encoded_message=encoded,
            key_size=_KEY_SIZE // 8,
            mgf=_padding.MGF1(hashes.SHA256()),
            hash_algorithm=hashes.SHA256(),
        )
        self.assertEqual(got, message)

    def test_strip_padding_aead(self):
        message = secrets.token_bytes(32)
        associated_data = secrets.token_bytes(32)
        key: RSA.RsaKey = RSA.generate(_KEY_SIZE, secrets.token_bytes)
        ct = PKCS1_OAEP.new(
            key.public_key(),
            hashAlgo=SHA256,
            label=associated_data,
        ).encrypt(message)

        # pylint: disable=protected-access
        padded_message_int: int = key._decrypt(
            Numbers.Integer.from_bytes(ct, byteorder='big'),)
        encoded = padded_message_int.to_bytes(_KEY_SIZE // 8, byteorder='big')
        assert len(encoded) == _KEY_SIZE // 8
        got = _padding.strip_padding(
            encoded_message=encoded,
            key_size=_KEY_SIZE // 8,
            mgf=_padding.MGF1(hashes.SHA256()),
            hash_algorithm=hashes.SHA256(),
            associated_data=associated_data,
        )
        self.assertEqual(got, message)


if __name__ == '__main__':
    absltest.main()
