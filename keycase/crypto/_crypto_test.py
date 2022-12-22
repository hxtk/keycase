"""Unit tests for _crypto module."""
import secrets

import Crypto.Cipher
from Crypto.Cipher import _mode_gcm
from absl.testing import absltest

from keycase.crypto import _crypto
from keycase.crypto import _cryptodome

from keycase.crypto import _exceptions


def _get_cipher(key: bytes, nonce: bytes) -> _mode_gcm.GcmMode:
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_GCM, nonce)
    assert isinstance(cipher, _mode_gcm.GcmMode)
    return cipher


class TestEncrypt(absltest.TestCase):
    """Unit tests for encryption and decryption operations."""

    def test_roundtrip(self):
        key = secrets.token_bytes(32)
        ct = _crypto.encrypt(b'foo', 'bar', key)
        got = _crypto.decrypt(ct, 'bar', key)
        assert got == b'foo'

    def test_key_length(self):
        key = secrets.token_bytes(16)
        with self.assertRaises(ValueError):
            _crypto.encrypt(b'foo', 'bar', key)

    def test_string_plaintext(self):
        key = secrets.token_bytes(32)
        ct = _crypto.encrypt('foo', b'bar', key)
        got = _crypto.decrypt(ct, 'bar', key)
        assert bytes.decode(got) == 'foo'

    def test_bad_decrypt_key(self):
        key = secrets.token_bytes(32)
        ct = _crypto.encrypt(b'foo', 'bar', key)

        bad_key = secrets.token_bytes(32)
        with self.assertRaises(_exceptions.AuthenticationError):
            _crypto.decrypt(ct, 'bar', bad_key)

    def test_bad_decrypt_associated_data(self):
        key = secrets.token_bytes(32)
        ct = _crypto.encrypt(b'foo', 'bar', key)

        bad_key = secrets.token_bytes(32)
        with self.assertRaises(_exceptions.AuthenticationError):
            _crypto.decrypt(ct, 'baz', bad_key)

    def test_encrypt_sanity(self):
        """Compare compatibility between cryptography.io and PyCryptodome.

        Two different implementations are used to ensure that the wire format
        of each respective output is being properly digested. With only one
        implementation, it is only confirmed that we reassemble it the same
        way we took it apart.

        This ensures that we can drop in new cryptographic modules as needed.
        """
        plaintext = secrets.token_bytes(32)
        key = secrets.token_bytes(32)
        ad = secrets.token_bytes(32)

        ct = _crypto.encrypt(plaintext, ad, key)

        got = _cryptodome.decrypt(ct, ad, key)
        assert plaintext == got


if __name__ == '__main__':
    absltest.main()
