"""Unit tests for _cryptodome module."""
import secrets

from absl.testing import absltest

from keycase.crypto import _crypto
from keycase.crypto import _cryptodome
from keycase.crypto import _exceptions
from keycase.crypto import _key


class TestEncrypt(absltest.TestCase):
    """Unit tests for encryption and decryption operations."""

    def setUp(self):
        self.key = _key.random_key()

    def test_roundtrip(self):
        ct = _cryptodome.encrypt(b'foo', 'bar', self.key)
        got = _cryptodome.decrypt(ct, 'bar', self.key)
        assert got == b'foo'

    def test_key_length(self):
        with self.assertRaises(ValueError):
            key = _key.RawKey(secrets.token_bytes(16))
            _cryptodome.encrypt(b'foo', 'bar', key)

    def test_string_plaintext(self):
        ct = _cryptodome.encrypt('foo', b'bar', self.key)
        got = _cryptodome.decrypt(ct, 'bar', self.key)
        assert bytes.decode(got) == 'foo'

    def test_bad_decrypt_key(self):
        ct = _cryptodome.encrypt(b'foo', 'bar', self.key)

        bad_key = _key.RawKey(secrets.token_bytes(32))
        with self.assertRaises(_exceptions.AuthenticationError):
            _cryptodome.decrypt(ct, 'bar', bad_key)

    def test_bad_decrypt_associated_data(self):
        ct = _cryptodome.encrypt(b'foo', 'bar', self.key)

        with self.assertRaises(_exceptions.AuthenticationError):
            _cryptodome.decrypt(ct, 'baz', self.key)

    def test_encrypt_sanity(self):
        """Compare compatibility between cryptography.io and PyCryptodome.

        Two different implementations are used to ensure that the wire format
        of each respective output is being properly digested. With only one
        implementation, it is only confirmed that we reassemble it the same
        way we took it apart.

        This ensures that we can drop in new cryptographic modules as needed.
        """
        plaintext = secrets.token_bytes(32)
        ad = secrets.token_bytes(32)

        ct = _cryptodome.encrypt(plaintext, ad, self.key)

        got = _crypto.decrypt(ct, ad, self.key)
        assert plaintext == got


if __name__ == '__main__':
    absltest.main()
