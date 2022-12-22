import secrets

from absl.testing import absltest

from keycase.crypto import _crypto
from keycase.crypto import _exceptions


class TestEncrypt(absltest.TestCase):

    def test_roundtrip(self):
        key = secrets.token_bytes(32)
        ct = _crypto.encrypt(b'foo', 'bar', key)
        got = _crypto.decrypt(ct, 'bar', key)
        assert got == b'foo'

    def test_key_length(self):
        key = secrets.token_bytes(16)
        with self.assertRaises(ValueError):
            _crypto.encrypt(b'foo', 'bar', key)

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


if __name__ == '__main__':
    absltest.main()
