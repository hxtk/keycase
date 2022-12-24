"""Unit tests for Vault module."""
import secrets

from absl.testing import absltest

from keycase import crypto
from keycase.v1alpha1 import keys_pb2
from keycase.vault import _vault


class TestEncryptedKey(absltest.TestCase):
    """Unit tests for the _vault.EncryptedKey class."""

    def test_encrypted_key_key_bytes(self):
        key = crypto.random_key()
        want = crypto.random_key()
        aad = secrets.token_bytes(32)
        ct = crypto.encrypt(want.key_bytes(), aad, key)
        got = _vault.EncryptedKey(ct, aad, key)
        self.assertEqual(want.key_bytes(), got.key_bytes())


class TestUserKey(absltest.TestCase):
    """Unit tests for the _vault.UserKey class."""

    def test_machine_key_key_bytes(self):
        uk = _vault.UserKey(
            keys_pb2.UserKey(
                name='foo',
                machine_salt=keys_pb2.MachineKey(tpm_pcr=0),
            ),
            'password',
        )
        self.assertLen(uk.key_bytes(), 32)

    def test_salt_key_key_bytes(self):
        uk = _vault.UserKey(
            keys_pb2.UserKey(
                name='foo',
                embedded_salt=keys_pb2.SaltKey(salt=secrets.token_bytes(32)),
            ),
            'password',
        )
        self.assertLen(uk.key_bytes(), 32)


if __name__ == '__main__':
    absltest.main()
