"""Unit tests for Vault module."""
import base64
import os
import secrets
import uuid

from absl.testing import absltest

from keycase import crypto
from keycase.v1alpha1 import keys_pb2
from keycase.vault import _vault


class TestVault(absltest.TestCase):
    """Unit tests for the _vault.Vault class."""

    def test_from_yaml(self):
        with open('keycase/vault/test_vault.yaml', 'r', encoding='utf-8') as f:
            v = _vault.Vault.from_yaml(f)
        self.assertEqual(
            v.user_keys['e9ef5506-3099-4a4d-b73b-e1d16163e2cf'],
            keys_pb2.UserKey(
                name='e9ef5506-3099-4a4d-b73b-e1d16163e2cf',
                embedded_salt=keys_pb2.SaltKey(salt=base64.decodebytes(
                    b'355jjlz2e6rOmQNWyZFK27igB1txXRAS7bfbWnZS2S4=')),
            ),
            'Could not retrieve user key.',
        )

    def test_get_token(self):
        user_key_name = str(uuid.uuid4())
        user_salt = secrets.token_bytes(32)
        user_key = crypto.password_key('password', user_salt)

        master_key_name = str(uuid.uuid4())
        master_key = crypto.random_key()
        encrypted_master_key = crypto.encrypt(
            master_key.key_bytes(),
            master_key_name,
            user_key,
        )

        secret_name = str(uuid.uuid4())
        secret = secrets.token_bytes(32)
        encrypted_secret = crypto.encrypt(
            secret,
            secret_name,
            master_key,
        )

        vault = keys_pb2.Vault()
        vault.user_keys.append(
            keys_pb2.UserKey(
                name=user_key_name,
                embedded_salt=keys_pb2.SaltKey(salt=user_salt),
            ),)
        vault.master_keys.append(
            keys_pb2.MasterKey(
                name=master_key_name,
                payloads=[
                    keys_pb2.Payload(
                        key_name=user_key_name,
                        ciphertext=encrypted_master_key,
                    ),
                ],
            ))
        vault.secrets.append(
            keys_pb2.Secret(
                name=secret_name,
                payloads=[
                    keys_pb2.Payload(
                        key_name=master_key_name,
                        ciphertext=encrypted_secret,
                    ),
                ],
            ))
        v = _vault.Vault.from_proto(vault)

        self.assertEqual(
            v.get_token(
                key_name=user_key_name,
                secret_name=secret_name,
            )('password'),
            secret,
        )


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

    @absltest.skipUnless(os.path.exists('/sys/class/tpm/tpm0'),
                         'Requires a TPM.')
    def test_machine_key_pcr_key_bytes(self):
        uk = _vault.UserKey(
            keys_pb2.UserKey(
                name='foo',
                machine_salt=keys_pb2.MachineKey(tpm_pcr=0),
            ),
            'password',
        )
        self.assertLen(uk.key_bytes(), 32)

    def test_machine_key_file_key_bytes(self):
        uk = _vault.UserKey(
            keys_pb2.UserKey(
                name='foo',
                machine_salt=keys_pb2.MachineKey(file_path='/etc/machine-id'),
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
