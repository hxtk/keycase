"""Build in-memory representation of a Vault."""
import io
from typing import Callable, Mapping, TextIO, Union
import yaml

from google.protobuf import json_format

from keycase import crypto
from keycase import machine
from keycase.v1alpha1 import keys_pb2


class NotFoundError(Exception):
    """Queried object did not exist."""


class Vault(object):
    """Represents an in-memory `key_pb2.Vault`"""

    def __init__(
        self,
        secrets: Mapping[str, keys_pb2.Secret],
        master_keys: Mapping[str, keys_pb2.MasterKey],
        user_keys: Mapping[str, keys_pb2.UserKey],
    ):
        self.secrets = secrets
        self.master_keys = master_keys
        self.user_keys = user_keys

    @classmethod
    def from_proto(cls, vault: keys_pb2.Vault) -> 'Vault':
        secrets = dict((x.name, x) for x in vault.secrets)
        master_keys = dict((x.name, x) for x in vault.master_keys)
        user_keys = dict((x.name, x) for x in vault.user_keys)
        return cls(secrets, master_keys, user_keys)

    @classmethod
    def from_yaml(cls, stream: TextIO) -> 'Vault':
        obj = yaml.safe_load(stream)

        vault = keys_pb2.Vault()
        json_format.ParseDict(obj, vault)
        return cls.from_proto(vault)

    def dump_proto(self) -> keys_pb2.Vault:
        return keys_pb2.Vault(
            user_keys=self.user_keys.values(),
            master_keys=self.master_keys.values(),
            secrets=self.secrets.values(),
        )

    def dump_string(self) -> str:
        buffer = io.StringIO()
        self.dump_stream(buffer)
        return buffer.read()

    def dump_stream(self, stream: io.StringIO) -> None:
        vault = self.dump_proto()
        yaml.dump(json_format.MessageToDict(vault), stream)

    def _internal_get_token(
        self,
        secret: keys_pb2.Secret,
        user_key: keys_pb2.UserKey,
    ) -> Callable[[str], bytes]:
        for secret_payload in secret.payloads:
            for master_payload in self.master_keys[
                    secret_payload.key_name].keys:
                if user_key.name == master_payload.key_name:
                    return _key_chain(
                        keys_pb2.Secret(
                            name=secret.name,
                            payloads=[secret_payload],
                        ),
                        keys_pb2.MasterKey(
                            name=secret_payload.key_name,
                            keys=[master_payload],
                        ),
                        user_key,
                    )
        raise NotFoundError('No suitable decryption path found.')

    def get_token(
        self,
        secret_name: str,
        key_name: str,
    ) -> Callable[[str], bytes]:
        return self._internal_get_token(
            self.secrets[secret_name],
            self.user_keys[key_name],
        )


class EncryptedKey(object):
    """Cryptographic Key constructed from data decrypted using another key."""

    def __init__(
        self,
        ciphertext: bytes,
        associated_data: Union[str, bytes],
        key: crypto.Key,
    ):
        self.ciphertext = ciphertext
        self.associated_data = associated_data
        self.key = key

    def key_bytes(self):
        return crypto.decrypt(self.ciphertext, self.associated_data, self.key)


class UserKey(object):
    """Cryptographic Key constructed from a `key_pb2.UserKey`"""

    def __init__(self, user_key: keys_pb2.UserKey, password: str):
        self.user_key = user_key
        self.password = password

    def key_bytes(self):
        kind = self.user_key.WhichOneof('kind')
        if kind == 'embedded_salt':
            return crypto.password_key(
                self.password,
                self.user_key.embedded_salt.salt,
            ).key_bytes()
        if kind == 'machine_salt':
            key = self.user_key.machine_salt
            kind = key.WhichOneof('kind')
            if kind == 'tpm_pcr':
                return crypto.password_key(
                    secret=self.password,
                    salt=machine.read_pcr(key.tpm_pcr),
                ).key_bytes()
            if kind == 'file_path':
                return crypto.password_key(
                    secret=self.password,
                    salt=machine.file_hash(key.file_path),
                ).key_bytes()
        raise NotImplementedError('That key type has not been implemented.')


def _key_chain(
    secret: keys_pb2.Secret,
    master_key: keys_pb2.MasterKey,
    user_key: keys_pb2.UserKey,
) -> Callable[[str], bytes]:

    def turnkey(password: str) -> bytes:
        return crypto.decrypt(
            secret.payloads[0].ciphertext,
            secret.name,
            EncryptedKey(
                master_key.keys[0].ciphertext,
                master_key.name,
                UserKey(user_key, password),
            ),
        )

    return turnkey
