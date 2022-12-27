from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class AsymmetricEncryptedKey(_message.Message):
    __slots__ = ["ciphertext", "private_commands", "private_key", "public_commands", "public_key", "public_key_bytes", "public_key_file"]
    class PrivateCommand(_message.Message):
        __slots__ = ["decrypt"]
        DECRYPT_FIELD_NUMBER: _ClassVar[int]
        decrypt: Command
        def __init__(self, decrypt: _Optional[_Union[Command, _Mapping]] = ...) -> None: ...
    class PublicCommand(_message.Message):
        __slots__ = ["encrypt"]
        ENCRYPT_FIELD_NUMBER: _ClassVar[int]
        encrypt: Command
        def __init__(self, encrypt: _Optional[_Union[Command, _Mapping]] = ...) -> None: ...
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_COMMANDS_FIELD_NUMBER: _ClassVar[int]
    PRIVATE_KEY_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_COMMANDS_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_BYTES_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FILE_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    private_commands: AsymmetricEncryptedKey.PrivateCommand
    private_key: Command
    public_commands: AsymmetricEncryptedKey.PublicCommand
    public_key: Command
    public_key_bytes: bytes
    public_key_file: str
    def __init__(self, ciphertext: _Optional[bytes] = ..., public_key: _Optional[_Union[Command, _Mapping]] = ..., public_commands: _Optional[_Union[AsymmetricEncryptedKey.PublicCommand, _Mapping]] = ..., public_key_file: _Optional[str] = ..., public_key_bytes: _Optional[bytes] = ..., private_key: _Optional[_Union[Command, _Mapping]] = ..., private_commands: _Optional[_Union[AsymmetricEncryptedKey.PrivateCommand, _Mapping]] = ...) -> None: ...

class Command(_message.Message):
    __slots__ = ["argv", "command"]
    ARGV_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    argv: _containers.RepeatedScalarFieldContainer[str]
    command: str
    def __init__(self, command: _Optional[str] = ..., argv: _Optional[_Iterable[str]] = ...) -> None: ...

class MachineKey(_message.Message):
    __slots__ = ["command", "file_path", "tpm_pcr"]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    TPM_PCR_FIELD_NUMBER: _ClassVar[int]
    command: Command
    file_path: str
    tpm_pcr: int
    def __init__(self, tpm_pcr: _Optional[int] = ..., file_path: _Optional[str] = ..., command: _Optional[_Union[Command, _Mapping]] = ...) -> None: ...

class MasterKey(_message.Message):
    __slots__ = ["create_timestamp", "name", "payloads"]
    CREATE_TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PAYLOADS_FIELD_NUMBER: _ClassVar[int]
    create_timestamp: _timestamp_pb2.Timestamp
    name: str
    payloads: _containers.RepeatedCompositeFieldContainer[Payload]
    def __init__(self, name: _Optional[str] = ..., payloads: _Optional[_Iterable[_Union[Payload, _Mapping]]] = ..., create_timestamp: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class Payload(_message.Message):
    __slots__ = ["ciphertext", "key_name"]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    KEY_NAME_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    key_name: str
    def __init__(self, key_name: _Optional[str] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...

class Pkcs11EncryptedKey(_message.Message):
    __slots__ = ["ciphertext", "pkcs11_uri", "public_key"]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    PKCS11_URI_FIELD_NUMBER: _ClassVar[int]
    PUBLIC_KEY_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    pkcs11_uri: str
    public_key: bytes
    def __init__(self, ciphertext: _Optional[bytes] = ..., pkcs11_uri: _Optional[str] = ..., public_key: _Optional[bytes] = ...) -> None: ...

class SaltKey(_message.Message):
    __slots__ = ["salt"]
    SALT_FIELD_NUMBER: _ClassVar[int]
    salt: bytes
    def __init__(self, salt: _Optional[bytes] = ...) -> None: ...

class Secret(_message.Message):
    __slots__ = ["description", "display_name", "name", "payloads"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PAYLOADS_FIELD_NUMBER: _ClassVar[int]
    description: str
    display_name: str
    name: str
    payloads: _containers.RepeatedCompositeFieldContainer[Payload]
    def __init__(self, name: _Optional[str] = ..., display_name: _Optional[str] = ..., description: _Optional[str] = ..., payloads: _Optional[_Iterable[_Union[Payload, _Mapping]]] = ...) -> None: ...

class UserKey(_message.Message):
    __slots__ = ["asymmetric_key", "create_time", "embedded_salt", "machine_salt", "name", "pkcs11_key"]
    ASYMMETRIC_KEY_FIELD_NUMBER: _ClassVar[int]
    CREATE_TIME_FIELD_NUMBER: _ClassVar[int]
    EMBEDDED_SALT_FIELD_NUMBER: _ClassVar[int]
    MACHINE_SALT_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PKCS11_KEY_FIELD_NUMBER: _ClassVar[int]
    asymmetric_key: AsymmetricEncryptedKey
    create_time: _timestamp_pb2.Timestamp
    embedded_salt: SaltKey
    machine_salt: MachineKey
    name: str
    pkcs11_key: Pkcs11EncryptedKey
    def __init__(self, name: _Optional[str] = ..., create_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ..., embedded_salt: _Optional[_Union[SaltKey, _Mapping]] = ..., machine_salt: _Optional[_Union[MachineKey, _Mapping]] = ..., pkcs11_key: _Optional[_Union[Pkcs11EncryptedKey, _Mapping]] = ..., asymmetric_key: _Optional[_Union[AsymmetricEncryptedKey, _Mapping]] = ...) -> None: ...

class Vault(_message.Message):
    __slots__ = ["default_key", "master_keys", "secrets", "user_keys"]
    DEFAULT_KEY_FIELD_NUMBER: _ClassVar[int]
    MASTER_KEYS_FIELD_NUMBER: _ClassVar[int]
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    USER_KEYS_FIELD_NUMBER: _ClassVar[int]
    default_key: str
    master_keys: _containers.RepeatedCompositeFieldContainer[MasterKey]
    secrets: _containers.RepeatedCompositeFieldContainer[Secret]
    user_keys: _containers.RepeatedCompositeFieldContainer[UserKey]
    def __init__(self, user_keys: _Optional[_Iterable[_Union[UserKey, _Mapping]]] = ..., master_keys: _Optional[_Iterable[_Union[MasterKey, _Mapping]]] = ..., secrets: _Optional[_Iterable[_Union[Secret, _Mapping]]] = ..., default_key: _Optional[str] = ...) -> None: ...
