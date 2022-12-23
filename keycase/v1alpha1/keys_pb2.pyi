from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Key(_message.Message):
    __slots__ = ["create_time", "embedded_salt", "key_encrypted", "machine_salt", "name", "pkcs11_key"]
    CREATE_TIME_FIELD_NUMBER: _ClassVar[int]
    EMBEDDED_SALT_FIELD_NUMBER: _ClassVar[int]
    KEY_ENCRYPTED_FIELD_NUMBER: _ClassVar[int]
    MACHINE_SALT_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    PKCS11_KEY_FIELD_NUMBER: _ClassVar[int]
    create_time: _timestamp_pb2.Timestamp
    embedded_salt: bytes
    key_encrypted: Payload
    machine_salt: MachineKey
    name: str
    pkcs11_key: Pkcs11EncryptedKey
    def __init__(self, name: _Optional[str] = ..., embedded_salt: _Optional[bytes] = ..., machine_salt: _Optional[_Union[MachineKey, _Mapping]] = ..., pkcs11_key: _Optional[_Union[Pkcs11EncryptedKey, _Mapping]] = ..., key_encrypted: _Optional[_Union[Payload, _Mapping]] = ..., create_time: _Optional[_Union[_timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class MachineKey(_message.Message):
    __slots__ = ["command", "file_path", "tpm_pcr"]
    class Command(_message.Message):
        __slots__ = ["argv", "command"]
        ARGV_FIELD_NUMBER: _ClassVar[int]
        COMMAND_FIELD_NUMBER: _ClassVar[int]
        argv: _containers.RepeatedScalarFieldContainer[str]
        command: str
        def __init__(self, command: _Optional[str] = ..., argv: _Optional[_Iterable[str]] = ...) -> None: ...
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    TPM_PCR_FIELD_NUMBER: _ClassVar[int]
    command: MachineKey.Command
    file_path: str
    tpm_pcr: int
    def __init__(self, tpm_pcr: _Optional[int] = ..., file_path: _Optional[str] = ..., command: _Optional[_Union[MachineKey.Command, _Mapping]] = ...) -> None: ...

class Payload(_message.Message):
    __slots__ = ["ciphertext", "key_names"]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    KEY_NAMES_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    key_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, key_names: _Optional[_Iterable[str]] = ..., ciphertext: _Optional[bytes] = ...) -> None: ...

class Pkcs11EncryptedKey(_message.Message):
    __slots__ = ["ciphertext", "pkcs11_uri"]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    PKCS11_URI_FIELD_NUMBER: _ClassVar[int]
    ciphertext: bytes
    pkcs11_uri: str
    def __init__(self, ciphertext: _Optional[bytes] = ..., pkcs11_uri: _Optional[str] = ...) -> None: ...

class Secret(_message.Message):
    __slots__ = ["data", "description", "display_name", "name"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_NAME_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    data: _containers.RepeatedCompositeFieldContainer[Payload]
    description: str
    display_name: str
    name: str
    def __init__(self, name: _Optional[str] = ..., display_name: _Optional[str] = ..., description: _Optional[str] = ..., data: _Optional[_Iterable[_Union[Payload, _Mapping]]] = ...) -> None: ...

class Vault(_message.Message):
    __slots__ = ["keys", "secrets"]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    SECRETS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[Key]
    secrets: _containers.RepeatedCompositeFieldContainer[Secret]
    def __init__(self, keys: _Optional[_Iterable[_Union[Key, _Mapping]]] = ..., secrets: _Optional[_Iterable[_Union[Secret, _Mapping]]] = ...) -> None: ...
