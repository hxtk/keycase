from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class CipherText(_message.Message):
    __slots__ = ["authn_tag", "ciphertext", "nonce"]
    AUTHN_TAG_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    authn_tag: bytes
    ciphertext: bytes
    nonce: bytes
    def __init__(self, nonce: _Optional[bytes] = ..., ciphertext: _Optional[bytes] = ..., authn_tag: _Optional[bytes] = ...) -> None: ...
