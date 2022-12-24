"""Module for generation of secure nonce values."""
import datetime
import secrets
import struct


def get_nonce() -> bytes:
    """Retrieve a 256-bit nonce suitable for AES256-GCM.

    The exact makeup of the nonce shall be considered an implementation
    detail, but it shall consist of at least 96 bits of randomness and
    may make use of non-random components to guard against collisions.

        >>> len(get_nonce())
        32

    Returns:
        bytes-like object whose length shall be exactly 32.
    """
    randomness = secrets.token_bytes(24)
    timestamp = struct.pack('<d', datetime.datetime.utcnow().timestamp())
    res = randomness + timestamp
    assert len(res) == 32
    return res
