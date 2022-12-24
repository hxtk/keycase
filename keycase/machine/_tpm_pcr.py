"""Cross-platform module for reading TPM Platform Control Registers."""
from typing import Literal, Optional

from keycase.machine import _tpm_pcr_constants as _constants


def read_pcr(
    register: _constants.Register,
    hash_size: Optional[Literal[1, 256, 384, 512]] = None,
) -> bytes:
    """Read the specified Platform Control Register.

    Args:
        register: The platform control register number to be read. This must be
            an integer in the semi-open range [0, 24).
        hash_size: The hash size to be read. One of SHA1, SHA256, SHA384,
            SHA512. If unspecified, the largest available hash shall be read.

    Returns:
        a `bytes` object containing the hash read from the specified
        Platform Control Register. Note that the hash is normally rendered as
        a hexadecimal string; the returned value here is the underlying 20-,
        32-, 48-, or 64-byte binary value.

    Raises:
        ValueError: if `register` was not in [0, 24)
        RuntimeError: if your platform is not supported; see message and cause
            for details.
    """
    del register, hash_size
    raise RuntimeError() from NotImplementedError(
        'read_pcr has not been implemented for this platform.')
