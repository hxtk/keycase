"""Linux module for reading TPM Platform Control Registers.

This specialization is used because it has fewer external dependencies
and therefore enhances portability to systems that may not be supported
by binary distributions of certain packages required for TPM interaction
on, e.g., Windows.
"""
import os
from typing import Optional

from keycase.machine import _tpm_pcr_constants as _constants

_BASE_PATH = '/sys/class/tpm/tpm0'
_PATHS = dict((x, f'{_BASE_PATH}/pcr-sha{x}') for x in _constants.SIZES)


def _get_largest_hash() -> _constants.HashSize:
    """Identify the largest available hash size.

    Returns:
        the number of the largest SHA variant for which a PCR directory
        exists, e.g., 1, 256, 384, 512.

    Raises:
        RuntimeError: if no PCR directory is found, e.g., the TPM does not
            support Platform Control Registers.
    """
    for k, v in _PATHS.items():
        if os.path.exists(v):
            return k
    raise RuntimeError('No PCR directory found. Does your TPM support PCRs?')


def read_pcr(
    register: _constants.Register,
    hash_size: Optional[_constants.HashSize] = None,
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
        RuntimeError: if the TPM virtual filesystem is not found or does not
            contain the requested hash size.
    """
    if register < 0 or register > 23:
        raise ValueError(f'Expected PCR in [0, 24); got {register}')
    if not os.path.exists(_BASE_PATH):
        raise RuntimeError(f'No such path `{_BASE_PATH}`. Do you have a TPM?')

    if hash_size is None:
        path = _PATHS[_get_largest_hash()]
    else:
        path = _PATHS[hash_size]
        if not os.path.exists(path):
            raise RuntimeError(
                f'No PCR directory found for hash size {hash_size}')

    with open(os.path.join(path, str(register)), 'r', encoding='utf-8') as f:
        return bytes.fromhex(f.readline().rstrip('\n'))
