"""Obtain measured identities for the host machine."""
import sys

from keycase.machine import _file
if 'linux' in sys.platform:
    from keycase.machine import _tpm_pcr_linux
    read_pcr = _tpm_pcr_linux.read_pcr
else:
    from keycase.machine import _tpm_pcr
    read_pcr = _tpm_pcr.read_pcr

file_hash = _file.file_hash

__all__ = ['read_pcr', 'file_hash']
