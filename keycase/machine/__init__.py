"""Obtain measured identities for the host machine."""
import sys

if 'linux' in sys.platform:
    from keycase.machine import _tpm_pcr_linux
    read_pcr = _tpm_pcr_linux.read_pcr
else:
    from keycase.machine import _tpm_pcr
    read_pcr = _tpm_pcr.read_pcr

__all__ = ['read_pcr']
