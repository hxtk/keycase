"""Read non-changing files on the device."""
import hashlib


def file_hash(path: str) -> bytes:
    """Hash the file at the specified path.

    Missing files and empty files are treated identically.

    Returns:
        a `bytes` object containing the raw bytes of a secure hash
        of the specified file. If the file is not found, it is treated
        as empty. The exact hashing mechanism is an implementation detail,
        but shall remain fixed for a given major release version and shall
        return at least 16 bytes.
    """
    try:
        with open(path, 'rb') as f:
            return hashlib.sha3_512(f.read()).digest()
    except FileNotFoundError:
        return hashlib.sha3_512(b'').digest()
