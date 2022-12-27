"""OAEP Padding Utilities for RSA cryptography."""
import math
import typing
from typing import Union

from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives import hashes


def _xor(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError('a and b MUST be `bytes` objects of equal length.')

    return bytes(x ^ y for x, y in zip(a, b))


class PaddingError(Exception):
    """Error stripping OAEP padding."""


MaskGenerationFunction = typing.Callable[[bytes, int], bytes]


class MGF1(object):
    """Implementation of the MFG1 Mask Generation Function.

    Args:
        hash_algorithm: the hash algorithm used to generate pseudorandom bytes.
    """

    def __init__(self, hash_algorithm: hashes.HashAlgorithm):
        self.hash_algorithm = hash_algorithm

    def __call__(self, mgf_seed: bytes, mask_len: int) -> bytes:
        """Implements MGF1.

        See: https://www.rfc-editor.org/rfc/rfc3447#appendix-B.2.1

        Args:
            mgf_seed: the random seed to use for mask generation.
            mask_len: the length of the mask to be generated.

        Returns:
            deterministic pseudorandom bytestring of length `mask_len`.
        """
        h_len = self.hash_algorithm.digest_size

        t = bytes()
        for counter in range(math.ceil(mask_len / h_len)):
            c = counter.to_bytes(length=4, byteorder='big', signed=False)
            hash_ = hashes.Hash(self.hash_algorithm)
            hash_.update(mgf_seed)
            hash_.update(c)
            t += hash_.finalize()

        return t[:mask_len]


def strip_padding(
    encoded_message: bytes,
    key_size: int,
    mgf: MaskGenerationFunction,
    hash_algorithm: hashes.HashAlgorithm,
    associated_data: Union[str, bytes, None] = None,
) -> bytes:
    """Remove padding from an OAEP-padded message.

    This function follows the algorithm defined in step 3 of the algorithm
    here: https://www.rfc-editor.org/rfc/rfc3447#section-7.1.2

    Args:
        encoded_message: EME-OAEP-encoded bytes representing the message.
        key_size: length in octets of RSA modulus `n`.
        hash_algorithm: the hashing algorithm used.
        mgf: a mask generation function.
        associated_data: some public data that will be used to authenticate the
            decrypted message.
    Returns:
        the decoded message with padding removed as a `bytes` object.
    """
    # a. If the label L is not provided, let L be the empty string. Let
    # lHash = Hash(L), an octet string of length hLen (see the note
    # in Section 7.1.1).
    if associated_data is None:
        label = b''
    elif isinstance(associated_data, str):
        label = associated_data.encode(encoding='utf-8')
    else:
        label = associated_data

    hash_ = hashes.Hash(hash_algorithm)
    hash_.update(label)
    l_hash = hash_.finalize()

    # b. Separate the encoded message EM into a single octet Y, an octet
    # string maskedSeed of length hLen, and an octet string maskedDB
    # of length k - hLen - 1 as:
    #
    #     EM = Y || maskedSeed || maskedDB.
    h_len = hash_algorithm.digest_size
    y, encoded_message = encoded_message[:1], encoded_message[1:]
    masked_seed, masked_db = (
        encoded_message[:h_len],
        encoded_message[h_len:],
    )
    assert len(masked_db) == key_size - h_len - 1

    # c. Let seedMask = MGF(maskedDB, hLen).
    seed_mask = mgf(masked_db, h_len)

    # d. Let seed = maskedSeed \xor seedMask.
    seed = _xor(masked_seed, seed_mask)

    # e. Let dbMask = MGF(seed, k - hLen - 1).
    db_mask = mgf(seed, key_size - h_len - 1)

    # f. Let DB = maskedDB \xor dbMask.
    db = _xor(masked_db, db_mask)

    # g. Separate DB into an octet string lHash' of length hLen, a
    # (possibly empty) padding string PS consisting of octets with
    # hexadecimal value 0x00, and a message M as
    #
    #     DB = lHash' || PS || 0x01 || M.
    #
    # ...
    l_hash_prime, residual = db[:h_len], db[h_len:]
    idx = residual.find(b'\x01')

    # ...
    # If there is no octet with hexadecimal value 0x01 to separate PS
    # from M, if lHash does not equal lHash', or if Y is nonzero,
    # output "decryption error" and stop.  (See the note below.)
    error_states = [
        # If there is no octet with hexadecimal value 0x01 to separate PS from M
        idx == -1,

        # if lHash does not equal lHash'
        not constant_time.bytes_eq(l_hash_prime, l_hash),

        # if Y is nonzero
        not constant_time.bytes_eq(y, b'\x00'),
    ]

    # 4. Output the message M.
    #
    #    Note.  Care must be taken to ensure that an opponent cannot
    #    distinguish the different error conditions in Step 3.g, whether by
    #    error message or timing, or, more generally, learn partial
    #    information about the encoded message EM.  Otherwise an opponent may
    #    be able to obtain useful information about the decryption of the
    #    ciphertext C, leading to a chosen-ciphertext attack such as the one
    #    observed by Manger [36].
    #
    # Below computes a sum of all error states and ensures that sum is 0 as a
    # constant-time implementation of `none`.
    if sum(1 if x else 0 for x in error_states) != 0:
        raise PaddingError('decryption error')

    return residual[idx + 1:]
