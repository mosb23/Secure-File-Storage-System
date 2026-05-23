"""
AES-128 Core Block Cipher
=========================

This module implements the AES-128 block cipher manually:

    aes_encrypt_block(plaintext_16_bytes, key_16_bytes) -> 16 bytes
    aes_decrypt_block(ciphertext_16_bytes, key_16_bytes) -> 16 bytes

All four core transformations are implemented from scratch:

    SubBytes / InvSubBytes
    ShiftRows / InvShiftRows
    MixColumns / InvMixColumns
    AddRoundKey

AES State Representation
------------------------
The 16-byte block is arranged as a 4x4 column-major matrix of bytes:

        | b0  b4  b8  b12 |
        | b1  b5  b9  b13 |
        | b2  b6  b10 b14 |
        | b3  b7  b11 b15 |

We store the state as a list of 16 bytes (flat) and access element
(row, col) as state[col*4 + row], which matches the AES specification.

Encryption Flow (AES-128, 10 rounds)
------------------------------------
    AddRoundKey (round 0)
    for r = 1..9:
        SubBytes
        ShiftRows
        MixColumns
        AddRoundKey (round r)
    SubBytes
    ShiftRows
    AddRoundKey (round 10)         # NOTE: no MixColumns in the last round
"""

from aes.sbox import S_BOX, INV_S_BOX, gf_mul
from aes.key_expansion import expand_key


BLOCK_SIZE = 16


# ---------------------------------------------------------------------------
# Helpers: state <-> bytes
# ---------------------------------------------------------------------------

def _bytes_to_state(block):
    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be exactly 16 bytes.")
    return list(block)


def _state_to_bytes(state):
    return bytes(state)


# ---------------------------------------------------------------------------
# SubBytes / InvSubBytes
# ---------------------------------------------------------------------------

def _sub_bytes(state):
    for i in range(16):
        state[i] = S_BOX[state[i]]


def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]


# ---------------------------------------------------------------------------
# ShiftRows / InvShiftRows
# ---------------------------------------------------------------------------
#
# In the column-major layout, row r is at indices r, r+4, r+8, r+12.
# ShiftRows cyclically shifts row r LEFT by r positions.

def _shift_rows(state):
    new_state = state[:]
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[r:] + row[:r]                # left rotate by r
        for c in range(4):
            new_state[r + 4 * c] = row[c]
    state[:] = new_state


def _inv_shift_rows(state):
    new_state = state[:]
    for r in range(4):
        row = [state[r + 4 * c] for c in range(4)]
        row = row[-r:] + row[:-r] if r else row  # right rotate by r
        for c in range(4):
            new_state[r + 4 * c] = row[c]
    state[:] = new_state


# ---------------------------------------------------------------------------
# MixColumns / InvMixColumns
# ---------------------------------------------------------------------------
#
# Each column is treated as a 4-element vector and multiplied (in GF(2^8))
# by the fixed matrix:
#
#     | 02 03 01 01 |        Inverse: | 0e 0b 0d 09 |
#     | 01 02 03 01 |                 | 09 0e 0b 0d |
#     | 01 01 02 03 |                 | 0d 09 0e 0b |
#     | 03 01 01 02 |                 | 0b 0d 09 0e |

def _mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3,
        a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3,
        a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3),
        gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2),
    ]


def _inv_mix_single_column(col):
    a0, a1, a2, a3 = col
    return [
        gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09),
        gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d),
        gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b),
        gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e),
    ]


def _mix_columns(state):
    for c in range(4):
        col = state[4 * c : 4 * c + 4]
        state[4 * c : 4 * c + 4] = _mix_single_column(col)


def _inv_mix_columns(state):
    for c in range(4):
        col = state[4 * c : 4 * c + 4]
        state[4 * c : 4 * c + 4] = _inv_mix_single_column(col)


# ---------------------------------------------------------------------------
# AddRoundKey
# ---------------------------------------------------------------------------

def _add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]


# ---------------------------------------------------------------------------
# Public API: single-block AES encryption / decryption
# ---------------------------------------------------------------------------

def aes_encrypt_block(plaintext, key):
    """Encrypt a single 16-byte block with AES-128."""
    if len(plaintext) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes.")

    round_keys = expand_key(key)
    state = _bytes_to_state(plaintext)

    _add_round_key(state, round_keys[0])

    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])

    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])

    return _state_to_bytes(state)


def aes_decrypt_block(ciphertext, key):
    """Decrypt a single 16-byte block with AES-128 (inverse of encrypt)."""
    if len(ciphertext) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes.")

    round_keys = expand_key(key)
    state = _bytes_to_state(ciphertext)

    _add_round_key(state, round_keys[10])
    _inv_shift_rows(state)
    _inv_sub_bytes(state)

    for r in range(9, 0, -1):
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)

    _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)
