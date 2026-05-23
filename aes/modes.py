"""
AES Block Cipher Modes of Operation
===================================

Implements AES-128 in CBC (Cipher Block Chaining) mode with PKCS#7 padding.

CBC mode
--------
Each plaintext block is XOR-ed with the previous ciphertext block before
being encrypted. The first block is XOR-ed with a random Initialization
Vector (IV):

    C_0 = E_K( P_0 XOR IV )
    C_i = E_K( P_i XOR C_(i-1) )      for i >= 1

To decrypt:
    P_0 = D_K(C_0) XOR IV
    P_i = D_K(C_i) XOR C_(i-1)

Properties:
    * Same plaintext block encrypts to different ciphertexts under
      different IVs.
    * The IV is NOT secret but MUST be unpredictable (random) per message.

PKCS#7 padding
--------------
AES is a block cipher: it requires plaintext length to be a multiple of
16 bytes. PKCS#7 pads with N bytes each of value N, where N is the number
of padding bytes added (1 <= N <= 16). If the plaintext is already a
multiple of 16, a full extra block of 16 0x10 bytes is appended -- this
is required so unpadding is unambiguous.
"""

import secrets

from aes.aes_core import aes_encrypt_block, aes_decrypt_block, BLOCK_SIZE


# ---------------------------------------------------------------------------
# PKCS#7 padding
# ---------------------------------------------------------------------------

def pkcs7_pad(data, block_size=BLOCK_SIZE):
    """Append PKCS#7 padding so len(data) becomes a multiple of block_size."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data, block_size=BLOCK_SIZE):
    """Remove PKCS#7 padding. Raises ValueError on malformed padding."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid PKCS#7 padding byte.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Corrupted PKCS#7 padding.")
    return data[:-pad_len]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def generate_iv():
    """Return a fresh random 16-byte IV using the OS CSPRNG."""
    return secrets.token_bytes(BLOCK_SIZE)


def generate_aes_key():
    """Return a fresh random 16-byte AES-128 session key."""
    return secrets.token_bytes(BLOCK_SIZE)


# ---------------------------------------------------------------------------
# CBC mode encryption / decryption
# ---------------------------------------------------------------------------

def aes_cbc_encrypt(plaintext, key, iv):
    """
    AES-128 CBC encryption with PKCS#7 padding.

    Args:
        plaintext: arbitrary-length bytes.
        key:       16-byte AES key.
        iv:        16-byte initialization vector.

    Returns:
        ciphertext bytes, length is a multiple of 16.
    """
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes.")

    padded = pkcs7_pad(plaintext)
    ciphertext = b""
    previous = iv

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        xored = _xor_bytes(block, previous)
        encrypted = aes_encrypt_block(xored, key)
        ciphertext += encrypted
        previous = encrypted

    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    """
    AES-128 CBC decryption with PKCS#7 unpadding.

    Args:
        ciphertext: bytes whose length is a multiple of 16.
        key:        16-byte AES key.
        iv:         16-byte initialization vector.

    Returns:
        original plaintext bytes.
    """
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 key must be 16 bytes.")
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must be 16 bytes.")
    if len(ciphertext) == 0 or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 16.")

    plaintext = b""
    previous = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        decrypted = aes_decrypt_block(block, key)
        plaintext += _xor_bytes(decrypted, previous)
        previous = block

    return pkcs7_unpad(plaintext)
