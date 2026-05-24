"""
AES Finite Field Mathematics and S-box
======================================

AES operates over the finite field GF(2^8) (the Rijndael field), where each
byte is treated as a polynomial of degree < 8 over GF(2) (i.e. coefficients
are 0 or 1).

The reduction polynomial used by AES is:

    m(x) = x^8 + x^4 + x^3 + x + 1     (binary: 0b1_0001_1011 = 0x11B)

This module manually implements:

    * gf_mul(a, b)     -> multiplication in GF(2^8)
    * gf_inv(a)        -> multiplicative inverse in GF(2^8)
    * S_BOX, INV_S_BOX -> AES substitution boxes, built from scratch
    * RCON             -> round constants for the AES key schedule

We do NOT hard-code the S-box: we COMPUTE it the same way the AES
specification defines it. This is the educationally honest approach.
"""

_AES_POLY = 0x11B

def gf_add(a, b):
    """
    Addition in GF(2^8) is plain XOR.

    (Adding two polynomials over GF(2) means adding coefficients mod 2,
    which is XOR for the bit representation.)
    """
    return a ^ b

def gf_mul(a, b):
    """
    Multiplication in GF(2^8) using the Russian-peasant / shift-and-XOR
    algorithm, with reduction modulo the AES irreducible polynomial 0x11B.
    """
    result = 0
    a &= 0xFF
    b &= 0xFF
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:

            a ^= 0x1B
        b >>= 1
    return result & 0xFF

def gf_pow(a, n):
    """Exponentiation in GF(2^8) via square-and-multiply (uses gf_mul)."""
    result = 1
    base = a & 0xFF
    while n > 0:
        if n & 1:
            result = gf_mul(result, base)
        base = gf_mul(base, base)
        n >>= 1
    return result

def gf_inv(a):
    """
    Multiplicative inverse in GF(2^8).

    The multiplicative group of GF(2^8) has order 255, so by Lagrange:
        a^254  =  a^(-1)   for any nonzero a.

    Convention: the inverse of 0 is defined to be 0 (used by SubBytes).
    """
    if a == 0:
        return 0
    return gf_pow(a, 254)

def _affine_transform(b):
    result = 0
    for i in range(8):
        bit = (
            ((b >> i) & 1)
            ^ ((b >> ((i + 4) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 6) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1)
            ^ ((0x63 >> i) & 1)
        )
        result |= (bit & 1) << i
    return result

def _inv_affine_transform(b):
    """
    Inverse of the AES affine transform: the matrix is invertible over GF(2),
    and AES specifies the inverse as:

        b'_i = b_(i+2) XOR b_(i+5) XOR b_(i+7) XOR d_i
        where d = 0x05.
    """
    result = 0
    for i in range(8):
        bit = (
            ((b >> ((i + 2) % 8)) & 1)
            ^ ((b >> ((i + 5) % 8)) & 1)
            ^ ((b >> ((i + 7) % 8)) & 1)
            ^ ((0x05 >> i) & 1)
        )
        result |= (bit & 1) << i
    return result

def _build_sbox():
    sbox = [0] * 256
    for a in range(256):
        sbox[a] = _affine_transform(gf_inv(a))
    return sbox

def _build_inv_sbox(sbox):
    inv = [0] * 256
    for i in range(256):
        inv[sbox[i]] = i
    return inv

S_BOX = _build_sbox()
INV_S_BOX = _build_inv_sbox(S_BOX)

def _build_rcon(num_rounds=10):
    rcon = [0] * (num_rounds + 1)
    val = 1
    for i in range(1, num_rounds + 1):
        rcon[i] = val
        val = gf_mul(val, 0x02)
    return rcon

RCON = _build_rcon(10)
