"""
RSA Core
========

This module implements RSA key generation and the raw RSA primitives:

    * generate_keypair(bits)   -> (public_key, private_key)
    * rsa_encrypt_int(m, pub)  -> ciphertext integer
    * rsa_decrypt_int(c, priv) -> message integer
    * rsa_encrypt_bytes(...)   -> bytes-friendly wrapper
    * rsa_decrypt_bytes(...)   -> bytes-friendly wrapper

Mathematical foundation
-----------------------
RSA works in the multiplicative group of integers modulo n.

    Key generation:
        1. Pick two large random primes p, q (each `bits/2` bits long).
        2. n = p * q                          -> the public modulus
        3. phi(n) = (p - 1) * (q - 1)         -> Euler's totient of n
        4. Choose public exponent e with gcd(e, phi(n)) = 1.
           Standard choice: e = 65537.
        5. Compute private exponent d = e^(-1) mod phi(n).
           This is where modinv() is essential.

    Public key  = (n, e)
    Private key = (n, d)

Encryption / decryption of an integer m with 0 <= m < n:

        c = m^e mod n        (encryption with public key)
        m = c^d mod n        (decryption with private key)

Correctness comes from Euler's theorem: m^(ed) ≡ m (mod n).

Notes for this educational project
----------------------------------
* We only use RSA to encrypt the AES session key (16 bytes), so we
  do NOT need a complex padding scheme. We use a tiny "I2OSP-like"
  prefix to encode bytes <-> integers safely.
* For production RSA you would use OAEP padding. This is acknowledged
  in the README as a future improvement.
"""

from rsa.math_utils import gcd, modinv, mod_exp
from rsa.prime import generate_distinct_primes


DEFAULT_PUBLIC_EXPONENT = 65537


def generate_keypair(bits=1024, e=DEFAULT_PUBLIC_EXPONENT):
    """
    Generate an RSA keypair.

    Args:
        bits: total size of the modulus n in bits (default 1024).
              Each prime p, q will have `bits // 2` bits.
        e:    public exponent (default 65537, the standard RSA choice).

    Returns:
        public_key  = {"n": n, "e": e}
        private_key = {"n": n, "d": d, "p": p, "q": q}
    """
    if bits < 16 or bits % 2 != 0:
        raise ValueError("bits must be an even integer >= 16.")

    half = bits // 2

    # Generate p, q until gcd(e, phi(n)) == 1 (almost always true on
    # the first try when e = 65537, but we loop for full correctness).
    while True:
        p, q = generate_distinct_primes(half)
        n = p * q
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            break

    d = modinv(e, phi)

    public_key = {"n": n, "e": e}
    private_key = {"n": n, "d": d, "p": p, "q": q}

    return public_key, private_key


# ---------------------------------------------------------------------------
# Raw integer-level RSA primitives
# ---------------------------------------------------------------------------

def rsa_encrypt_int(m, public_key):
    """
    Encrypt the integer m using public_key.

    Requirement: 0 <= m < n.
    """
    n, e = public_key["n"], public_key["e"]
    if not (0 <= m < n):
        raise ValueError("Message integer must satisfy 0 <= m < n.")
    return mod_exp(m, e, n)


def rsa_decrypt_int(c, private_key):
    """
    Decrypt the ciphertext integer c using private_key.

    Requirement: 0 <= c < n.
    """
    n, d = private_key["n"], private_key["d"]
    if not (0 <= c < n):
        raise ValueError("Ciphertext integer must satisfy 0 <= c < n.")
    return mod_exp(c, d, n)


# ---------------------------------------------------------------------------
# Bytes-friendly wrappers (used by the hybrid layer)
# ---------------------------------------------------------------------------
#
# We need to convert a small byte string (an AES key) into an integer
# small enough to RSA-encrypt, and back.
#
# We use a minimal length-prefix scheme:
#     plaintext bytes  ->  b"\x00" || length(1 byte) || data
#     concatenated bytes are interpreted as a big-endian integer
#
# The leading 0x00 keeps the high byte from being interpreted as part of
# the length and ensures the integer stays under n. This is a SIMPLIFIED
# encoding suitable for the AES key (max 32 bytes). For arbitrary-length
# messages, a proper padding scheme (OAEP) would be required.

def _bytes_to_int(data):
    return int.from_bytes(data, byteorder="big")


def _int_to_bytes(value, length):
    return value.to_bytes(length, byteorder="big")


def rsa_encrypt_bytes(data, public_key):
    """
    Encrypt a short byte string (e.g. an AES session key) and return the
    ciphertext as bytes whose length equals the modulus byte-length.
    """
    n = public_key["n"]
    n_byte_len = (n.bit_length() + 7) // 8

    if len(data) > n_byte_len - 3:
        raise ValueError(
            "Data too long for this RSA modulus; use a larger key size."
        )

    # Simple framing: 0x00 || length || data, then pad with leading zeros.
    framed = b"\x00" + bytes([len(data)]) + data
    pad_len = n_byte_len - len(framed)
    framed = b"\x00" * pad_len + framed

    m = _bytes_to_int(framed)
    c = rsa_encrypt_int(m, public_key)
    return _int_to_bytes(c, n_byte_len)


def rsa_decrypt_bytes(cipher, private_key):
    """
    Decrypt a ciphertext produced by rsa_encrypt_bytes and recover the
    original byte string.
    """
    n = private_key["n"]
    n_byte_len = (n.bit_length() + 7) // 8

    if len(cipher) != n_byte_len:
        raise ValueError("Ciphertext length does not match modulus size.")

    c = _bytes_to_int(cipher)
    m = rsa_decrypt_int(c, private_key)
    framed = _int_to_bytes(m, n_byte_len)

    # Strip leading zero padding bytes.
    i = 0
    while i < len(framed) and framed[i] == 0:
        i += 1
    # Expect the structure: (zeros) || length || data
    # After stripping zeros, the first remaining byte is the length.
    if i >= len(framed):
        raise ValueError("Malformed RSA plaintext: all zeros.")
    length = framed[i]
    data = framed[i + 1 : i + 1 + length]
    if len(data) != length:
        raise ValueError("Malformed RSA plaintext: length mismatch.")
    return data
