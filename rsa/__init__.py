"""RSA package: number theory, prime generation, and RSA primitives."""

from rsa.math_utils import gcd, egcd, modinv, mod_exp
from rsa.prime import is_probable_prime, generate_prime, generate_distinct_primes
from rsa.rsa_core import (
    generate_keypair,
    rsa_encrypt_int,
    rsa_decrypt_int,
    rsa_encrypt_bytes,
    rsa_decrypt_bytes,
)

__all__ = [
    "gcd", "egcd", "modinv", "mod_exp",
    "is_probable_prime", "generate_prime", "generate_distinct_primes",
    "generate_keypair",
    "rsa_encrypt_int", "rsa_decrypt_int",
    "rsa_encrypt_bytes", "rsa_decrypt_bytes",
]
