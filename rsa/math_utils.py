"""
RSA Mathematics Utilities
=========================

This module implements the four fundamental number-theory operations that
RSA depends on:

    1. gcd(a, b)               -> Euclidean algorithm
    2. egcd(a, b)              -> Extended Euclidean algorithm
    3. modinv(a, m)            -> Modular multiplicative inverse
    4. mod_exp(base, exp, mod) -> Modular exponentiation (repeated squaring)

IMPORTANT (project rules)
-------------------------
* We do NOT use Python's built-in `pow(a, b, m)`.
* We do NOT use any external cryptography library.
* Every algorithm is written manually for educational clarity.

Why these four functions matter for RSA
---------------------------------------
* RSA key generation needs:
    - gcd  : to verify that the public exponent e is coprime with phi(n).
    - egcd / modinv : to compute the private exponent d such that
                      (d * e) mod phi(n) == 1.
* RSA encryption/decryption is just modular exponentiation:
        ciphertext = (message ** e) mod n
        message    = (ciphertext ** d) mod n
  Because n is ~1024 bits, naive exponentiation is impossible.
  We MUST use repeated squaring.

All functions in this file work on arbitrary-size Python integers, which
is exactly what RSA needs (numbers with hundreds of digits).
"""

def gcd(a, b):
    """
    Return the greatest common divisor of a and b using Euclid's algorithm.

    Examples:
        gcd(54, 24) -> 6
        gcd(17, 31) -> 1   (17 and 31 are coprime)
    """
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a

def egcd(a, b):
    """
    Extended Euclidean algorithm.

    Returns a tuple (g, x, y) such that:
        a*x + b*y = g = gcd(a, b)

    Example:
        egcd(30, 18) -> (6, -1, 2)
        Check: 30*(-1) + 18*(2) = -30 + 36 = 6 = gcd(30, 18)
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    return (old_r, old_s, old_t)

def modinv(a, m):
    """
    Return the modular multiplicative inverse of a modulo m.

    Raises ValueError if the inverse does not exist (i.e. gcd(a, m) != 1).

    Example:
        modinv(3, 11) -> 4   because (3 * 4) mod 11 = 12 mod 11 = 1
    """
    if m <= 0:
        raise ValueError("Modulus must be positive.")

    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(
            f"Modular inverse does not exist: gcd({a}, {m}) = {g}, "
            "but it must be 1."
        )

    return x % m

def mod_exp(base, exp, mod):
    """
    Compute (base ** exp) mod mod using repeated squaring.

    This is THE workhorse function of RSA encryption/decryption.

    Example:
        mod_exp(7, 13, 19) -> 7
        mod_exp(2, 10, 1000) -> 24   (2^10 = 1024, 1024 mod 1000 = 24)
    """
    if mod <= 0:
        raise ValueError("Modulus must be positive.")
    if exp < 0:

        base = modinv(base, mod)
        exp = -exp
    if mod == 1:
        return 0

    result = 1
    base = base % mod

    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod

    return result
