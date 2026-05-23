"""
Prime Number Generation for RSA
===============================

RSA security depends on two LARGE secret primes p and q (typically
512 bits each so that n = p*q is 1024 bits).

This module manually implements:
    1. is_probable_prime(n)   -> Miller-Rabin probabilistic primality test
    2. generate_prime(bits)   -> generate a random prime of the given size

We do NOT use any external cryptography library.
We do NOT use Python's built-in pow(a, b, m); instead we call our own
manual mod_exp() from rsa.math_utils.

Why Miller-Rabin?
-----------------
Trial division up to sqrt(n) is impossible for 512-bit numbers
(sqrt(2^512) = 2^256 candidate divisors).
Miller-Rabin is a fast PROBABILISTIC test:

    * If it says "composite", n is definitely composite.
    * If it says "probably prime", the probability of being wrong
      after k independent rounds is at most (1/4)^k.

For RSA quality we use k = 40 rounds, giving an error probability
below 2^-80, which is astronomically small.
"""

import secrets

from rsa.math_utils import mod_exp


# A few small primes used to quickly reject obvious composites
# before invoking the more expensive Miller-Rabin test.
_SMALL_PRIMES = [
      2,   3,   5,   7,  11,  13,  17,  19,  23,  29,
     31,  37,  41,  43,  47,  53,  59,  61,  67,  71,
     73,  79,  83,  89,  97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
]


def _miller_rabin_round(n, a):
    """
    Single Miller-Rabin round with witness `a`.

    Background (Fermat's little theorem extended):
        For an odd prime n, write n - 1 = d * 2^s with d odd.
        Then for any a coprime with n, exactly one of the following holds:
            (1)  a^d  ≡  1 (mod n)
            (2)  a^(d * 2^r)  ≡  -1 (mod n)   for some r in [0, s-1]

    If NEITHER (1) nor (2) is true, then n is definitely composite
    and `a` is called a "witness" for that fact.

    Returns:
        True   if the test passes (n could still be prime).
        False  if n is definitely composite.
    """
    # Decompose n - 1 = d * 2^s with d odd.
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Compute a^d mod n using our manual modular exponentiation.
    x = mod_exp(a, d, n)

    # Case (1): a^d ≡ 1 (mod n) -- looks prime, pass the test.
    if x == 1 or x == n - 1:
        return True

    # Otherwise, square up to s-1 times looking for x ≡ -1 (mod n).
    for _ in range(s - 1):
        x = (x * x) % n
        if x == n - 1:
            return True

    # No witness condition met -> definitely composite.
    return False


def is_probable_prime(n, rounds=40):
    """
    Miller-Rabin primality test.

    Returns:
        True   if n is probably prime (error probability <= (1/4)^rounds).
        False  if n is definitely composite.

    For rounds = 40 the error probability is below 2^-80, far stricter
    than what RSA needs for production use.
    """
    # Reject trivial cases.
    if n < 2:
        return False

    # Quick check against a precomputed list of small primes.
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Run `rounds` independent rounds with random witnesses in [2, n-2].
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2  # pick a in [2, n-2]
        if not _miller_rabin_round(n, a):
            return False

    return True


def generate_prime(bits):
    """
    Generate a random probable prime with exactly `bits` bits.

    Algorithm:
        1. Pick a random `bits`-bit odd number with the top bit forced to 1
           (so the result really has the requested length, not fewer bits).
        2. Quickly reject if divisible by any small prime.
        3. Run Miller-Rabin; if it passes, return.
        4. Otherwise, add 2 and try again.

    For 512-bit primes this typically takes < 1 second on a normal laptop.
    """
    if bits < 8:
        raise ValueError("Use at least 8 bits.")

    while True:
        # Random bits-bit candidate.
        candidate = secrets.randbits(bits)

        # Force the top TWO bits to 1. This guarantees that the product of
        # two such primes occupies exactly 2*bits bits (i.e. an n-bit RSA
        # modulus really has n bits, not n-1).
        candidate |= (1 << (bits - 1))
        if bits >= 2:
            candidate |= (1 << (bits - 2))

        # Force the least significant bit to 1 -> odd.
        candidate |= 1

        # Try a small batch of consecutive odd candidates before giving up.
        for _ in range(bits * 2):
            if _passes_small_prime_filter(candidate):
                if is_probable_prime(candidate):
                    return candidate
            candidate += 2


def _passes_small_prime_filter(n):
    """Quick rejection: divisible by any small prime (except itself)?"""
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    return True


def generate_distinct_primes(bits):
    """
    Generate two distinct primes p, q each of the given bit length.
    Used by RSA key generation.
    """
    p = generate_prime(bits)
    while True:
        q = generate_prime(bits)
        if q != p:
            return p, q
