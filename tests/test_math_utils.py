"""
Unit tests for rsa/math_utils.py

These tests verify the four number-theoretic primitives that RSA depends on:
    gcd, egcd, modinv, mod_exp

Note on `pow(a, b, m)`:
    The project rules forbid using Python's built-in `pow(a, b, m)` in the
    cryptographic implementation itself.
    We are allowed to use it HERE inside tests as an independent oracle
    to cross-check that our hand-written mod_exp returns the correct value.
"""

import random
import unittest

from rsa.math_utils import gcd, egcd, modinv, mod_exp

class TestGCD(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(gcd(54, 24), 6)
        self.assertEqual(gcd(17, 31), 1)
        self.assertEqual(gcd(100, 75), 25)
        self.assertEqual(gcd(0, 5), 5)
        self.assertEqual(gcd(5, 0), 5)

    def test_negative_inputs(self):
        self.assertEqual(gcd(-54, 24), 6)
        self.assertEqual(gcd(54, -24), 6)
        self.assertEqual(gcd(-54, -24), 6)

    def test_large_numbers(self):
        a = 12345678901234567890
        b = 98765432109876543210
        g = gcd(a, b)
        self.assertGreater(g, 0)
        self.assertEqual(a % g, 0)
        self.assertEqual(b % g, 0)

class TestEGCD(unittest.TestCase):
    def test_bezout_identity(self):
        """For every (a, b), egcd must return (g, x, y) with a*x + b*y == g."""
        cases = [(30, 18), (17, 31), (240, 46), (1, 1), (123456, 7891)]
        for a, b in cases:
            g, x, y = egcd(a, b)
            self.assertEqual(a * x + b * y, g,
                             f"Bezout failed for ({a}, {b})")
            self.assertEqual(g, gcd(a, b),
                             f"egcd gcd mismatch for ({a}, {b})")

    def test_random_pairs(self):
        random.seed(42)
        for _ in range(200):
            a = random.randint(1, 10**6)
            b = random.randint(1, 10**6)
            g, x, y = egcd(a, b)
            self.assertEqual(a * x + b * y, g)
            self.assertEqual(g, gcd(a, b))

class TestModInv(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(modinv(3, 11), 4)
        self.assertEqual(modinv(7, 26), 15)
        self.assertEqual(modinv(17, 3120), 2753)

    def test_inverse_property(self):
        """modinv(a, m) must satisfy (a * inv) mod m == 1 whenever it exists."""
        random.seed(123)
        for _ in range(100):
            m = random.randint(2, 10**6)
            a = random.randint(1, m - 1)
            if gcd(a, m) != 1:
                continue
            inv = modinv(a, m)
            self.assertEqual((a * inv) % m, 1)

    def test_raises_when_not_coprime(self):
        with self.assertRaises(ValueError):
            modinv(6, 9)

class TestModExp(unittest.TestCase):
    def test_small_known_values(self):
        self.assertEqual(mod_exp(7, 13, 19), pow(7, 13, 19))
        self.assertEqual(mod_exp(2, 10, 1000), 24)
        self.assertEqual(mod_exp(0, 5, 7), 0)
        self.assertEqual(mod_exp(5, 0, 7), 1)
        self.assertEqual(mod_exp(123, 1, 100), 23)
        self.assertEqual(mod_exp(10, 5, 1), 0)

    def test_matches_builtin_pow(self):
        """Cross-check against Python's built-in pow as an oracle."""
        random.seed(7)
        for _ in range(200):
            base = random.randint(0, 10**6)
            exp = random.randint(0, 1000)
            mod = random.randint(1, 10**6)
            self.assertEqual(mod_exp(base, exp, mod), pow(base, exp, mod))

    def test_rsa_scale_numbers(self):
        """Test with numbers in the RSA size range (~1024 bits)."""
        random.seed(99)
        for _ in range(5):
            base = random.getrandbits(1024)
            exp = random.getrandbits(1024)
            mod = random.getrandbits(1024) | 1
            self.assertEqual(mod_exp(base, exp, mod), pow(base, exp, mod))

    def test_rsa_round_trip(self):
        """
        Mini end-to-end RSA-style check using our four primitives:
            * choose small primes p, q
            * n = p*q, phi = (p-1)*(q-1)
            * pick e coprime with phi, compute d = modinv(e, phi)
            * verify: (m^e)^d mod n == m
        This is the whole point of these utilities.
        """
        p, q = 61, 53
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 17
        self.assertEqual(gcd(e, phi), 1)
        d = modinv(e, phi)

        for m in [0, 1, 2, 42, 123, n - 1]:
            c = mod_exp(m, e, n)
            recovered = mod_exp(c, d, n)
            self.assertEqual(recovered, m,
                             f"RSA round-trip failed for m={m}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
