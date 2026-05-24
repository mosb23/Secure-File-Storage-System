"""Tests for rsa/prime.py (Miller-Rabin + prime generation)."""

import unittest

from rsa.prime import is_probable_prime, generate_prime

class TestMillerRabin(unittest.TestCase):
    def test_known_primes(self):
        known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 97, 101,
                        7919, 104729, 1000003, 2_147_483_647]
        for p in known_primes:
            self.assertTrue(is_probable_prime(p), f"{p} should be prime")

    def test_known_composites(self):
        known_composites = [0, 1, 4, 6, 8, 9, 10, 15, 21, 25, 49, 100,
                            1001, 1024, 1_000_000, 1_234_567]
        for n in known_composites:
            self.assertFalse(is_probable_prime(n), f"{n} should be composite")

    def test_carmichael_numbers_rejected(self):
        carmichaels = [561, 1105, 1729, 2465, 2821, 6601, 8911]
        for c in carmichaels:
            self.assertFalse(is_probable_prime(c), f"Carmichael {c} should be composite")

class TestGeneratePrime(unittest.TestCase):
    def test_small_size(self):
        p = generate_prime(64)
        self.assertEqual(p.bit_length(), 64)
        self.assertTrue(is_probable_prime(p))

    def test_medium_size(self):
        p = generate_prime(128)
        self.assertEqual(p.bit_length(), 128)
        self.assertTrue(is_probable_prime(p))

if __name__ == "__main__":
    unittest.main(verbosity=2)
