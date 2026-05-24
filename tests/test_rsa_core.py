"""Tests for rsa/rsa_core.py (key generation, encrypt, decrypt)."""

import unittest

from rsa.rsa_core import (
    generate_keypair,
    rsa_encrypt_int,
    rsa_decrypt_int,
    rsa_encrypt_bytes,
    rsa_decrypt_bytes,
)
from rsa.math_utils import gcd

class TestRSAKeyGeneration(unittest.TestCase):
    def test_modulus_size(self):
        pub, priv = generate_keypair(512)
        self.assertEqual(pub["n"].bit_length(), 512)
        self.assertEqual(pub["n"], priv["n"])

    def test_keys_are_inverses(self):
        pub, priv = generate_keypair(512)
        e, d = pub["e"], priv["d"]
        phi = (priv["p"] - 1) * (priv["q"] - 1)
        self.assertEqual((e * d) % phi, 1)
        self.assertEqual(gcd(e, phi), 1)

class TestRSAIntegerEncryptionRoundTrip(unittest.TestCase):
    def test_roundtrip_various_messages(self):
        pub, priv = generate_keypair(512)
        for m in [0, 1, 2, 42, 1234567, pub["n"] - 1]:
            c = rsa_encrypt_int(m, pub)
            self.assertEqual(rsa_decrypt_int(c, priv), m)

class TestRSABytesEncryptionRoundTrip(unittest.TestCase):
    def test_roundtrip_aes_key_sized_data(self):
        pub, priv = generate_keypair(1024)

        data = b"\x00\x01\x02\x03\x04\x05\x06\x07" \
               b"\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
        cipher = rsa_encrypt_bytes(data, pub)
        self.assertEqual(rsa_decrypt_bytes(cipher, priv), data)

    def test_roundtrip_various_lengths(self):
        pub, priv = generate_keypair(1024)
        for n in [1, 5, 16, 32, 64]:
            data = bytes(range(n))
            cipher = rsa_encrypt_bytes(data, pub)
            self.assertEqual(rsa_decrypt_bytes(cipher, priv), data)

if __name__ == "__main__":
    unittest.main(verbosity=2)
