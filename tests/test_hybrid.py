"""Tests for hybrid/hybrid_crypto.py (RSA + AES end-to-end)."""

import os
import unittest

from rsa.rsa_core import generate_keypair
from hybrid.hybrid_crypto import hybrid_encrypt, hybrid_decrypt

class TestHybrid(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public_key, cls.private_key = generate_keypair(512)

    def test_text_roundtrip(self):
        message = b"The quick brown fox jumps over the lazy dog."
        bundle = hybrid_encrypt(message, self.public_key)
        self.assertEqual(hybrid_decrypt(bundle, self.private_key), message)

    def test_empty_file_roundtrip(self):
        message = b""
        bundle = hybrid_encrypt(message, self.public_key)
        self.assertEqual(hybrid_decrypt(bundle, self.private_key), message)

    def test_binary_blob_roundtrip(self):
        message = os.urandom(4096)
        bundle = hybrid_encrypt(message, self.public_key)
        self.assertEqual(hybrid_decrypt(bundle, self.private_key), message)

    def test_ciphertext_block_aligned(self):
        message = b"abc"
        bundle = hybrid_encrypt(message, self.public_key)
        self.assertEqual(len(bundle["ciphertext"]) % 16, 0)
        self.assertEqual(len(bundle["iv"]), 16)
        self.assertEqual(len(bundle["aes_key"]), 16)

    def test_two_encryptions_differ(self):
        message = b"deterministic input"
        b1 = hybrid_encrypt(message, self.public_key)
        b2 = hybrid_encrypt(message, self.public_key)

        self.assertNotEqual(b1["ciphertext"], b2["ciphertext"])
        self.assertNotEqual(b1["encrypted_key"], b2["encrypted_key"])

        self.assertEqual(hybrid_decrypt(b1, self.private_key), message)
        self.assertEqual(hybrid_decrypt(b2, self.private_key), message)

if __name__ == "__main__":
    unittest.main(verbosity=2)
