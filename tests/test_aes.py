"""Tests for the AES module (sbox, block cipher, CBC mode)."""

import unittest

from aes.sbox import S_BOX, INV_S_BOX, gf_mul, gf_inv
from aes.aes_core import aes_encrypt_block, aes_decrypt_block
from aes.modes import (
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    pkcs7_pad,
    pkcs7_unpad,
    generate_aes_key,
    generate_iv,
)


class TestGF(unittest.TestCase):
    def test_gf_mul_known_values(self):
        self.assertEqual(gf_mul(0x57, 0x83), 0xC1)  # AES spec example
        self.assertEqual(gf_mul(0x00, 0xFF), 0x00)
        self.assertEqual(gf_mul(0x01, 0xAB), 0xAB)
        self.assertEqual(gf_mul(0x02, 0x80), 0x1B)

    def test_gf_inv_roundtrip(self):
        for a in range(1, 256):
            self.assertEqual(gf_mul(a, gf_inv(a)), 1)
        self.assertEqual(gf_inv(0), 0)


class TestSBox(unittest.TestCase):
    def test_known_entries(self):
        self.assertEqual(S_BOX[0x00], 0x63)
        self.assertEqual(S_BOX[0x53], 0xED)
        self.assertEqual(S_BOX[0xFF], 0x16)

    def test_sbox_is_a_bijection(self):
        self.assertEqual(sorted(S_BOX), list(range(256)))

    def test_inverse_sbox(self):
        for i in range(256):
            self.assertEqual(INV_S_BOX[S_BOX[i]], i)


class TestAESBlock(unittest.TestCase):
    def test_nist_vector(self):
        """Standard NIST AES-128 test vector (FIPS 197 Appendix B)."""
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(aes_encrypt_block(plaintext, key), expected)
        self.assertEqual(aes_decrypt_block(expected, key), plaintext)

    def test_fips_appendix_a_key(self):
        """Another well-known vector from FIPS 197 examples."""
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(aes_encrypt_block(plaintext, key), expected)
        self.assertEqual(aes_decrypt_block(expected, key), plaintext)


class TestPKCS7(unittest.TestCase):
    def test_padding_lengths(self):
        self.assertEqual(pkcs7_pad(b""),
                         b"\x10" * 16)
        self.assertEqual(pkcs7_pad(b"A"), b"A" + b"\x0f" * 15)
        self.assertEqual(pkcs7_pad(b"A" * 16),
                         b"A" * 16 + b"\x10" * 16)

    def test_roundtrip(self):
        for n in [0, 1, 15, 16, 17, 31, 32, 33, 100, 1024]:
            data = bytes(range(256))[:n] if n <= 256 else bytes(n)
            self.assertEqual(pkcs7_unpad(pkcs7_pad(data)), data)

    def test_corrupted_padding_rejected(self):
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"A" * 16)  # last byte 'A' would mean 65 bytes padding


class TestAESCBC(unittest.TestCase):
    def test_roundtrip_various_sizes(self):
        key = generate_aes_key()
        iv = generate_iv()
        for n in [0, 1, 15, 16, 17, 100, 1000, 4096]:
            data = bytes((i * 7 + 3) & 0xFF for i in range(n))
            cipher = aes_cbc_encrypt(data, key, iv)
            self.assertEqual(aes_cbc_decrypt(cipher, key, iv), data)
            self.assertEqual(len(cipher) % 16, 0)

    def test_different_iv_gives_different_ciphertext(self):
        key = generate_aes_key()
        data = b"Same plaintext"
        c1 = aes_cbc_encrypt(data, key, generate_iv())
        c2 = aes_cbc_encrypt(data, key, generate_iv())
        self.assertNotEqual(c1, c2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
