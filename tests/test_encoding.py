"""Tests for encoding/encoding_utils.py."""

import unittest

from encoding.encoding_utils import (
    utf8_encode, utf8_decode,
    to_hex, from_hex,
    to_base64, from_base64,
)

class TestEncoding(unittest.TestCase):
    def test_utf8_roundtrip(self):
        for s in ["hello", "Café crème", "日本語", "🔐 secure"]:
            self.assertEqual(utf8_decode(utf8_encode(s)), s)

    def test_hex_roundtrip(self):
        for data in [b"", b"\x00", b"\xde\xad\xbe\xef", bytes(range(256))]:
            self.assertEqual(from_hex(to_hex(data)), data)

    def test_base64_roundtrip(self):
        for data in [b"", b"a", b"AES key bytes", bytes(range(256))]:
            self.assertEqual(from_base64(to_base64(data)), data)

    def test_invalid_base64_rejected(self):
        with self.assertRaises(Exception):
            from_base64("not valid base64!")

if __name__ == "__main__":
    unittest.main(verbosity=2)
