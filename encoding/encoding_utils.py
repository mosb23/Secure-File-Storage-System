"""
Encoding Utilities
==================

Encrypted data is binary. To display it on a web page or store it in a
text file, we must encode it as a printable string. This module provides
convenient wrappers around three universal encodings:

    * UTF-8        -- text <-> bytes
    * Hex          -- bytes <-> ASCII hex string
    * Base64       -- bytes <-> ASCII base64 string

We allow the use of Python's built-in `base64` and `binascii` modules
because they are general-purpose ENCODING utilities, not cryptographic
libraries. They do not perform any encryption.

Where each encoding is used in this project
-------------------------------------------
    * UTF-8  : reading/writing text files; converting user-typed strings
               into bytes before AES encryption.
    * Hex    : compactly displaying short binary values (AES key, IV) in
               the web UI so a student can verify the bytes.
    * Base64 : compactly representing long binary blobs (encrypted file
               contents, RSA-wrapped AES key) for download/upload.
"""

import base64


# ---------------------------------------------------------------------------
# UTF-8 helpers
# ---------------------------------------------------------------------------

def utf8_encode(text):
    """Convert a Python str into UTF-8 bytes."""
    if not isinstance(text, str):
        raise TypeError("utf8_encode expects a str.")
    return text.encode("utf-8")


def utf8_decode(data):
    """Decode UTF-8 bytes back into a Python str."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("utf8_decode expects bytes.")
    return data.decode("utf-8")


# ---------------------------------------------------------------------------
# Hex helpers
# ---------------------------------------------------------------------------

def to_hex(data):
    """Bytes -> uppercase-friendly hex string (lowercase digits)."""
    return data.hex()


def from_hex(hex_string):
    """Hex string -> bytes. Whitespace is ignored."""
    cleaned = "".join(hex_string.split())
    return bytes.fromhex(cleaned)


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------

def to_base64(data):
    """Bytes -> Base64 ASCII string."""
    return base64.b64encode(data).decode("ascii")


def from_base64(b64_string):
    """Base64 string -> bytes."""
    return base64.b64decode(b64_string)
