"""
Hybrid Cryptosystem (RSA + AES)
================================

This module combines our hand-written RSA and AES implementations into
the workflow used by real secure systems:

    Encryption (sender side, knows recipient's public RSA key):
        1. Generate a random AES-128 session key K.
        2. Generate a random 16-byte IV.
        3. Ciphertext_AES = AES-CBC-Encrypt(plaintext, K, IV).
        4. Encrypted_Key  = RSA-Encrypt(K, public_key).
        5. Send/store the bundle: (Encrypted_Key, IV, Ciphertext_AES).

    Decryption (receiver side, owns the private RSA key):
        1. K = RSA-Decrypt(Encrypted_Key, private_key).
        2. plaintext = AES-CBC-Decrypt(Ciphertext_AES, K, IV).

Why hybrid?
-----------
    * RSA is slow and can only encrypt small messages (smaller than its
      modulus). Encrypting a multi-megabyte file with RSA would take
      hours.
    * AES is extremely fast and works on data of any size, but both
      parties need to share the same secret key in advance.
    * Hybrid encryption gives us the best of both worlds: we use AES
      for the bulk data and RSA only to safely transport the AES key.

This is exactly how HTTPS, PGP, and most modern secure messaging
protocols work conceptually.
"""

from aes.modes import (
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    generate_aes_key,
    generate_iv,
)
from rsa.rsa_core import rsa_encrypt_bytes, rsa_decrypt_bytes

def hybrid_encrypt(plaintext, public_key):
    """
    Encrypt arbitrary bytes using the hybrid RSA+AES scheme.

    Args:
        plaintext:   the bytes to protect.
        public_key:  dict with keys "n" and "e".

    Returns:
        dict with three byte fields:
            "encrypted_key": RSA-encrypted AES session key
            "iv":            16-byte IV (random per message)
            "ciphertext":    AES-CBC ciphertext of the plaintext

        Plus a debug copy of the AES key as bytes, so the UI can show it.
        (In a real product you would NOT return the AES key alongside;
        we include it because this is an educational demo.)
    """
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes.")

    aes_key = generate_aes_key()
    iv = generate_iv()

    ciphertext = aes_cbc_encrypt(bytes(plaintext), aes_key, iv)
    encrypted_key = rsa_encrypt_bytes(aes_key, public_key)

    return {
        "aes_key": aes_key,
        "encrypted_key": encrypted_key,
        "iv": iv,
        "ciphertext": ciphertext,
    }

def hybrid_decrypt(bundle, private_key):
    """
    Decrypt a hybrid bundle produced by hybrid_encrypt.

    Args:
        bundle:       dict containing "encrypted_key", "iv", "ciphertext".
        private_key:  dict with keys "n" and "d".

    Returns:
        original plaintext bytes.
    """
    required = ("encrypted_key", "iv", "ciphertext")
    for k in required:
        if k not in bundle:
            raise ValueError(f"Hybrid bundle missing field: {k}")

    aes_key = rsa_decrypt_bytes(bundle["encrypted_key"], private_key)
    plaintext = aes_cbc_decrypt(bundle["ciphertext"], aes_key, bundle["iv"])
    return plaintext
