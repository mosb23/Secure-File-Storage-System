"""
AES-128 Key Expansion
=====================

AES-128 uses a 16-byte (128-bit) cipher key, but the actual encryption
needs 11 separate "round keys" (one for the initial AddRoundKey and one
per round, for 10 rounds total). The key expansion deterministically
derives these 11 round keys from the original key.

Output:
    expand_key(key) returns a list of 11 round keys.
    Each round key is itself a list of 16 bytes (one 4x4 byte state).

Algorithm (AES-128 only, Nk = 4, Nr = 10):

    The 16-byte key is treated as 4 "words" w[0..3] of 4 bytes each.
    The expansion produces 44 words w[0..43]:
        * For i < 4: w[i] = the original key word.
        * For i >= 4:
            temp = w[i-1]
            if i mod 4 == 0:
                temp = SubWord( RotWord(temp) ) XOR Rcon[i/4]
            w[i] = w[i-4] XOR temp

Where:
    RotWord([a,b,c,d]) = [b,c,d,a]            -- cyclic left rotate
    SubWord([a,b,c,d]) = [S[a], S[b], S[c], S[d]]  -- apply AES S-box
    Rcon[j]            = (rcon_byte[j], 0, 0, 0)
"""

from aes.sbox import S_BOX, RCON


def _rot_word(word):
    """Cyclic left rotation of a 4-byte word."""
    return [word[1], word[2], word[3], word[0]]


def _sub_word(word):
    """Apply the AES S-box byte-by-byte."""
    return [S_BOX[b] for b in word]


def expand_key(key):
    """
    Expand a 16-byte AES-128 key into a list of 11 round keys
    (each round key is a list of 16 bytes).
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")

    # Work in 4-byte word units. w is a list of 44 words.
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]  # w[0..3]

    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = _sub_word(_rot_word(temp))
            temp[0] ^= RCON[i // 4]
        new_word = [w[i - 4][j] ^ temp[j] for j in range(4)]
        w.append(new_word)

    # Group the 44 words into 11 round keys of 16 bytes each.
    round_keys = []
    for r in range(11):
        rk = []
        for j in range(4):
            rk.extend(w[r * 4 + j])
        round_keys.append(rk)

    return round_keys
