# RSA & AES Hybrid Cryptosystem — Secure File Storage System

## Project Overview

This project is a university cryptography project that demonstrates a complete hybrid cryptosystem using:

- RSA for asymmetric encryption
- AES-128 for symmetric encryption
- Flask for the educational user interface

The system simulates a secure file storage platform where:

1. A file is encrypted using AES
2. The AES session key is encrypted using RSA
3. Only the RSA private key owner can decrypt the AES key
4. The original file can then be recovered securely

---

# Educational Goal

The main goal of this project is educational clarity.

Everything is implemented manually from scratch to understand the internal mathematics and cryptographic workflow behind modern secure systems.

This project intentionally avoids external cryptography libraries.

---

# Important Rules

## Forbidden Libraries / APIs

The following are NOT allowed:

- pycryptodome
- cryptography
- OpenSSL
- Crypto++
- javax.crypto
- Fernet
- RSA.generate()
- Cipher.AES
- pow(a, b, m)

All algorithms must be implemented manually.

---

# Technologies Used

| Component | Technology |
|---|---|
| Programming Language | Python 3.11+ |
| Backend/UI | Flask |
| Frontend | HTML + CSS + Jinja |
| IDE | Visual Studio Code |
| Environment | Python venv |

---

# Current Project Status

## Completed

### STEP 1 — Environment Setup & Project Initialization

Completed tasks:

- Python environment setup
- Virtual environment creation
- Flask installation
- Professional project architecture
- Folder structure initialization
- Flask application initialization
- Git initialization
- requirements.txt generation

---

# Why We Started With Architecture First

Cryptography projects become difficult to debug if everything is written at once.

Professional systems are built in stages:

1. Environment setup
2. Architecture design
3. Mathematical foundations
4. Core cryptographic algorithms
5. Integration
6. UI
7. Testing

This modular structure helps:

- debugging
- testing
- teamwork
- scalability
- educational understanding

---

# Project Structure

```text
secure-file-storage-system/
│
├── rsa/
│   ├── __init__.py
│   ├── prime.py
│   ├── math_utils.py
│   ├── rsa_core.py
│
├── aes/
│   ├── __init__.py
│   ├── sbox.py
│   ├── key_expansion.py
│   ├── aes_core.py
│   ├── modes.py
│
├── hybrid/
│   ├── __init__.py
│   ├── hybrid_crypto.py
│
├── encoding/
│   ├── __init__.py
│   ├── encoding_utils.py
│
├── ui/
│   ├── app.py
│   ├── templates/
│   ├── static/
│
├── uploads/
├── encrypted/
├── decrypted/
│
├── tests/
│
├── README.md
├── requirements.txt
└── main.py
```

---

# Module Responsibilities

## RSA Module

Responsible for:

- Prime generation
- GCD
- Extended Euclidean Algorithm
- Modular inverse
- Modular exponentiation
- RSA key generation
- RSA encryption/decryption

Files:

```text
rsa/
```

---

## AES Module

Responsible for:

- AES finite field mathematics
- AES transformations
- Key expansion
- CBC mode

Files:

```text
aes/
```

---

## Hybrid Module

Responsible for combining:

- RSA
- AES
- session key exchange

This simulates real-world hybrid cryptosystems.

Files:

```text
hybrid/
```

---

## Encoding Module

Responsible for:

- UTF-8 encoding
- Base64 encoding
- Hexadecimal conversion

This is necessary because encrypted data is binary.

Files:

```text
encoding/
```

---

## UI Module

Responsible for:

- Flask application
- File uploads
- Encryption/decryption pages
- Workflow visualization

Files:

```text
ui/
```

---

# Current Flask Test

The project currently contains a minimal Flask app to verify environment setup.

Run:

```bash
python main.py
```

Open:

```text
http://127.0.0.1:5000
```

Expected output:

```text
RSA & AES Hybrid Cryptosystem Project
```

---

# Setup Instructions

## 1) Clone Project

```bash
git clone <repository-url>
cd secure-file-storage-system
```

---

## 2) Create Virtual Environment

### Windows

```powershell
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS

```bash
python -m venv venv
source venv/bin/activate
```

---

## 3) Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4) Run Project

```bash
python main.py
```

---

# Planned Implementation Roadmap

## STEP 2 — RSA Mathematics Utilities

Implement manually:

- GCD
- Extended Euclidean Algorithm
- Modular inverse
- Manual modular exponentiation

---

## STEP 3 — Prime Generation

Implement:

- Random large number generation
- Miller-Rabin primality testing
- Large prime generation

---

## STEP 4 — Modular Exponentiation

Implement repeated squaring manually.

IMPORTANT:

We are NOT allowed to use:

```python
pow(a, b, m)
```

---

## STEP 5 — RSA Key Generation

Implement:

- p and q generation
- modulus n
- Euler’s Totient
- public exponent
- private exponent

---

## STEP 6 — RSA Encryption/Decryption

Implement:

- RSA encryption
- RSA decryption
- integer conversion handling

---

## STEP 7 — AES Finite Field Mathematics

Implement:

- GF(2^8) arithmetic
- XOR operations
- Rijndael finite field operations

---

## STEP 8 — AES Transformations

Implement manually:

- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey

---

## STEP 9 — AES Key Expansion

Implement:

- round constants
- word rotation
- S-box substitution
- round key generation

---

## STEP 10 — AES CBC Mode

Implement:

- Initialization Vector (IV)
- block chaining
- PKCS#7 padding

---

## STEP 11 — Hybrid Integration

Workflow:

1. Generate AES session key
2. Encrypt file using AES
3. Encrypt AES key using RSA
4. Store encrypted file + encrypted key + IV

---

## STEP 12 — Flask UI

Add pages for:

- RSA key generation
- File upload
- Encrypt/decrypt actions
- Result visualization

---

## STEP 13 — File Encryption Workflow

Implement complete secure file storage process.

---

## STEP 14 — Testing & Validation

Test:

- RSA correctness
- AES correctness
- Hybrid correctness
- edge cases

---

## STEP 15 — Final Documentation

Prepare:

- README
- screenshots
- final report
- workflow explanation

---

# Team Distribution

| Member | Responsibility |
|---|---|
| Member 1 | RSA implementation |
| Member 2 | AES core implementation |
| Member 3 | AES modes + encoding |
| Member 4 | Hybrid integration |
| Member 5 | UI + testing + documentation |

---

# Security Notes

This project is for educational purposes.

Although the algorithms are real, production-grade cryptographic systems require:

- security audits
- side-channel protection
- constant-time operations
- secure random number generation
- hardened implementations

This project focuses on understanding cryptographic principles.

---

# Learning Objectives

By completing this project, the team should understand:

- Number theory behind RSA
- Finite field mathematics behind AES
- Symmetric vs asymmetric encryption
- Hybrid cryptosystems
- Secure key exchange
- Binary encoding techniques
- Cryptographic architecture

---

# Future Improvements

Possible future upgrades:

- 2048-bit RSA
- Digital signatures
- OAEP padding
- GCM mode
- User authentication
- Database integration
- File metadata encryption

---

# Authors

University Cryptography Project Team

Course:
Data Security / Cryptography

Project:
RSA & AES Hybrid Cryptosystem — Secure File Storage System