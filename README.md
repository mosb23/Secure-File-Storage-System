# 🔐 Secure File Storage System

## 📌 Project Overview

This project is a Python and Flask secure file storage demo that implements a
hybrid cryptosystem from scratch.

The system uses:

- 🔑 RSA to generate public/private keys and encrypt the AES session key.
- 🧊 AES-128-CBC to encrypt the uploaded file data.
- 🔁 Base64, Hex, UTF-8, and JSON to make encrypted binary data displayable and
  transferable.
- 🖥️ A simple web UI to demonstrate key generation, file encryption, encrypted
  bundle download, bundle decryption, and recovered file download.

No external cryptography libraries are used. The AES, RSA, prime generation,
key schedule, and modular exponentiation logic are implemented manually for the
course requirement.

## 🏢 Business Scenario

The selected business model is a Secure File Storage System.

1. A user uploads a private file.
2. The application generates a unique AES-128 session key for that file.
3. The file is encrypted using AES in CBC mode.
4. The AES session key is encrypted using the user's RSA public key.
5. The encrypted file, encrypted AES key, IV, and metadata are stored together
   in a downloadable `.enc.txt` bundle.
6. During decryption, the RSA private key recovers the AES key, and the AES key
   decrypts the original file.

This demonstrates realistic hybrid encryption: AES protects the actual file
contents, while RSA protects the AES key.

## ✅ Requirements Compliance

| Requirement | Implementation |
| --- | --- |
| AES full rounds | `aes/aes_core.py` implements AES-128 block encryption and decryption with 10 rounds. |
| Key expansion | `aes/key_expansion.py` expands a 16-byte AES key into 11 round keys. |
| SubBytes | `aes/aes_core.py` uses the generated AES S-box from `aes/sbox.py`. |
| ShiftRows | `aes/aes_core.py` implements ShiftRows and inverse ShiftRows. |
| MixColumns | `aes/aes_core.py` implements MixColumns and inverse MixColumns over GF(2^8). |
| AddRoundKey | `aes/aes_core.py` XORs each round key into the AES state. |
| AES-128 | `aes/modes.py` generates 16-byte AES-128 session keys. |
| CBC mode | `aes/modes.py` implements AES-CBC with PKCS#7 padding. |
| RSA prime generation | `rsa/prime.py` implements Miller-Rabin probable-prime generation. |
| RSA key generation | `rsa/rsa_core.py` generates public and private RSA keypairs. |
| RSA encryption/decryption | `rsa/rsa_core.py` supports integer RSA and byte-wrapper RSA for AES keys. |
| Manual modular exponentiation | `rsa/math_utils.py` implements repeated-squaring modular exponentiation. |
| No `pow(a, b, m)` in implementation | The implementation uses `mod_exp`; tests use `pow` only as an independent oracle. |
| Hybrid cryptosystem | `hybrid/hybrid_crypto.py` combines RSA key wrapping with AES file encryption. |
| Encoding scheme | `encoding/encoding_utils.py` supports UTF-8, Hex, and Base64. |
| UI demonstration | `ui/app.py` and `ui/templates/` provide the web workflow. |

## 📁 Project Structure

```text
secure-file-storage-system/
|-- main.py
|-- requirements.txt
|-- README.md
|-- aes/
|   |-- aes_core.py
|   |-- key_expansion.py
|   |-- modes.py
|   `-- sbox.py
|-- rsa/
|   |-- math_utils.py
|   |-- prime.py
|   `-- rsa_core.py
|-- hybrid/
|   `-- hybrid_crypto.py
|-- encoding/
|   `-- encoding_utils.py
|-- ui/
|   |-- app.py
|   |-- static/
|   `-- templates/
|-- tests/
|-- uploads/
|-- encrypted/
`-- decrypted/
```

## 🧩 AES Implementation

The AES implementation is located in the `aes/` package.

`aes/sbox.py` implements finite-field arithmetic over GF(2^8), builds the AES
S-box, builds the inverse S-box, and generates RCON values.

`aes/key_expansion.py` implements the AES-128 key schedule:

```text
Input key: 16 bytes
Words: 44
Round keys: 11
Rounds: 10
```

`aes/aes_core.py` implements the AES block cipher:

```text
Initial AddRoundKey
Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey
Round 10: SubBytes, ShiftRows, AddRoundKey
```

`aes/modes.py` implements CBC mode with PKCS#7 padding:

```text
C0 = AES_Encrypt(P0 XOR IV)
Ci = AES_Encrypt(Pi XOR C(i-1))

P0 = AES_Decrypt(C0) XOR IV
Pi = AES_Decrypt(Ci) XOR C(i-1)
```

Each uploaded file receives a fresh random AES key and a fresh random IV.

## 🔏 RSA Implementation

The RSA implementation is located in the `rsa/` package.

`rsa/math_utils.py` implements:

- Greatest common divisor using the Euclidean algorithm.
- Extended Euclidean algorithm.
- Modular inverse.
- Manual modular exponentiation using repeated squaring.

`rsa/prime.py` implements:

- Random odd candidate generation with the requested bit length.
- Small-prime filtering.
- Miller-Rabin primality testing.
- Distinct prime generation for RSA.

`rsa/rsa_core.py` implements RSA key generation:

```text
p, q = generated distinct primes
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = modular inverse of e modulo phi
```

Public key:

```python
{"n": n, "e": e}
```

Private key:

```python
{"n": n, "d": d, "p": p, "q": q}
```

RSA encryption and decryption use:

```text
c = m^e mod n
m = c^d mod n
```

The implementation does not call Python's built-in `pow(a, b, m)` in the
application code.

## 🔄 Hybrid Cryptosystem Workflow

The hybrid implementation is located in `hybrid/hybrid_crypto.py`.

Encryption:

```text
1. Generate a random AES-128 session key.
2. Generate a random 16-byte IV.
3. Encrypt the uploaded file using AES-128-CBC.
4. Encrypt the AES session key using the RSA public key.
5. Save encrypted_key, IV, ciphertext, and metadata in a JSON bundle.
```

Decryption:

```text
1. Read the encrypted JSON bundle.
2. Decode the Base64 fields back into bytes.
3. Decrypt the AES session key using the RSA private key.
4. Decrypt the ciphertext using AES-128-CBC.
5. Save and download the recovered original file.
```

## 🧾 Encoding Scheme

Encrypted data is binary, so it cannot always be displayed directly in a web
page or safely stored inside a text file. This project uses three encodings:

| Encoding | Where used | Reason |
| --- | --- | --- |
| UTF-8 | Text input, JSON files, and readable metadata | Converts text to bytes and bytes back to text. |
| Hex | AES key and IV display in the UI | Compact and easy to inspect for short binary values. |
| Base64 | RSA-encrypted AES key, IV, and ciphertext inside the bundle | Converts encrypted binary data into transferable text. |

The encrypted bundle is a JSON text file with Base64 fields:

```json
{
  "version": 1,
  "business_model": "Secure File Storage System",
  "algorithms": {
    "file_encryption": "AES-128-CBC",
    "padding": "PKCS#7",
    "key_wrap": "RSA length-prefixed educational key wrap",
    "encoding": "JSON fields with Base64 binary values"
  },
  "rsa_public": {
    "bits": 1024,
    "n_hex": "0x...",
    "e": 65537
  },
  "original_name": "example.txt",
  "encrypted_key_b64": "...",
  "iv_b64": "...",
  "ciphertext_b64": "..."
}
```

## 🌐 Web UI

The Flask UI demonstrates the full business workflow.

| Page | Route | Purpose |
| --- | --- | --- |
| Home | `/` | Shows the secure file storage scenario and hybrid workflow. |
| RSA Keys | `/keys` | Shows the active RSA keypair and allows key regeneration. |
| Encrypt | `/encrypt` | Uploads and encrypts a file. |
| Encryption Result | `/encrypt` after POST | Shows AES key, IV, encrypted AES key, ciphertext preview, and bundle download. |
| Decrypt | `/decrypt` | Uploads an encrypted bundle. |
| Decryption Result | `/decrypt` after POST | Shows recovered file information and download link. |

## 🚀 How to Run

Create and activate a virtual environment:

```powershell
python -m venv venv
venv\Scripts\activate
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the app:

```powershell
python main.py
```

Open the browser at:

```text
http://127.0.0.1:5000
```

## 🧪 How to Test

Run:

```powershell
python -m unittest discover -s tests -v
```

Latest verification:

```text
Ran 50 tests
OK
```

The tests cover AES vectors, CBC round trips, PKCS#7 padding, RSA math,
Miller-Rabin prime generation, RSA encryption/decryption, hybrid encryption,
encoding helpers, and Flask route behavior.

## 🎬 Demo Steps

1. Start the Flask app with `python main.py`.
2. Open `/keys` and generate or view the RSA keypair.
3. Open `/encrypt` and upload a file.
4. Download the generated `.enc.txt` encrypted bundle.
5. Open the bundle to show the JSON and Base64 encoded encrypted values.
6. Open `/decrypt` and upload the `.enc.txt` bundle.
7. Download the recovered original file.

## 🎓 Educational Scope

This is a university cryptography project built to demonstrate AES, RSA, and a
hybrid cryptosystem clearly. The UI displays internal values such as the AES
key and RSA private components so the encryption workflow can be inspected
during evaluation.

For a production system, additional protections such as authenticated
encryption, RSA-OAEP, persistent key storage, user authentication, access
control, and stronger operational security would be required.

## 👥 Authors

University Cryptography Project Team

Course: Data Security / Cryptography

Project: RSA and AES Hybrid Cryptosystem - Secure File Storage System
