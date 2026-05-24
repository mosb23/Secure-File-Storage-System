# RSA and AES Hybrid Cryptosystem

Secure File Storage System is an educational Python/Flask project that
implements a complete hybrid encryption workflow from scratch:

- RSA handles asymmetric key generation and wraps the AES session key.
- AES-128 handles file encryption in CBC mode with PKCS#7 padding.
- Flask provides a small browser UI for key generation, encryption, decryption,
  result inspection, and file downloads.

The project is intentionally written without external cryptography libraries so
the number theory, finite-field math, block cipher steps, and hybrid flow are
visible in the code.

Important: this is a learning project, not a production-ready secure storage
system. The algorithms are real, but several production requirements are still
missing. See "Known Gaps" and "Enhancement TODOs" below.

---

## Current Status

The first-party source code is fully wired end to end:

- RSA math utilities, Miller-Rabin prime generation, key generation, integer
  encryption/decryption, and short-byte encryption/decryption are implemented.
- AES finite-field math, S-box generation, key expansion, block encryption,
  block decryption, CBC mode, and PKCS#7 padding are implemented.
- The hybrid layer generates a random AES key and IV, encrypts arbitrary file
  bytes with AES-CBC, and wraps the AES key with RSA.
- The Flask UI can generate keys, encrypt uploaded files, download encrypted
  bundles, decrypt bundles, preview recovered text, and download recovered
  files.
- Generated filenames are sanitized, download paths are constrained to the
  output folders, and bundles include educational metadata about the business
  model, algorithms, encoding, and RSA public key used for encryption.
- The test suite currently passes.

Latest local verification:

```powershell
python -m unittest discover -s tests -v
```

Result:

```text
Ran 50 tests
OK
```

---

## Technology Stack

| Area | Technology |
| --- | --- |
| Language | Python 3.11+ |
| Web framework | Flask |
| Templates | Jinja2 |
| Frontend | HTML and CSS |
| Testing | Python `unittest` |
| Crypto libraries | None |
| Randomness | Python `secrets` module |

Dependencies are limited to Flask and its runtime packages, listed in
`requirements.txt`.

---

## Business Model

The approved scenario is a Secure File Storage System:

1. A user uploads a private file.
2. The system creates a unique AES-128 session key and IV for that one file.
3. The file bytes are encrypted with AES-CBC.
4. The AES session key is encrypted with the user's current RSA public key.
5. The system stores a transferable `.enc.txt` bundle containing the encrypted
   AES key, IV, ciphertext, and readable metadata.
6. The matching RSA private key is required to recover the AES key and decrypt
   the file.

This clearly demonstrates the required hybrid cryptosystem workflow: AES
protects the actual file data, while RSA protects the AES key.

---

## Project Structure

```text
secure-file-storage-system/
|-- .gitignore
|-- README.md
|-- main.py
|-- requirements.txt
|-- aes/
|   |-- __init__.py
|   |-- aes_core.py
|   |-- key_expansion.py
|   |-- modes.py
|   `-- sbox.py
|-- decrypted/
|   `-- .gitkeep
|-- encoding/
|   |-- __init__.py
|   `-- encoding_utils.py
|-- encrypted/
|   `-- .gitkeep
|-- hybrid/
|   |-- __init__.py
|   `-- hybrid_crypto.py
|-- rsa/
|   |-- __init__.py
|   |-- math_utils.py
|   |-- prime.py
|   `-- rsa_core.py
|-- tests/
|   |-- __init__.py
|   |-- test_aes.py
|   |-- test_encoding.py
|   |-- test_hybrid.py
|   |-- test_math_utils.py
|   |-- test_prime.py
|   |-- test_rsa_core.py
|   `-- test_ui_app.py
|-- ui/
|   |-- app.py
|   |-- static/
|   |   |-- .gitkeep
|   |   `-- style.css
|   `-- templates/
|       |-- base.html
|       |-- decrypt.html
|       |-- decrypt_result.html
|       |-- encrypt.html
|       |-- encrypt_result.html
|       |-- index.html
|       `-- keys.html
`-- uploads/
    `-- .gitkeep
```

The local `venv/` directory may exist during development, but it is ignored by
Git and is not part of the application source.

---

## File-by-File Logic

| File | Responsibility |
| --- | --- |
| `main.py` | Imports the Flask `app` from `ui.app` and runs it in debug mode when executed directly. |
| `requirements.txt` | Pins Flask and Flask runtime dependencies. |
| `.gitignore` | Ignores the virtual environment, Python caches, and generated upload/encryption/decryption artifacts while keeping `.gitkeep` placeholders. |
| `aes/__init__.py` | Re-exports the public AES helpers from the AES package. |
| `aes/sbox.py` | Implements GF(2^8) arithmetic, multiplicative inverse, AES affine transform, generated S-box, generated inverse S-box, and RCON values. |
| `aes/key_expansion.py` | Expands one 16-byte AES-128 key into 11 round keys using RotWord, SubWord, and RCON. |
| `aes/aes_core.py` | Implements AES-128 block encryption/decryption: SubBytes, ShiftRows, MixColumns, AddRoundKey, and inverse operations. |
| `aes/modes.py` | Implements PKCS#7 padding, random AES key generation, random IV generation, AES-CBC encryption, and AES-CBC decryption. |
| `rsa/__init__.py` | Re-exports the public RSA helpers from the RSA package. |
| `rsa/math_utils.py` | Implements `gcd`, `egcd`, `modinv`, and manual modular exponentiation without using `pow(a, b, m)`. |
| `rsa/prime.py` | Implements Miller-Rabin primality testing and random probable-prime generation with `secrets`. |
| `rsa/rsa_core.py` | Implements RSA key generation, raw integer encryption/decryption, and short-byte wrappers used to encrypt the AES session key. |
| `encoding/__init__.py` | Re-exports encoding helper functions. |
| `encoding/encoding_utils.py` | Converts between UTF-8 text, bytes, hex strings, and strict Base64 strings. |
| `hybrid/__init__.py` | Re-exports the hybrid encrypt/decrypt functions. |
| `hybrid/hybrid_crypto.py` | Combines AES-CBC and RSA key wrapping into one encrypt/decrypt workflow. |
| `ui/app.py` | Defines the Flask app, routes, in-memory RSA keypair, sanitized upload names, bundle metadata, bundle parsing, key mismatch checks, constrained downloads, and helper functions. |
| `ui/templates/base.html` | Shared page layout, header, navigation, flash messages, content block, and footer. |
| `ui/templates/index.html` | Home page with workflow summary, current key summary, and main action buttons. |
| `ui/templates/keys.html` | RSA key view/regeneration page. Shows public key and optionally private values. |
| `ui/templates/encrypt.html` | File upload form for encryption. |
| `ui/templates/encrypt_result.html` | Encryption output page with download link and educational display of AES key, IV, RSA-wrapped key, and ciphertext preview. |
| `ui/templates/decrypt.html` | Upload form for encrypted `.enc.txt` bundles. |
| `ui/templates/decrypt_result.html` | Decryption output page with recovered file download and optional UTF-8 text preview. |
| `ui/static/style.css` | Basic educational UI styling. |
| `tests/test_math_utils.py` | Tests RSA math primitives and cross-checks manual modular exponentiation against Python `pow` only inside tests. |
| `tests/test_prime.py` | Tests Miller-Rabin against known primes, composites, Carmichael numbers, and generated primes. |
| `tests/test_rsa_core.py` | Tests RSA key generation, integer round trips, and byte round trips. |
| `tests/test_aes.py` | Tests finite-field math, S-box properties, AES official vectors, PKCS#7, and CBC mode. |
| `tests/test_encoding.py` | Tests UTF-8, hex, Base64 round trips, and invalid Base64 rejection. |
| `tests/test_hybrid.py` | Tests end-to-end RSA + AES encryption/decryption for empty, text, and binary data. |
| `tests/test_ui_app.py` | Tests Flask encrypt/decrypt routes, bundle metadata, filename sanitization, wrong-key rejection, invalid Base64, malformed bundles, malformed RSA metadata, and path traversal rejection. |
| `uploads/.gitkeep` | Keeps the upload folder in Git. The current app reads uploads directly from memory rather than saving originals here. |
| `encrypted/.gitkeep` | Keeps the encrypted output folder in Git. Generated encrypted bundles are ignored. |
| `decrypted/.gitkeep` | Keeps the decrypted output folder in Git. Generated recovered files are ignored. |

---

## Application Flow

### Startup Flow

1. `python main.py` imports `app` from `ui.app`.
2. `ui.app` calculates the project base directory.
3. It ensures `uploads/`, `encrypted/`, and `decrypted/` exist.
4. It creates the Flask application.
5. It sets a demo Flask `secret_key` and a 16 MB upload limit.
6. The process starts the Flask development server.
7. The RSA keypair is not generated immediately; it is generated lazily on
   first access to a route that needs it.

### Key Flow

1. The first call to `get_or_create_keypair()` generates a default RSA-1024
   keypair.
2. `rsa.rsa_core.generate_keypair(bits)` generates two distinct probable
   primes, each `bits / 2` bits.
3. It computes:
   - `n = p * q`
   - `phi = (p - 1) * (q - 1)`
   - `e = 65537`
   - `d = modinv(e, phi)`
4. The public key is stored as `{"n": n, "e": e}`.
5. The private key is stored as `{"n": n, "d": d, "p": p, "q": q}`.
6. The UI stores the current keypair in the process-level `_KEYPAIR` variable.
7. Regenerating a keypair replaces the old one, so old encrypted bundles cannot
   be decrypted unless they were created with the currently active private key.

### Encryption Flow

1. User opens `/encrypt`.
2. User uploads a file.
3. Flask sanitizes the uploaded filename for safe local storage.
4. Flask reads the entire uploaded file into memory as bytes.
5. `hybrid_encrypt(plaintext, public_key)` runs:
   - Generate a random 16-byte AES session key.
   - Generate a random 16-byte IV.
   - Encrypt the file with AES-128-CBC and PKCS#7 padding.
   - Encrypt the AES key with RSA using the current public key.
6. `ui.app` serializes the encrypted data as JSON:
   - bundle version
   - business model name
   - algorithm names
   - encoding scheme
   - sanitized original file name
   - RSA public key metadata used for encryption
   - RSA-encrypted AES key as Base64
   - IV as Base64
   - ciphertext as Base64
7. The JSON is saved in `encrypted/` with a name like:

```text
<job_id>__<original_name>.enc.txt
```

8. The result page displays educational debug values:
   - AES session key in hex
   - IV in hex
   - RSA-wrapped AES key in Base64
   - bundle metadata
   - first 512 Base64 characters of ciphertext
9. User downloads the `.enc.txt` bundle.

### Decryption Flow

1. User opens `/decrypt`.
2. User uploads an encrypted `.enc.txt` bundle produced by the app.
3. Flask reads and parses the JSON bundle.
4. Base64 fields are decoded back to bytes.
5. If the bundle includes RSA public key metadata, the app checks that it
   matches the current in-memory RSA keypair before decrypting.
6. `hybrid_decrypt(bundle, private_key)` runs:
   - RSA-decrypt the encrypted AES key using the current private key.
   - AES-CBC-decrypt the ciphertext using the recovered AES key and IV.
   - Remove PKCS#7 padding.
7. The recovered plaintext is saved in `decrypted/` with a name like:

```text
<job_id>__<original_name>
```

8. If the bytes decode as UTF-8, the result page shows a preview up to 1000
   characters.
9. User downloads the recovered file.

### Download Flow

1. Download links call `/download/<kind>/<name>`.
2. `kind=encrypted` maps to the `encrypted/` folder.
3. `kind=decrypted` maps to the `decrypted/` folder.
4. The route rejects names containing path separators or attempts to escape the
   selected output directory.
5. Flask sends the selected file as an attachment.
6. `_strip_job_id()` removes the internal `<job_id>__` prefix from the visible
   download name.

---

## Encrypted Bundle Format

Although the downloaded file extension is `.enc.txt` for easy inspection in
Notepad, the contents are JSON:

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
  "encrypted_key_b64": "Base64 RSA-encrypted AES key",
  "iv_b64": "Base64 AES-CBC IV",
  "ciphertext_b64": "Base64 AES-CBC ciphertext"
}
```

The AES session key is not written into the bundle. It is displayed on the
encryption result page only for educational visibility.

Current bundle limitations:

- No timestamp.
- No message authentication code.
- No digital signature.
- No checksum of the original plaintext.
- No encrypted metadata beyond the file contents.
- The RSA public modulus is included for educational key matching, but there is
  no persistent key database or stable key ID.

---

## RSA Logic

### Math Utilities

`rsa/math_utils.py` provides the mathematical foundation:

- `gcd(a, b)` uses the Euclidean algorithm.
- `egcd(a, b)` uses the iterative extended Euclidean algorithm.
- `modinv(a, m)` returns the modular multiplicative inverse.
- `mod_exp(base, exp, mod)` performs repeated-squaring modular exponentiation.

The implementation intentionally does not call Python's built-in
`pow(a, b, m)` in cryptographic code. Tests are allowed to use `pow` as an
independent oracle.

### Prime Generation

`rsa/prime.py` creates RSA prime numbers:

1. Generate random candidate bits with `secrets.randbits`.
2. Force the top bits so the number has the requested bit length.
3. Force the lowest bit so the number is odd.
4. Reject obvious composites using small-prime division.
5. Run 40 rounds of Miller-Rabin.
6. Return the candidate when it is probably prime.

Miller-Rabin behavior:

- If the test returns composite, the number is definitely composite.
- If the test returns probably prime, the probability of a false prime after
  40 rounds is extremely small for educational use.

### Key Generation

`rsa/rsa_core.py` creates keypairs:

```text
p, q = distinct generated primes
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
d = e^(-1) mod phi
```

Public key:

```python
{"n": n, "e": e}
```

Private key:

```python
{"n": n, "d": d, "p": p, "q": q}
```

### RSA Encryption

For integer messages:

```text
c = m^e mod n
m = c^d mod n
```

For bytes, the project only needs to encrypt a short AES session key. It uses a
simple educational framing scheme:

```text
framed = zero padding || 0x00 || length || data
```

This is enough for the current 16-byte AES key use case, but it is not secure
general-purpose RSA padding. Production RSA encryption should use OAEP.

---

## AES Logic

### Finite Field and S-box

`aes/sbox.py` implements AES field operations over GF(2^8):

- Addition is XOR.
- Multiplication uses shift-and-XOR with Rijndael reduction polynomial `0x11B`.
- Inversion uses exponentiation in the finite field.
- The AES S-box is generated from the multiplicative inverse plus the AES
  affine transform.
- The inverse S-box is generated from the S-box.
- RCON values are generated for the AES-128 key schedule.

### Key Expansion

`aes/key_expansion.py` supports AES-128 only:

- Input key size: 16 bytes.
- Number of words: 44.
- Number of round keys: 11.
- Number of rounds: 10.

The key schedule applies:

- RotWord
- SubWord
- RCON
- XOR with the word four positions earlier

### Block Cipher

`aes/aes_core.py` encrypts and decrypts one 16-byte block.

Encryption:

1. Initial AddRoundKey.
2. Rounds 1 to 9:
   - SubBytes
   - ShiftRows
   - MixColumns
   - AddRoundKey
3. Round 10:
   - SubBytes
   - ShiftRows
   - AddRoundKey

Decryption applies the inverse operations in reverse order.

The state is stored as a flat 16-byte column-major list matching the AES
specification.

### CBC Mode and Padding

`aes/modes.py` makes AES usable for files of arbitrary length:

- `generate_aes_key()` returns 16 random bytes.
- `generate_iv()` returns 16 random bytes.
- `pkcs7_pad()` pads plaintext to a multiple of 16 bytes.
- `pkcs7_unpad()` validates and removes padding.
- `aes_cbc_encrypt()` chains plaintext blocks with the previous ciphertext
  block.
- `aes_cbc_decrypt()` reverses the chaining and removes padding.

CBC formulas:

```text
C0 = AES_Encrypt(P0 XOR IV)
Ci = AES_Encrypt(Pi XOR C(i-1))

P0 = AES_Decrypt(C0) XOR IV
Pi = AES_Decrypt(Ci) XOR C(i-1)
```

---

## Hybrid Cryptosystem Logic

The hybrid layer exists because RSA and AES solve different problems:

- RSA can protect small secrets with a public/private keypair, but it is slow
  and limited by modulus size.
- AES is fast for files of any size, but both sides need the same secret key.
- Hybrid encryption uses AES for the file and RSA for the AES key.

Encryption:

```text
plaintext file bytes
    -> random AES key + random IV
    -> AES-CBC ciphertext
    -> RSA-encrypted AES key
    -> bundle = encrypted key + IV + ciphertext
```

Decryption:

```text
bundle
    -> RSA-decrypt AES key
    -> AES-CBC-decrypt ciphertext
    -> original file bytes
```

`hybrid_encrypt()` returns the AES key as `"aes_key"` only so the UI can show it
for learning. It should not be exposed in a real application.

---

## Setup

### 1. Create a Virtual Environment

Windows PowerShell:

```powershell
python -m venv venv
venv\Scripts\activate
```

Linux/macOS:

```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Run the Web App

```bash
python main.py
```

Open:

```text
http://127.0.0.1:5000
```

### 4. Run Tests

```bash
python -m unittest discover -s tests -v
```

---

## Web Pages

| Page | Route | Purpose |
| --- | --- | --- |
| Home | `GET /` | Shows hybrid workflow, current key summary, and navigation actions. |
| RSA Keys | `GET /keys` | Shows current key metadata, public key, and private key values behind a details control. |
| Generate Keys | `POST /keys/generate` | Regenerates a 512, 1024, or 2048-bit keypair. |
| Encrypt | `GET /encrypt` | Shows file upload form. |
| Encrypt | `POST /encrypt` | Encrypts the uploaded file and creates a downloadable `.enc.txt` bundle. |
| Decrypt | `GET /decrypt` | Shows encrypted bundle upload form. |
| Decrypt | `POST /decrypt` | Decrypts the bundle and creates a downloadable recovered file. |
| Download | `GET /download/<kind>/<name>` | Downloads generated encrypted or decrypted files. |

---

## Test Coverage

The current suite covers the cryptographic core and the main Flask workflow for
an educational project.

| Test file | Coverage |
| --- | --- |
| `tests/test_math_utils.py` | GCD, EGCD, modular inverse, modular exponentiation, RSA-style math round trip. |
| `tests/test_prime.py` | Known primes, known composites, Carmichael numbers, generated 64-bit and 128-bit primes. |
| `tests/test_rsa_core.py` | 512-bit key shape, inverse key relation, integer encryption/decryption, byte encryption/decryption. |
| `tests/test_aes.py` | GF multiplication, GF inverse, S-box known entries, inverse S-box, NIST AES vectors, PKCS#7, CBC mode. |
| `tests/test_encoding.py` | UTF-8, hex, Base64 round trips, and invalid Base64 rejection. |
| `tests/test_hybrid.py` | End-to-end hybrid round trips for empty, text, and binary data; randomization checks. |
| `tests/test_ui_app.py` | Flask route workflow, metadata bundle creation, sanitized filenames, wrong-key rejection, invalid Base64, malformed bundles, malformed RSA metadata, and path traversal rejection. |

Important test gaps:

- No upload limit tests.
- No large-file performance tests.
- No browser/UI regression tests.
- No CSRF/security-header tests.
- No authenticated-encryption tamper detection tests yet, because the current
  cryptosystem does not include authentication.

---

## Known Gaps

These are the main things missing or risky in the current project.

### Security Gaps

- AES-CBC has confidentiality but no authentication. A modified ciphertext may
  only fail during padding or may decrypt to corrupted plaintext. Add an HMAC
  or switch to an authenticated mode such as AES-GCM.
- RSA byte encryption uses simplified framing, not OAEP. This is educational
  only and should not be used for production encryption.
- The private key, primes, AES key, and IV are displayed in the UI for learning.
  A real app must never expose these secrets to users or logs.
- The RSA keypair is stored only in process memory. Server restart or key
  regeneration makes older bundles undecryptable.
- There is no user authentication, authorization, or per-user storage boundary.
- Flask `secret_key` is hardcoded and `debug=True` is used for local demo.
- There is no CSRF protection for POST forms.
- The app now sanitizes filenames and constrains downloads to generated output
  folders, but production storage should still use opaque IDs, stronger access
  checks, and a stricter file lifecycle.
- Generated encrypted and decrypted files remain on disk until manually removed.
- There is no secure deletion or retention policy.

### Functional Gaps

- Encrypted bundles do not contain a key ID, so the app cannot select among
  multiple stored keys.
- There is no key export/import feature.
- There is no persistent database for files, users, keys, or metadata.
- The `uploads/` directory exists but uploaded originals are currently read
  directly from memory and not saved there.
- Error messages are basic and mostly exception-driven.
- The app reads entire files into memory. The upload limit is 16 MB, but
  streaming/chunked encryption would scale better.
- AES-CBC builds byte strings by repeated concatenation, which can be inefficient
  for larger files.
- The global `_KEYPAIR` state is not designed for multi-user or multi-process
  deployment.

### Documentation Gaps

- No screenshots.
- No architecture diagram image.
- No sequence diagram.
- No deployment guide.
- No API reference generated from docstrings.
- No threat model document.
- No final report template.

---

## Enhancement TODOs

### Highest Priority

- Add authenticated encryption: AES-GCM, or AES-CBC plus HMAC-SHA256 over
  `version || key_id || iv || ciphertext || metadata`.
- Replace simplified RSA key wrapping with RSA-OAEP.
- Add tamper-detection tests once authentication is implemented.
- Add upload-size tests.

### Product Features

- Add user accounts and login.
- Store files per user.
- Add a database table for files, bundle metadata, key IDs, created timestamps,
  and status.
- Add key export/import so bundles can survive server restarts.
- Add key rotation and key versioning.
- Add a file history page with download/delete actions.
- Add bundle migration/backward-compatibility handling as formats evolve.
- Encrypt or sign file metadata.
- Add optional digital signatures to prove the bundle creator.

### Developer Experience

- Add a `pyproject.toml`.
- Add linting and formatting, for example Ruff.
- Add type hints for keys, bundles, and route helper functions.
- Replace raw dictionaries with dataclasses or typed dictionaries.
- Add continuous integration to run tests automatically.
- Add coverage reporting.
- Add structured logging.
- Move Flask config into environment variables.
- Split Flask routes into blueprints as the UI grows.

### Performance and Scalability

- Use `bytearray` or list-and-join instead of repeated byte concatenation in CBC.
- Add streaming/chunked file processing.
- Move slow key generation into a background task or show progress.
- Add cleanup jobs for old encrypted/decrypted artifacts.
- Add configurable upload limits.

### UI/UX

- Add a page that lists generated encrypted/decrypted files.
- Add clearer error pages for invalid bundles or wrong keys.
- Add copy buttons for key/ciphertext fields.
- Add progress indicators for 2048-bit key generation and larger files.
- Add a key fingerprint on every page so users know which key is active.
- Add import/export buttons for keys and encrypted bundles.

### Security Documentation

- Add a threat model.
- Add a table of educational choices versus production choices.
- Document why CBC needs authentication.
- Document why RSA needs OAEP.
- Document key lifecycle and storage assumptions.

---

## Educational Rules Followed

The project avoids:

- `cryptography`
- `pycryptodome`
- OpenSSL wrappers
- `Crypto.*`
- `RSA.generate()`
- `Cipher.AES`
- Python `pow(a, b, m)` inside implementation code

Allowed standard-library utilities:

- `secrets` for random bytes and random integers
- `base64` for text-safe binary encoding
- `json` for the bundle envelope
- `uuid` for non-cryptographic job IDs
- `datetime` for display timestamps

---

## How to Explain the Project

The short explanation:

1. RSA is good for protecting small secrets, but not large files.
2. AES is good for encrypting large files, but needs a shared secret key.
3. The app generates a random AES key for each file.
4. The file is encrypted with AES-CBC.
5. The AES key is encrypted with RSA.
6. The encrypted file, IV, and encrypted AES key are saved together.
7. Decryption reverses the process using the RSA private key.

The important caveat:

This demonstrates the shape of real hybrid cryptosystems, but real secure
systems also need authentication, OAEP, key persistence, access control,
auditing, safe file handling, and careful operational design.

---

## Authors

University Cryptography Project Team

Course: Data Security / Cryptography

Project: RSA and AES Hybrid Cryptosystem - Secure File Storage System
