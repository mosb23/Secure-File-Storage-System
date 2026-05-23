"""
Flask Web UI for the RSA & AES Hybrid Cryptosystem
==================================================

Pages / Routes
--------------
    GET  /                -> home page (workflow explanation + main menu)
    GET  /keys            -> RSA key page (shows current key, button to regenerate)
    POST /keys/generate   -> generate a fresh RSA-1024 keypair
    GET  /encrypt         -> file upload form
    POST /encrypt         -> hybrid-encrypt the uploaded file, show results
    GET  /decrypt         -> form to upload encrypted bundle
    POST /decrypt         -> decrypt and show / download original file
    GET  /download/<kind>/<name>  -> download a generated file

State Management
----------------
For an educational demo we keep the RSA keypair in memory (singleton).
Encrypted artifacts are stored under encrypted/ and decrypted/.
"""

import os
import json
import uuid
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
    flash,
    abort,
)

from rsa.rsa_core import generate_keypair
from hybrid.hybrid_crypto import hybrid_encrypt, hybrid_decrypt
from encoding.encoding_utils import to_hex, to_base64, from_base64


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(BASE_DIR, "decrypted")

for d in (UPLOAD_DIR, ENCRYPTED_DIR, DECRYPTED_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(__name__)
app.secret_key = "educational-demo-not-for-production"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB upload limit


# ---------------------------------------------------------------------------
# In-memory RSA keypair
# ---------------------------------------------------------------------------
#
# For this academic demo we keep one keypair in memory. In a real product
# you would persist keys securely and authenticate users.

_KEYPAIR = {"public": None, "private": None, "bits": None, "generated_at": None}


def get_or_create_keypair(bits=1024):
    """Return the current keypair, generating one on first access."""
    if _KEYPAIR["public"] is None:
        pub, priv = generate_keypair(bits)
        _KEYPAIR["public"] = pub
        _KEYPAIR["private"] = priv
        _KEYPAIR["bits"] = bits
        _KEYPAIR["generated_at"] = datetime.now().isoformat(timespec="seconds")
    return _KEYPAIR


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    kp = get_or_create_keypair()
    return render_template("index.html", keypair_summary=_keypair_summary(kp))


@app.route("/keys")
def keys_page():
    kp = get_or_create_keypair()
    return render_template(
        "keys.html",
        bits=kp["bits"],
        generated_at=kp["generated_at"],
        public_n_hex=hex(kp["public"]["n"]),
        public_e=kp["public"]["e"],
        private_d_hex=hex(kp["private"]["d"]),
        prime_p_hex=hex(kp["private"]["p"]),
        prime_q_hex=hex(kp["private"]["q"]),
    )


@app.route("/keys/generate", methods=["POST"])
def keys_generate():
    bits = int(request.form.get("bits", "1024"))
    if bits not in (512, 1024, 2048):
        bits = 1024
    pub, priv = generate_keypair(bits)
    _KEYPAIR["public"] = pub
    _KEYPAIR["private"] = priv
    _KEYPAIR["bits"] = bits
    _KEYPAIR["generated_at"] = datetime.now().isoformat(timespec="seconds")
    flash(f"New RSA-{bits} keypair generated.", "success")
    return redirect(url_for("keys_page"))


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt_page():
    if request.method == "GET":
        return render_template("encrypt.html")

    if "file" not in request.files or request.files["file"].filename == "":
        flash("Please choose a file to encrypt.", "error")
        return redirect(url_for("encrypt_page"))

    upload = request.files["file"]
    original_name = upload.filename
    plaintext = upload.read()

    kp = get_or_create_keypair()
    bundle = hybrid_encrypt(plaintext, kp["public"])

    # Save the bundle to disk so the user can download it.
    # We use a .enc.txt extension so the file opens in Notepad on Windows
    # by default. The contents are still JSON (a readable, self-describing
    # envelope around the Base64-encoded ciphertext).
    job_id = uuid.uuid4().hex[:12]
    encrypted_filename = f"{job_id}__{original_name}.enc.txt"
    encrypted_path = os.path.join(ENCRYPTED_DIR, encrypted_filename)

    on_disk = {
        "original_name": original_name,
        "encrypted_key_b64": to_base64(bundle["encrypted_key"]),
        "iv_b64": to_base64(bundle["iv"]),
        "ciphertext_b64": to_base64(bundle["ciphertext"]),
    }
    with open(encrypted_path, "w", encoding="utf-8") as f:
        json.dump(on_disk, f, indent=2)

    return render_template(
        "encrypt_result.html",
        original_name=original_name,
        plaintext_size=len(plaintext),
        ciphertext_size=len(bundle["ciphertext"]),
        aes_key_hex=to_hex(bundle["aes_key"]),
        iv_hex=to_hex(bundle["iv"]),
        encrypted_key_b64=to_base64(bundle["encrypted_key"]),
        ciphertext_preview_b64=to_base64(bundle["ciphertext"])[:512],
        download_name=encrypted_filename,
    )


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    if request.method == "GET":
        return render_template("decrypt.html")

    if "file" not in request.files or request.files["file"].filename == "":
        flash("Please choose an encrypted .enc.json file to decrypt.", "error")
        return redirect(url_for("decrypt_page"))

    upload = request.files["file"]
    try:
        on_disk = json.loads(upload.read().decode("utf-8"))
        bundle = {
            "encrypted_key": from_base64(on_disk["encrypted_key_b64"]),
            "iv": from_base64(on_disk["iv_b64"]),
            "ciphertext": from_base64(on_disk["ciphertext_b64"]),
        }
        original_name = on_disk.get("original_name", "decrypted.bin")
    except Exception as exc:
        flash(f"Invalid encrypted bundle: {exc}", "error")
        return redirect(url_for("decrypt_page"))

    kp = get_or_create_keypair()
    try:
        plaintext = hybrid_decrypt(bundle, kp["private"])
    except Exception as exc:
        flash(f"Decryption failed: {exc}", "error")
        return redirect(url_for("decrypt_page"))

    job_id = uuid.uuid4().hex[:12]
    decrypted_filename = f"{job_id}__{original_name}"
    decrypted_path = os.path.join(DECRYPTED_DIR, decrypted_filename)
    with open(decrypted_path, "wb") as f:
        f.write(plaintext)

    # Try to show a small text preview if the data is UTF-8 decodable.
    try:
        preview_text = plaintext.decode("utf-8")
        if len(preview_text) > 1000:
            preview_text = preview_text[:1000] + " … (truncated)"
    except UnicodeDecodeError:
        preview_text = None

    return render_template(
        "decrypt_result.html",
        original_name=original_name,
        plaintext_size=len(plaintext),
        download_name=decrypted_filename,
        preview_text=preview_text,
    )


@app.route("/download/<kind>/<path:name>")
def download(kind, name):
    if kind == "encrypted":
        folder = ENCRYPTED_DIR
    elif kind == "decrypted":
        folder = DECRYPTED_DIR
    else:
        abort(404)
    full = os.path.join(folder, name)
    if not os.path.isfile(full):
        abort(404)
    return send_file(full, as_attachment=True, download_name=_strip_job_id(name))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _keypair_summary(kp):
    return {
        "bits": kp["bits"],
        "generated_at": kp["generated_at"],
        "n_short": _short_hex(kp["public"]["n"]),
        "e": kp["public"]["e"],
    }


def _short_hex(value):
    h = hex(value)
    if len(h) <= 24:
        return h
    return h[:14] + "…" + h[-8:]


def _strip_job_id(name):
    # Files are stored as "<jobid>__<originalname>". Strip prefix for download.
    if "__" in name:
        return name.split("__", 1)[1]
    return name


if __name__ == "__main__":
    app.run(debug=True)
