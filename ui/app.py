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
from werkzeug.utils import secure_filename

from rsa.rsa_core import generate_keypair
from hybrid.hybrid_crypto import hybrid_encrypt, hybrid_decrypt
from encoding.encoding_utils import to_hex, to_base64, from_base64

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "encrypted")
DECRYPTED_DIR = os.path.join(BASE_DIR, "decrypted")

for d in (UPLOAD_DIR, ENCRYPTED_DIR, DECRYPTED_DIR):
    os.makedirs(d, exist_ok=True)

app = Flask(__name__)
app.secret_key = "educational-demo-not-for-production"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

BUNDLE_VERSION = 1
BUSINESS_MODEL = "Secure File Storage System"
AES_ALGORITHM = "AES-128-CBC"
AES_PADDING = "PKCS#7"
RSA_KEY_WRAP = "RSA length-prefixed educational key wrap"
TEXT_ENCODING = "JSON fields with Base64 binary values"

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
    original_name = _safe_original_name(upload.filename)
    plaintext = upload.read()

    kp = get_or_create_keypair()
    bundle = hybrid_encrypt(plaintext, kp["public"])

    job_id = uuid.uuid4().hex[:12]
    encrypted_filename = _generated_name(job_id, original_name, ".enc.txt")
    encrypted_path = _resolve_output_path(ENCRYPTED_DIR, encrypted_filename)
    on_disk = _bundle_to_json(original_name, bundle, kp)

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
        bundle_version=BUNDLE_VERSION,
        aes_algorithm=AES_ALGORITHM,
        aes_padding=AES_PADDING,
        rsa_key_wrap=RSA_KEY_WRAP,
        text_encoding=TEXT_ENCODING,
        rsa_bits=kp["bits"],
    )

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    if request.method == "GET":
        return render_template("decrypt.html")

    if "file" not in request.files or request.files["file"].filename == "":
        flash("Please choose an encrypted .enc.txt file to decrypt.", "error")
        return redirect(url_for("decrypt_page"))

    upload = request.files["file"]
    try:
        on_disk = _read_bundle_json(upload)
        bundle = _bundle_from_json(on_disk)
        original_name = _safe_original_name(on_disk.get("original_name", "decrypted.bin"))
    except Exception as exc:
        flash(f"Invalid encrypted bundle: {exc}", "error")
        return redirect(url_for("decrypt_page"))

    kp = get_or_create_keypair()
    try:
        _validate_bundle_key(on_disk, kp)
        plaintext = hybrid_decrypt(bundle, kp["private"])
    except Exception as exc:
        flash(f"Decryption failed: {exc}", "error")
        return redirect(url_for("decrypt_page"))

    job_id = uuid.uuid4().hex[:12]
    decrypted_filename = _generated_name(job_id, original_name)
    decrypted_path = _resolve_output_path(DECRYPTED_DIR, decrypted_filename)
    with open(decrypted_path, "wb") as f:
        f.write(plaintext)

    try:
        preview_text = plaintext.decode("utf-8")
        if len(preview_text) > 1000:
            preview_text = preview_text[:1000] + " ... (truncated)"
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
    try:
        full = _resolve_output_path(folder, name)
    except ValueError:
        abort(404)
    if not os.path.isfile(full):
        abort(404)
    return send_file(full, as_attachment=True, download_name=_strip_job_id(name))

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
    return h[:14] + "..." + h[-8:]

def _safe_original_name(name):
    """Return a filesystem-safe display/storage name for an uploaded file."""
    safe = secure_filename(str(name or "").strip())
    return safe or "uploaded.bin"

def _generated_name(job_id, original_name, suffix=""):
    return f"{job_id}__{_safe_original_name(original_name)}{suffix}"

def _resolve_output_path(folder, name):
    """Resolve a generated filename and reject path traversal attempts."""
    if os.path.basename(name) != name:
        raise ValueError("Generated filename must not contain path separators.")

    folder_abs = os.path.abspath(folder)
    full = os.path.abspath(os.path.join(folder_abs, name))
    if os.path.commonpath([folder_abs, full]) != folder_abs:
        raise ValueError("Generated filename escapes the output directory.")
    return full

def _bundle_to_json(original_name, bundle, kp):
    """Build the transferable JSON envelope around encrypted binary fields."""
    return {
        "version": BUNDLE_VERSION,
        "business_model": BUSINESS_MODEL,
        "algorithms": {
            "file_encryption": AES_ALGORITHM,
            "padding": AES_PADDING,
            "key_wrap": RSA_KEY_WRAP,
            "encoding": TEXT_ENCODING,
        },
        "rsa_public": {
            "bits": kp["bits"],
            "n_hex": hex(kp["public"]["n"]),
            "e": kp["public"]["e"],
        },
        "original_name": original_name,
        "encrypted_key_b64": to_base64(bundle["encrypted_key"]),
        "iv_b64": to_base64(bundle["iv"]),
        "ciphertext_b64": to_base64(bundle["ciphertext"]),
    }

def _read_bundle_json(upload):
    raw = upload.read().decode("utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Bundle must be a JSON object.")
    return parsed

def _bundle_from_json(on_disk):
    required = ("encrypted_key_b64", "iv_b64", "ciphertext_b64")
    missing = [field for field in required if field not in on_disk]
    if missing:
        raise ValueError("Missing bundle field(s): " + ", ".join(missing))

    return {
        "encrypted_key": from_base64(on_disk["encrypted_key_b64"]),
        "iv": from_base64(on_disk["iv_b64"]),
        "ciphertext": from_base64(on_disk["ciphertext_b64"]),
    }

def _validate_bundle_key(on_disk, kp):
    """Reject bundles that advertise a different RSA public modulus."""
    rsa_public = on_disk.get("rsa_public")
    if not rsa_public:
        return
    if not isinstance(rsa_public, dict):
        raise ValueError("Bundle RSA public metadata must be a JSON object.")

    bundle_n = str(rsa_public.get("n_hex", "")).lower()
    current_n = hex(kp["private"]["n"]).lower()
    if bundle_n and bundle_n != current_n:
        raise ValueError("Bundle was encrypted with a different RSA keypair.")

def _strip_job_id(name):
    if "__" in name:
        return name.split("__", 1)[1]
    return name

if __name__ == "__main__":
    app.run(debug=True)
