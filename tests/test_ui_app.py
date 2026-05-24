"""Route-level tests for the Flask secure file storage workflow."""

import io
import json
import os
import tempfile
import unittest

import ui.app as ui_app
from rsa.rsa_core import generate_keypair


class TestFlaskWorkflow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_encrypted_dir = ui_app.ENCRYPTED_DIR
        self.old_decrypted_dir = ui_app.DECRYPTED_DIR
        self.old_upload_dir = ui_app.UPLOAD_DIR
        self.old_keypair = dict(ui_app._KEYPAIR)

        ui_app.ENCRYPTED_DIR = os.path.join(self.tmp.name, "encrypted")
        ui_app.DECRYPTED_DIR = os.path.join(self.tmp.name, "decrypted")
        ui_app.UPLOAD_DIR = os.path.join(self.tmp.name, "uploads")
        for folder in (ui_app.ENCRYPTED_DIR, ui_app.DECRYPTED_DIR, ui_app.UPLOAD_DIR):
            os.makedirs(folder, exist_ok=True)

        public_key, private_key = generate_keypair(512)
        ui_app._KEYPAIR.update(
            {
                "public": public_key,
                "private": private_key,
                "bits": 512,
                "generated_at": "test-time",
            }
        )

        ui_app.app.config["TESTING"] = True
        self.client = ui_app.app.test_client()

    def tearDown(self):
        ui_app.ENCRYPTED_DIR = self.old_encrypted_dir
        ui_app.DECRYPTED_DIR = self.old_decrypted_dir
        ui_app.UPLOAD_DIR = self.old_upload_dir
        ui_app._KEYPAIR.update(self.old_keypair)
        self.tmp.cleanup()

    def test_encrypt_creates_versioned_bundle_and_sanitizes_filename(self):
        response = self._post_encrypt(b"top secret", "../../report.txt")

        self.assertEqual(response.status_code, 200)
        encrypted_files = os.listdir(ui_app.ENCRYPTED_DIR)
        self.assertEqual(len(encrypted_files), 1)
        self.assertTrue(encrypted_files[0].endswith("__report.txt.enc.txt"))
        self.assertNotIn("..", encrypted_files[0])

        bundle = self._read_encrypted_bundle(encrypted_files[0])
        self.assertEqual(bundle["version"], ui_app.BUNDLE_VERSION)
        self.assertEqual(bundle["business_model"], ui_app.BUSINESS_MODEL)
        self.assertEqual(bundle["original_name"], "report.txt")
        self.assertEqual(bundle["algorithms"]["file_encryption"], ui_app.AES_ALGORITHM)
        self.assertEqual(bundle["algorithms"]["encoding"], ui_app.TEXT_ENCODING)
        self.assertEqual(bundle["rsa_public"]["bits"], 512)
        self.assertIn("encrypted_key_b64", bundle)
        self.assertIn("iv_b64", bundle)
        self.assertIn("ciphertext_b64", bundle)

    def test_encrypt_then_decrypt_roundtrip_via_routes(self):
        plaintext = b"route-level hybrid encryption roundtrip"
        self._post_encrypt(plaintext, "notes.txt")
        encrypted_name = os.listdir(ui_app.ENCRYPTED_DIR)[0]
        bundle_bytes = self._read_encrypted_bundle_bytes(encrypted_name)

        response = self.client.post(
            "/decrypt",
            data={"file": (io.BytesIO(bundle_bytes), "notes.enc.txt")},
            content_type="multipart/form-data",
        )

        self.assertEqual(response.status_code, 200)
        decrypted_files = os.listdir(ui_app.DECRYPTED_DIR)
        self.assertEqual(len(decrypted_files), 1)
        recovered_path = os.path.join(ui_app.DECRYPTED_DIR, decrypted_files[0])
        with open(recovered_path, "rb") as f:
            self.assertEqual(f.read(), plaintext)

    def test_decrypt_rejects_bundle_for_different_rsa_key(self):
        self._post_encrypt(b"wrong key check", "wrong-key.txt")
        encrypted_name = os.listdir(ui_app.ENCRYPTED_DIR)[0]
        bundle = self._read_encrypted_bundle(encrypted_name)
        bundle["rsa_public"]["n_hex"] = "0x12345"

        response = self.client.post(
            "/decrypt",
            data={"file": (io.BytesIO(json.dumps(bundle).encode("utf-8")), "wrong.enc.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"different RSA keypair", response.data)
        self.assertEqual(os.listdir(ui_app.DECRYPTED_DIR), [])

    def test_decrypt_rejects_missing_bundle_fields(self):
        response = self.client.post(
            "/decrypt",
            data={"file": (io.BytesIO(b'{"version": 1}'), "bad.enc.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Missing bundle field", response.data)
        self.assertEqual(os.listdir(ui_app.DECRYPTED_DIR), [])

    def test_decrypt_rejects_invalid_base64_field(self):
        bundle = {
            "encrypted_key_b64": "not valid base64!",
            "iv_b64": "also not valid",
            "ciphertext_b64": "still not valid",
        }

        response = self.client.post(
            "/decrypt",
            data={"file": (io.BytesIO(json.dumps(bundle).encode("utf-8")), "bad.enc.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid encrypted bundle", response.data)
        self.assertEqual(os.listdir(ui_app.DECRYPTED_DIR), [])

    def test_decrypt_rejects_malformed_rsa_metadata(self):
        self._post_encrypt(b"metadata check", "metadata.txt")
        encrypted_name = os.listdir(ui_app.ENCRYPTED_DIR)[0]
        bundle = self._read_encrypted_bundle(encrypted_name)
        bundle["rsa_public"] = "not an object"

        response = self.client.post(
            "/decrypt",
            data={"file": (io.BytesIO(json.dumps(bundle).encode("utf-8")), "bad.enc.txt")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"RSA public metadata", response.data)
        self.assertEqual(os.listdir(ui_app.DECRYPTED_DIR), [])

    def test_download_rejects_path_traversal(self):
        response = self.client.get("/download/encrypted/..%2FREADME.md")
        self.assertEqual(response.status_code, 404)

        with self.assertRaises(ValueError):
            ui_app._resolve_output_path(ui_app.ENCRYPTED_DIR, "../README.md")

    def _post_encrypt(self, plaintext, filename):
        return self.client.post(
            "/encrypt",
            data={"file": (io.BytesIO(plaintext), filename)},
            content_type="multipart/form-data",
        )

    def _read_encrypted_bundle(self, name):
        with open(os.path.join(ui_app.ENCRYPTED_DIR, name), "r", encoding="utf-8") as f:
            return json.load(f)

    def _read_encrypted_bundle_bytes(self, name):
        with open(os.path.join(ui_app.ENCRYPTED_DIR, name), "rb") as f:
            return f.read()


if __name__ == "__main__":
    unittest.main(verbosity=2)
