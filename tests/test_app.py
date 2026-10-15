"""Test suite (standard library ``unittest`` only).

Run from the project root:   python -m unittest discover -s tests -t . -v
"""
from __future__ import annotations

import io
import os
import re
import shutil
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from app import create_app
from encryption import DecryptionError, Vault, decrypt_backup, derive_vault_key, encrypt_backup, generate_salt
from password_generator import AMBIGUOUS, SYMBOLS, generate_password
from security_audit import audit_vault, calculate_strength, find_duplicates

MASTER = "Correct-Horse-Battery-9!"
SECRET = "s" * 48
PEPPER = "p" * 48


class CryptoAndLogicTests(unittest.TestCase):
    def test_generator_respects_options(self):
        pw = generate_password(30, use_upper=True, use_lower=False, use_digits=True, use_symbols=False)
        self.assertEqual(len(pw), 30)
        self.assertTrue(any(c.isupper() for c in pw) and any(c.isdigit() for c in pw))
        self.assertFalse(any(c.islower() or c in SYMBOLS for c in pw))

    def test_generator_has_every_selected_class_and_no_ambiguous(self):
        for _ in range(50):
            pw = generate_password(8, exclude_ambiguous=True)
            self.assertTrue(any(c.isupper() for c in pw) and any(c.islower() for c in pw))
            self.assertTrue(any(c.isdigit() for c in pw) and any(c in SYMBOLS for c in pw))
            self.assertFalse(any(c in AMBIGUOUS for c in pw))

    def test_generator_rejects_bad_input(self):
        with self.assertRaises(ValueError):
            generate_password(4)
        with self.assertRaises(ValueError):
            generate_password(20, use_upper=False, use_lower=False, use_digits=False, use_symbols=False)

    def test_strength_scoring(self):
        self.assertEqual(calculate_strength("password").score, 0)
        self.assertTrue(calculate_strength("abc123").is_weak)
        self.assertGreaterEqual(calculate_strength(MASTER).score, 3)
        self.assertGreaterEqual(calculate_strength(generate_password(24)).score, 4)

    def test_duplicates_and_vault_audit(self):
        old = (datetime.now(timezone.utc) - timedelta(days=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        new = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        entries = [
            {"id": 1, "account_name": "A", "password": "password", "updated_at": old},
            {"id": 2, "account_name": "B", "password": "Zx9!kLm2#qWe7vB", "updated_at": new},
            {"id": 3, "account_name": "C", "password": "Zx9!kLm2#qWe7vB", "updated_at": new},
        ]
        self.assertEqual(len(find_duplicates(entries)), 1)
        report = audit_vault(entries)
        self.assertEqual([w["id"] for w in report["weak"]], [1])
        self.assertEqual([o["id"] for o in report["old"]], [1])
        self.assertEqual(report["duplicate_count"], 2)
        self.assertLess(report["score"], 100)

    def test_vault_encryption_roundtrip_and_isolation(self):
        salt = generate_salt()
        vault = Vault(derive_vault_key(MASTER, salt, PEPPER))
        token = vault.encrypt("hunter2")
        self.assertNotIn(b"hunter2", token)
        self.assertEqual(vault.decrypt(token), "hunter2")
        for wrong in (Vault(derive_vault_key("Other-Password-1!", salt, PEPPER)),
                      Vault(derive_vault_key(MASTER, salt, "q" * 48))):
            with self.assertRaises(DecryptionError):
                wrong.decrypt(token)
        with self.assertRaises(DecryptionError):  # tampering is detected
            vault.decrypt(token[:-2] + b"AA")

    def test_backup_roundtrip(self):
        blob = encrypt_backup({"credentials": [{"password": "secret-value"}]}, "backup-passphrase-1")
        self.assertNotIn(b"secret-value", blob)
        self.assertEqual(decrypt_backup(blob, "backup-passphrase-1")["credentials"][0]["password"], "secret-value")
        with self.assertRaises(DecryptionError):
            decrypt_backup(blob, "wrong-passphrase-123")
        with self.assertRaises(DecryptionError):
            decrypt_backup(b"not json", "backup-passphrase-1")


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "vault.db")
        self.app = create_app({
            "TESTING": True, "SECRET_KEY": SECRET, "ENCRYPTION_PEPPER": PEPPER,
            "DATABASE_PATH": self.db_path, "LOG_DIR": os.path.join(self.tmp, "logs"),
        })
        self.client = self.app.test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------ helpers
    def token(self, client=None):
        html = (client or self.client).get("/login", follow_redirects=True).get_data(as_text=True)
        return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)

    def post(self, path, data=None, client=None, **kwargs):
        client = client or self.client
        data = dict(data or {})
        data["csrf_token"] = self.token(client)
        return client.post(path, data=data, **kwargs)

    def register(self, username="alice", password=MASTER, client=None):
        return self.post("/register", {"username": username, "password": password, "confirm_password": password},
                         client=client)

    def login(self, username="alice", password=MASTER, client=None):
        return self.post("/login", {"username": username, "password": password}, client=client)

    def signed_in_client(self, username="alice"):
        client = self.app.test_client()
        self.register(username, client=client)
        self.assertEqual(self.login(username, client=client).status_code, 302)
        return client

    def add(self, client, account="GitHub", username="octocat", password="Zx9!kLm2#qWe7vB", url="github.com"):
        resp = self.post("/credentials/new", {"account_name": account, "username": username,
                                              "password": password, "website_url": url}, client=client)
        self.assertEqual(resp.status_code, 302, resp.get_data(as_text=True)[:500])

    def query(self, sql):
        conn = sqlite3.connect(self.db_path)
        try:
            return conn.execute(sql).fetchall()
        finally:
            conn.close()

    def audit_events(self):
        return [r[0] for r in self.query("SELECT event FROM audit_logs ORDER BY id")]


class AuthTests(AppTestCase):
    def test_config_requires_secrets(self):
        with self.assertRaises(RuntimeError):
            create_app({"SECRET_KEY": "", "DATABASE_PATH": os.path.join(self.tmp, "x.db")})

    def test_schema_created_automatically(self):
        tables = {r[0] for r in self.query("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"users", "credentials", "audit_logs"} <= tables)

    def test_registration_validation(self):
        self.assertEqual(self.register("a", "short").status_code, 400)
        self.assertEqual(self.register("bob", "password1234").status_code, 400)       # too weak
        self.assertEqual(self.register("bob", MASTER).status_code, 302)
        self.assertEqual(self.register("BOB", MASTER).status_code, 400)               # case-insensitive duplicate

    def test_master_password_is_bcrypt_hashed(self):
        self.register()
        stored = self.query("SELECT password_hash FROM users")[0][0]
        self.assertTrue(bytes(stored).startswith(b"$2"))
        self.assertNotIn(MASTER.encode(), bytes(stored))

    def test_login_logout_and_protected_pages(self):
        self.assertEqual(self.client.get("/vault").status_code, 302)                  # not signed in
        self.register()
        self.assertEqual(self.login("alice", "Wrong-Password-1!").status_code, 401)
        self.assertEqual(self.login().status_code, 302)
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.post("/logout")
        self.assertEqual(self.client.get("/dashboard").status_code, 302)

    def test_account_lockout(self):
        self.register()
        for _ in range(5):
            self.assertEqual(self.login("alice", "Wrong-Password-1!").status_code, 401)
        self.assertEqual(self.login().status_code, 401)  # correct password, but locked
        self.assertIn("account_locked", self.audit_events())

    def test_csrf_blocks_posts_without_token(self):
        self.register()
        self.assertEqual(self.client.post("/login", data={"username": "alice", "password": MASTER}).status_code, 400)

    def test_security_headers(self):
        resp = self.client.get("/login")
        self.assertIn("default-src 'self'", resp.headers["Content-Security-Policy"])
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
        self.assertEqual(resp.headers["Cache-Control"], "no-store")
        self.assertIn("HttpOnly", resp.headers["Set-Cookie"])


class VaultTests(AppTestCase):
    def test_crud_search_and_encryption_at_rest(self):
        client = self.signed_in_client()
        self.add(client)
        self.add(client, account="Bank", username="alice@example.com", password="Qw8#vTn4!zPr6Yh", url="https://bank.test")

        raw = self.query("SELECT username_enc, password_enc FROM credentials")
        self.assertEqual(len(raw), 2)
        with open(self.db_path, "rb") as handle:
            blob = handle.read()
        for secret in (b"Zx9!kLm2#qWe7vB", b"octocat", b"Qw8#vTn4!zPr6Yh"):
            self.assertNotIn(secret, blob)

        page = client.get("/vault").get_data(as_text=True)
        self.assertIn("GitHub", page)
        self.assertNotIn("Zx9!kLm2#qWe7vB", page)                                       # never rendered
        self.assertIn("GitHub", client.get("/vault?q=octo&field=username").get_data(as_text=True))
        self.assertNotIn("Bank", client.get("/vault?q=octo&field=username").get_data(as_text=True))
        self.assertIn("Bank", client.get("/vault?q=bank.test&field=website").get_data(as_text=True))
        self.assertIn("Bank", client.get("/vault?q=bank&field=account").get_data(as_text=True))

        reveal = client.post("/credentials/1/reveal", headers={"X-CSRF-Token": self.token(client)})
        self.assertEqual(reveal.get_json()["password"], "Zx9!kLm2#qWe7vB")

        self.assertEqual(self.post("/credentials/1/edit", {"account_name": "GitHub", "username": "octocat",
                                                            "password": "", "website_url": ""}, client=client).status_code, 302)
        self.assertEqual(client.post("/credentials/1/reveal", headers={"X-CSRF-Token": self.token(client)})
                         .get_json()["password"], "Zx9!kLm2#qWe7vB")                      # blank keeps password
        self.post("/credentials/1/edit", {"account_name": "GitHub", "username": "octocat",
                                          "password": "New-Pass-7!xYz-Long"}, client=client)
        self.assertEqual(client.post("/credentials/1/reveal", headers={"X-CSRF-Token": self.token(client)})
                         .get_json()["password"], "New-Pass-7!xYz-Long")

        self.assertEqual(self.post("/credentials/2/delete", client=client).status_code, 302)
        self.assertEqual(client.get("/credentials/2/edit").status_code, 404)

        events = self.audit_events()
        for expected in ("login_success", "password_created", "password_updated", "password_deleted"):
            self.assertIn(expected, events)

    def test_users_cannot_access_each_others_entries(self):
        alice, mallory = self.signed_in_client("alice"), self.signed_in_client("mallory")
        self.add(alice)
        self.assertEqual(mallory.get("/credentials/1/edit").status_code, 404)
        self.assertEqual(mallory.post("/credentials/1/reveal", headers={"X-CSRF-Token": self.token(mallory)}).status_code, 404)
        self.assertEqual(self.post("/credentials/1/delete", client=mallory).status_code, 404)
        self.assertNotIn("GitHub", mallory.get("/vault").get_data(as_text=True))

    def test_validation_and_unsafe_urls(self):
        client = self.signed_in_client()
        for bad in ("javascript:alert(1)", "data:text/html,<b>x</b>", "ftp://example.com", "http://", "https://exa mple.com"):
            resp = self.post("/credentials/new", {"account_name": "X", "username": "u", "password": "p",
                                                  "website_url": bad}, client=client)
            self.assertEqual(resp.status_code, 400, bad)
        for good in ("example.com", "https://sub.example.co.uk/path?q=1", "http://localhost:8080", "http://[::1]:5000/"):
            resp = self.post("/credentials/new", {"account_name": "X", "username": "u", "password": "p",
                                                  "website_url": good}, client=client)
            self.assertEqual(resp.status_code, 302, good)
        self.assertEqual(self.post("/credentials/new", {"account_name": "", "username": "", "password": ""},
                                   client=client).status_code, 400)

    def test_audit_page_flags_weak_and_reused(self):
        client = self.signed_in_client()
        self.add(client, account="One", password="password")
        self.add(client, account="Two", password="Zx9!kLm2#qWe7vB")
        self.add(client, account="Three", password="Zx9!kLm2#qWe7vB")
        page = client.get("/audit").get_data(as_text=True)
        self.assertIn("Weak passwords (1)", page)
        self.assertIn("Reused passwords (1 group)", page)

    def test_api_generate_and_strength(self):
        client = self.signed_in_client()
        data = client.get("/api/generate?length=24&symbols=0", headers={"X-Requested-With": "fetch"}).get_json()
        self.assertEqual(len(data["password"]), 24)
        self.assertEqual(client.get("/api/generate?length=3").status_code, 400)
        strength = client.post("/api/strength", json={"password": "password"},
                               headers={"X-CSRF-Token": self.token(client)}).get_json()
        self.assertTrue(strength["is_weak"])
        self.assertEqual(self.client.get("/api/generate", headers={"X-Requested-With": "fetch"}).status_code, 401)


class BackupTests(AppTestCase):
    def test_export_requires_master_password_and_roundtrips(self):
        alice = self.signed_in_client("alice")
        self.add(alice)
        bad = self.post("/backup/export", {"master_password": "Wrong-Password-1!", "passphrase": "backup-pass-12345",
                                            "confirm_passphrase": "backup-pass-12345"}, client=alice)
        self.assertEqual(bad.status_code, 302)                                          # refused, redirected back
        good = self.post("/backup/export", {"master_password": MASTER, "passphrase": "backup-pass-12345",
                                             "confirm_passphrase": "backup-pass-12345"}, client=alice)
        self.assertEqual(good.status_code, 200)
        blob = good.get_data()
        self.assertNotIn(b"octocat", blob)
        self.assertEqual(decrypt_backup(blob, "backup-pass-12345")["credentials"][0]["username"], "octocat")

        bob = self.signed_in_client("bob")                                              # multi-user restore
        wrong = self.post("/backup/import", {"passphrase": "nope-nope-nope-1", "backup_file": (io.BytesIO(blob), "b.pwmbackup")},
                          client=bob, content_type="multipart/form-data")
        self.assertEqual(wrong.status_code, 302)
        self.assertNotIn("GitHub", bob.get("/vault").get_data(as_text=True))
        self.post("/backup/import", {"passphrase": "backup-pass-12345", "backup_file": (io.BytesIO(blob), "b.pwmbackup")},
                  client=bob, content_type="multipart/form-data")
        self.assertIn("GitHub", bob.get("/vault").get_data(as_text=True))
        self.assertEqual(bob.post("/credentials/2/reveal", headers={"X-CSRF-Token": self.token(bob)}).get_json()["password"],
                         "Zx9!kLm2#qWe7vB")


if __name__ == "__main__":
    unittest.main()
