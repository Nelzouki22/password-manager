"""Cryptographic helpers built on the ``cryptography`` library (Fernet).

Key hierarchy
-------------
* ``vault key``  = HKDF-SHA256( scrypt(master_password, per-user salt),  salt = SHA-256(server pepper) )
  The key needs BOTH the user's master password and the server-side secret
  (``ENCRYPTION_PEPPER``, supplied through the environment). A stolen database
  file alone is therefore useless, and so is a stolen pepper alone.
* ``backup key`` = scrypt(backup passphrase, random per-file salt).

Fernet provides authenticated encryption (AES-128-CBC + HMAC-SHA256), so any
tampering with a stored token is detected on decryption.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
BACKUP_FORMAT = "pwm-backup"
BACKUP_VERSION = 1


class DecryptionError(Exception):
    """Raised when data cannot be decrypted (wrong key, corrupt or tampered data)."""


def generate_salt() -> bytes:
    return os.urandom(SALT_BYTES)


def _scrypt(secret: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(secret.encode("utf-8"))


def derive_vault_key(master_password: str, salt: bytes, pepper: str) -> bytes:
    """Derive the per-user Fernet key from the master password, user salt and server pepper."""
    stretched = _scrypt(master_password, bytes(salt))
    okm = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hashlib.sha256(pepper.encode("utf-8")).digest(),
        info=b"password-manager/vault-key/v1",
    ).derive(stretched)
    return base64.urlsafe_b64encode(okm)


class Vault:
    """Encrypts and decrypts individual credential fields with one Fernet key."""

    def __init__(self, key: bytes) -> None:
        self._fernet = Fernet(key)

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode("utf-8"))

    def decrypt(self, token: bytes) -> str:
        try:
            return self._fernet.decrypt(bytes(token)).decode("utf-8")
        except (InvalidToken, ValueError) as exc:
            raise DecryptionError("Unable to decrypt data.") from exc


# ----------------------------------------------------------------- encrypted backups
def encrypt_backup(payload: dict[str, Any], passphrase: str) -> bytes:
    """Serialise ``payload`` into an encrypted, self-describing backup file."""
    salt = os.urandom(SALT_BYTES)
    key = base64.urlsafe_b64encode(_scrypt(passphrase, salt))
    token = Fernet(key).encrypt(json.dumps(payload).encode("utf-8"))
    envelope = {
        "format": BACKUP_FORMAT,
        "version": BACKUP_VERSION,
        "kdf": "scrypt",
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": token.decode("ascii"),
    }
    return json.dumps(envelope).encode("utf-8")


def decrypt_backup(blob: bytes, passphrase: str) -> dict[str, Any]:
    """Decrypt a backup produced by :func:`encrypt_backup`.

    KDF parameters are fixed constants and are deliberately NOT read from the
    file, so a malicious backup cannot request absurd memory/CPU costs.
    """
    try:
        envelope = json.loads(blob.decode("utf-8"))
        if envelope.get("format") != BACKUP_FORMAT or envelope.get("version") != BACKUP_VERSION:
            raise DecryptionError("Unsupported backup format.")
        salt = base64.b64decode(envelope["salt"], validate=True)
        if len(salt) != SALT_BYTES:
            raise DecryptionError("Invalid backup file.")
        key = base64.urlsafe_b64encode(_scrypt(passphrase, salt))
        plaintext = Fernet(key).decrypt(envelope["data"].encode("ascii"))
        payload = json.loads(plaintext)
    except DecryptionError:
        raise
    except (InvalidToken, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise DecryptionError("Could not decrypt backup.") from exc
    if not isinstance(payload, dict):
        raise DecryptionError("Invalid backup contents.")
    return payload
