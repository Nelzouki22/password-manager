# SecureVault — a self-hosted password manager

A multi-user password manager built with **Flask**, **SQLite** and **Bootstrap 5**. Credentials are encrypted with **Fernet** (from the `cryptography` library), master passwords are hashed with **bcrypt**, and every sensitive action is written to an audit log.

> **Status:** a well-tested learning/portfolio-grade implementation that follows secure-coding practice. It has **not** had an independent security audit. Read [Security limitations](#security-limitations) before storing anything you cannot afford to lose.

## Features

| Area | What you get |
|------|--------------|
| Accounts | Registration, login, logout, multi-user isolation |
| Vault | Add, edit, delete, view and **search** (by website, username or account name) |
| Generator | Secure random passwords: length 8–128, upper/lower/numbers/symbols, optional "avoid look-alikes" |
| Audit | Strength scoring, weak-password warnings, duplicate (reused) detection, stale-password check, 0–100 vault score |
| Logging | Login attempts, password create / update / delete / reveal, lockouts, backups — stored in the DB **and** a rotating `logs/audit.log` |
| Backup | Export to an encrypted file, import an encrypted backup |
| UI | Responsive Bootstrap 5, dark mode (remembers your choice), dashboard |
| Ops | Docker + Compose, health-check endpoint, unit/integration tests |

## Project structure

```
password-manager/
├── app.py                # Flask app factory, routes, security headers
├── auth.py               # bcrypt, lockout, sessions, CSRF, rate limiting
├── encryption.py         # Fernet vault, key derivation, encrypted backups
├── database.py           # SQLite connection handling + schema (auto-created)
├── models.py             # Data-access functions (all queries parameterised)
├── password_generator.py # Secure password generator
├── security_audit.py     # Strength, weak/duplicate/old checks, vault score
├── templates/            # Jinja2 pages (Bootstrap 5)
├── static/               # css/app.css, js/app.js, js/theme.js
├── tests/                # unittest suite (21 tests)
├── screenshots/          # README with the shots to capture
├── requirements.txt
├── Dockerfile  docker-compose.yml  .env.example  .gitignore  .dockerignore
└── README.md
```

## Quick start

Requires **Python 3.10+**.

```bash
git clone <your-repo-url> password-manager && cd password-manager

python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env                 # Windows: copy .env.example .env
```

Generate two secrets (run it twice) and paste them into `.env` as `SECRET_KEY` and `ENCRYPTION_PEPPER`:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Start the app and open <http://127.0.0.1:5000>:

```bash
flask --app app run        # or: python app.py
```

The SQLite database and its tables are created automatically on first run (`instance/vault.db`, permissions `0600`).

> **Back up `ENCRYPTION_PEPPER` separately from the database.** It is mixed into every vault key. If it is lost or changed, stored passwords become permanently unreadable.

### Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `SECRET_KEY` | *(required, ≥32 chars)* | Signs session cookies and CSRF tokens |
| `ENCRYPTION_PEPPER` | *(required, ≥32 chars)* | Server-side secret mixed into vault keys |
| `DATABASE_PATH` | `instance/vault.db` | SQLite file location |
| `LOG_DIR` | `logs` | Audit log directory |
| `SESSION_IDLE_MINUTES` | `15` | Auto sign-out after inactivity |
| `MAX_LOGIN_ATTEMPTS` | `5` | Failed logins before an account locks |
| `LOCKOUT_MINUTES` | `15` | Lock duration |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` when served over HTTPS |
| `TRUST_PROXY` | `false` | Set `true` only behind your own reverse proxy |

The app refuses to start if either secret is missing or shorter than 32 characters.

## Docker

```bash
cp .env.example .env     # fill in SECRET_KEY and ENCRYPTION_PEPPER
docker compose up --build -d
```

Open <http://127.0.0.1:8000>. Data lives in the `vault-data` volume. The container runs as a non-root user, with a read-only filesystem, dropped capabilities and a health check. For access beyond localhost, put an **HTTPS** reverse proxy (Caddy, nginx, Traefik) in front and set `SESSION_COOKIE_SECURE=true` and `TRUST_PROXY=true`.

The image runs **one** Gunicorn worker (with several threads) on purpose — see [Security limitations](#security-limitations).

## User guide

1. **Register** — pick a username and a master password (≥12 characters, rated *Strong*). A passphrase of several unrelated words plus a number or symbol works well. **There is no password reset**: your master password is part of the encryption key.
2. **Sign in** — you are signed out automatically after 15 idle minutes.
3. **Add a password** — *Add* in the menu. Fill in account name, username, optional website, and a password. Use the **generator** panel to pick length and character types, then *Generate & fill*. A live meter rates the password; weak or reused passwords trigger a warning after saving.
4. **Find things** — *Vault* lists everything. Search by website, username or account name (or all three).
5. **Use a password** — the eye icon reveals it for 15 seconds; the clipboard icon copies it and tries to clear the clipboard after 30 seconds.
6. **Edit / delete** — pencil and trash icons. When editing, leave the password blank to keep the current one.
7. **Security audit** — lists weak passwords, reused passwords and passwords unchanged for 180+ days, plus your activity log.
8. **Backup** — *Backup → Export* needs your master password and a separate backup passphrase, and downloads a `.pwmbackup` file. *Import* adds the entries from a backup to your vault (it never removes or overwrites existing ones).
9. **Dark mode** — the moon/sun button in the top bar.

## Security features

### How your data is protected

```
master password ──► bcrypt (cost 12, after SHA-256 pre-hash) ──► stored hash   (login check only)
        │
        └─► scrypt (N=2^15, r=8, p=1, per-user random salt)
                 └─► HKDF-SHA256 (keyed with SHA-256 of ENCRYPTION_PEPPER)
                          └─► 256-bit vault key ──► Fernet ──► username + password ciphertext
```

- **No plaintext passwords, ever.** Saved usernames and passwords are Fernet-encrypted (authenticated encryption — tampering is detected). The master password is stored only as a bcrypt hash.
- **Two secrets are needed to decrypt:** the user's master password *and* the server's `ENCRYPTION_PEPPER` (an environment variable). A stolen database file alone is useless.
- **Per-user keys.** Each user has a random salt, so one user's key cannot decrypt another's data. Every query is also scoped by user ID, so guessing IDs returns *404*.
- **bcrypt pre-hash** avoids bcrypt's silent 72-byte truncation. Login does equal work for unknown users (dummy hash) to prevent user enumeration by timing, and all failures show one generic message.
- **Brute-force defence:** accounts lock for 15 minutes after 5 failures; a per-IP limiter caps sign-in (20 / 10 min) and sign-up (10 / hour) attempts.
- **Session safety:** the unlocked vault key lives only in server memory, never in the cookie. Cookies are signed, `HttpOnly`, `SameSite=Strict` (and `Secure` over HTTPS); sessions expire when idle and are rebuilt at login.
- **CSRF protection** on every POST (form field or `X-CSRF-Token` header).
- **Re-authentication** (master password) is required to export the vault.
- **Browser hardening:** strict Content-Security-Policy (no inline scripts or styles), `X-Frame-Options: DENY`, `nosniff`, `no-referrer`, `Cache-Control: no-store`, HSTS when `SESSION_COOKIE_SECURE=true`. Website links must be `http(s)` and open with `rel="noopener noreferrer nofollow"`; passwords are inserted with `textContent`, never parsed as HTML.
- **Injection safety:** parameterised SQL only; Jinja2 auto-escaping; log values are sanitised against log injection.
- **Backups** use a random salt and a passphrase-derived scrypt key. KDF parameters are *not* read from the file, so a malicious backup can't demand huge memory. Uploads are capped at 2 MB / 5,000 entries and every field is validated.
- **Audit logging** never records passwords or stored usernames.

### What is *not* encrypted

Account name, website URL and timestamps are stored as plain text so the vault can be listed and searched. Don't put secrets in those fields.

### Security limitations

- **Single process.** Unlocked keys are held in the memory of the one server process. Run one worker (threads are fine); a restart signs everyone out. Scaling out would need an external, secured key store.
- **Memory.** Python cannot reliably wipe secrets from memory; someone with access to the running server could read keys of signed-in users.
- **Lockout can be abused** to temporarily block a known username (a deliberate trade-off).
- **No 2FA, master-password change or recovery yet** (see roadmap). Forgetting the master password means losing the data.
- **Bootstrap is loaded from the jsDelivr CDN** without Subresource Integrity hashes. For production, download the files into `static/` and tighten the CSP to `'self'`.
- Always serve over **HTTPS**. Treat this as a hardened starting point, not a replacement for audited products.

## Database schema

Created automatically by `database.py`:

```sql
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   BLOB    NOT NULL,           -- bcrypt hash of the master password
    kdf_salt        BLOB    NOT NULL,           -- per-user salt for the vault key
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_login_at   TEXT
);

CREATE TABLE credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    account_name  TEXT    NOT NULL,
    username_enc  BLOB    NOT NULL,             -- Fernet token
    password_enc  BLOB    NOT NULL,             -- Fernet token
    website_url   TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE audit_logs (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username_attempted TEXT,
    event              TEXT NOT NULL,
    detail             TEXT,
    ip_address         TEXT,
    created_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
```

Logged events: `login_success`, `login_failed`, `login_blocked`, `account_locked`, `login_rate_limited`, `reauth_failed`, `user_registered`, `logout`, `password_created`, `password_updated`, `credential_edited`, `password_deleted`, `password_revealed`, `backup_exported`, `backup_imported`, `backup_import_failed`.

## Routes

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/register`, `/login` | GET, POST | – | Create account / sign in |
| `/logout` | POST | ✔ | Sign out |
| `/dashboard` | GET | ✔ | Stats, security score, recent entries |
| `/vault?q=&field=` | GET | ✔ | List and search (`all`, `website`, `username`, `account`) |
| `/credentials/new` | GET, POST | ✔ | Add |
| `/credentials/<id>/edit` | GET, POST | ✔ | Edit |
| `/credentials/<id>/delete` | POST | ✔ | Delete |
| `/credentials/<id>/reveal` | POST | ✔ | Return one decrypted password (JSON) |
| `/api/generate` | GET | ✔ | `length, upper, lower, digits, symbols, ambiguous` |
| `/api/strength` | POST | ✔ | Strength of a password (JSON body) |
| `/audit` | GET | ✔ | Security report + activity log |
| `/backup`, `/backup/export`, `/backup/import` | GET, POST | ✔ | Encrypted backup |
| `/healthz` | GET | – | Health check |

## Backup file format

A JSON envelope: `{"format":"pwm-backup","version":1,"kdf":"scrypt","salt":"<base64>","data":"<Fernet token>"}`. The token decrypts to `{"exported_at": ..., "credentials":[{account_name, username, password, website_url, created_at}, ...]}`.

## Testing

```bash
python -m unittest discover -s tests -t . -v
```

The suite (21 tests) covers the generator, strength scoring, duplicate detection, encryption round-trips and tamper detection, registration rules, bcrypt storage, login/lockout, CSRF, security headers, full CRUD, search, **encryption-at-rest (plaintext never appears in the DB file)**, cross-user access attempts, URL validation, the audit page and export/import.

## Production checklist

- [ ] HTTPS reverse proxy; `SESSION_COOKIE_SECURE=true`; `TRUST_PROXY=true`
- [ ] `SECRET_KEY` and `ENCRYPTION_PEPPER` from a secrets manager; pepper backed up separately
- [ ] Regular backups of the database volume
- [ ] Bootstrap vendored locally (or SRI added) and CSP tightened
- [ ] Exactly one Gunicorn worker process
- [ ] Log shipping / monitoring for `account_locked` and `login_failed` events

## Roadmap

Master-password change (re-encrypt vault), TOTP two-factor authentication, password history, CSV import from other managers, breach checking (k-anonymity), per-entry notes and tags.

## Screenshots

See [`screenshots/README.md`](screenshots/README.md) for the list of shots to capture and what each should show.
