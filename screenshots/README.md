# Screenshots

Capture these with a **demo account and fake data only** (never real credentials), then save the PNGs in this folder using the file names below and reference them from the main README, e.g. `![Dashboard](screenshots/03-dashboard.png)`.

Tip: take each shot in both light and dark mode if you want a gallery (`*-dark.png`). A 1280×800 window works well; add one 390 px-wide mobile shot to show the responsive layout.

| File | Page | What it should show |
|------|------|---------------------|
| `01-register.png` | `/register` | Account creation form with the master-password guidance text |
| `02-login.png` | `/login` | Sign-in card; optionally a red "Invalid credentials…" alert |
| `03-dashboard.png` | `/dashboard` | Four stat cards (accounts, weak, reused, old), the security-score bar, and the recently-added list |
| `04-vault.png` | `/vault` | Table of accounts with strength badges and action buttons; ideally one password revealed |
| `05-vault-search.png` | `/vault?q=git&field=website` | Search bar with the field selector and filtered results |
| `06-add-password.png` | `/credentials/new` | Form with the live strength meter and the generator panel (length slider + character checkboxes) |
| `07-audit.png` | `/audit` | Weak / reused / old password panels and the activity log table (login and password events) |
| `08-backup.png` | `/backup` | Export (master password + passphrase) and Import (file + passphrase) cards |
| `09-dark-mode.png` | any page | The dashboard or vault in dark mode |
| `10-mobile.png` | `/vault` at ~390 px | Collapsed navbar and horizontally scrollable table |

## Suggested demo data

| Account | Username | Password to enter | Purpose |
|---------|----------|-------------------|---------|
| GitHub | octocat | a generated 20-character password | Strong entry |
| Old Forum | demo_user | `password123` | Triggers the weak warning |
| Shop A / Shop B | demo@example.com | the same generated password in both | Triggers duplicate detection |
