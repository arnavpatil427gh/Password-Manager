# LocalVault

A local, offline password generator and manager with a clean desktop GUI inspired by Google Password Manager. Built with Python and Tkinter. Your passwords are stored in a single encrypted file on your own device and are never sent anywhere.

> **Disclaimer:** This is a learning/hobby project and has not been independently audited. For critical accounts, consider an established, audited password manager.

<!-- Add a screenshot here, e.g. ![LocalVault screenshot](screenshots/main.png) -->

## Features

- **Local-only storage:** one encrypted vault file, no cloud, no network access
- **Strong encryption:** AES-256-GCM with a key derived from your master password using scrypt
- **Password generator:** cryptographically secure (`secrets`), adjustable length, optional symbols and digits, guarantees at least one character of each selected type
- **Google-style interface:** sidebar, search bar, avatar list, and detail/edit dialogs
- **Password Checkup:** flags reused and weak passwords
- **Clipboard protection:** copied passwords are cleared from the clipboard after 30 seconds
- **Auto-lock:** the vault locks after 5 minutes of inactivity
- **Safe saving:** atomic writes with an automatic `.bak` backup
- **Brute-force slowdown:** the unlock button is delayed after failed attempts

## Requirements

- Python 3.9 or newer
- Tkinter (bundled with Python on Windows and macOS; on Debian/Ubuntu install it with `sudo apt install python3-tk`)
- [`cryptography`](https://pypi.org/project/cryptography/)

## Installation

```bash
git clone https://github.com/arnavpatil427gh/Password-Manager
cd localvault
```

Create and activate a virtual environment (recommended):

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

Install the dependency:

```bash
pip install -r requirements.txt
```

## Usage

```bash
python app.py
```

1. **First launch:** create a master password (at least 8 characters, 12 or more recommended).
2. **Add passwords:** click **+ Add password**, or use **Generate** to create a strong one.
3. **View or copy:** click any entry to show, hide, or copy its username and password.
4. **Checkup:** open the Checkup tab to see weak and reused passwords.
5. **Lock:** use **Lock vault** in the sidebar when you step away.

Your vault is stored at:

| OS | Path |
|---|---|
| Windows | `C:\Users\<you>\.localvault\vault.dat` |
| macOS / Linux | `~/.localvault/vault.dat` |

A backup of the previous save is kept next to it as `vault.bak`. Back up this folder regularly.

> **Important:** there is no password recovery. If you forget your master password, your vault cannot be decrypted.

## How it works

| Step | Detail |
|---|---|
| Key derivation | scrypt (`n=2^15, r=8, p=1`) with a random 16-byte salt turns your master password into a 256-bit key |
| Encryption | AES-256-GCM with a fresh random 12-byte nonce on every save |
| Integrity | GCM authentication detects a wrong password and any tampering with the file |
| File format | JSON header (version, KDF parameters, salt, nonce) plus base64 ciphertext |
| Master password | Never stored, not even as a hash |

The vault contents are a JSON structure of entries (`site`, `username`, `password`, `notes`, `created`, `modified`) that is decrypted into memory on unlock and re-encrypted on every change.

## Project structure

```
localvault/
├── app.py            # Tkinter GUI (login, main window, dialogs)
├── generator.py      # secure password generation
├── crypto.py         # key derivation, encrypt/decrypt, file format
├── storage.py        # Vault class: load/save, entries, master password change
└── requirements.txt
```

The logic (`generator`, `crypto`, `storage`) is independent of the UI, so another interface (such as a CLI) could be added without touching the core.

## Configuration

Adjustable constants at the top of `app.py`:

```python
AUTO_LOCK_MS = 5 * 60 * 1000   # inactivity timeout
CLIP_CLEAR_MS = 30 * 1000      # clipboard clear delay
```

The vault location is set by `DEFAULT_PATH` in `storage.py`.

## Security notes and limitations

- Python cannot reliably wipe secrets from memory, so decrypted entries stay in memory while the vault is unlocked.
- The clipboard is cleared after 30 seconds, but clipboard managers or history tools may keep a copy.
- Malware or a keylogger on your device can capture your master password. This tool protects the vault file at rest, not a compromised machine.
- A weak master password weakens everything. Use a long, unique passphrase.
- There is no sync between devices. Copy the vault file manually if you need it elsewhere.
- On macOS, Tk ignores custom button background colors, so buttons look plainer.

## Roadmap

- [ ] Unit tests (encryption round trip, wrong password, tampered file)
- [ ] Encrypted export and import (including browser CSV)
- [ ] Passphrase (random words) generator
- [ ] Password strength meter
- [ ] Breach check via HaveIBeenPwned k-anonymity API (optional)
- [ ] TOTP (2FA code) storage
- [ ] Dark mode

## Contributing

Issues and pull requests are welcome. For security-related problems, please open an issue describing the concern without including any real vault data.

## License

Released under the [MIT License](LICENSE).
