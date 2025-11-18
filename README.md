# Hassle Free PGP - Offline PGP Client

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python: 3.7+](https://img.shields.io/badge/python-3.7%2B-blue)
![Security: Offline Only](https://img.shields.io/badge/security-offline%20only-green)
![Security: Audited](https://img.shields.io/badge/security-audited-green)

**A safe, offline, open-source PGP encryption tool for everyone.**

---

Hassle Free PGP is a fully offline, security-focused PGP (Pretty Good Privacy) GUI application written in Python. Created to make solid encryption tools more accessible and easier to use, this tool operates completely offline with zero network access—perfect for privacy-conscious users who want transparent, verifiable security.

## 🔒 Why Hassle Free PGP?

### ✅ Safe & Secure
- **Security audited** - Comprehensive security review completed
- **Strong cryptography** - RSA 4096, AES-256, SHA-256
- **Secure key storage** - File permissions (600/700) protect your keys
- **Passphrase protected** - All private keys encrypted with your passphrase
- **No vulnerabilities** - Path traversal and injection attacks blocked

### 🔌 Completely Offline
- **Zero network requests** - No internet connection required or used
- **No telemetry** - Your data never leaves your computer
- **No auto-updates** - You control when and how to update
- **No keyservers** - All operations local (by design)
- **Air-gap ready** - Works on completely isolated systems

### 📖 Open Source & Transparent
- **MIT Licensed** - Free to use, modify, and distribute
- **Readable code** - Pure Python, easy to audit
- **One dependency** - Only pgpy library for PGP operations
- **Verifiable security** - All code available for inspection
- **Community driven** - Built with privacy in mind

Perfect for: Journalists, activists, security researchers, privacy advocates, and anyone who values secure, offline communication.

## 🚀 Quick Start (Copy/Paste Friendly)

The easiest way to run Hassle Free PGP today is to install Python, create a virtual environment, install the single dependency, and start the GUI. No additional download (such as `Hassle_Free_PGP.zip`) is checked into the repo—you create the app locally or grab a Release asset when one is published.

### macOS (includes “what is Homebrew?” steps)

```bash
# 1. Install Homebrew if you don’t already have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install the newest Python
brew install python

# 3. Download the source (pick ONE of these)
git clone https://github.com/palwoth/Hassle_Free_PGP.git
# OR click “Code → Download ZIP”, unzip, and cd into the folder

cd Hassle_Free_PGP

# 4. Create & activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 5. Install dependencies
pip install -r setup/requirements.txt

# 6. Launch the app
./run.sh
# OR: python -m hassle_free_pgp.app
```

### Windows (PowerShell)

```powershell
# Download the source (Git clone or GitHub ZIP) and open PowerShell in that folder
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r setup/requirements.txt
python -m hassle_free_pgp.app
```

### Linux

```bash
sudo apt install -y python3 python3-venv python3-pip  # adapt for your distro
git clone https://github.com/palwoth/Hassle_Free_PGP.git
cd Hassle_Free_PGP
python3 -m venv .venv
source .venv/bin/activate
pip install -r setup/requirements.txt
./run.sh
# OR: python -m hassle_free_pgp.app
```

Next time you want to use the app, just activate the existing `.venv` and run `./run.sh` again—no need to reinstall anything.

### Need a drag-and-drop `.app`?

When you're ready to ship a Mac bundle to someone else, run:

```bash
cd setup
python setup.py py2app
cd ..
cd dist
zip -r Hassle_Free_PGP.zip "Hassle Free PGP.app"
```

Upload that ZIP to a GitHub Release or your own hosting and share the link. Keeping the binary out of git keeps the repo small and reviewable.

If you hit issues (`tkinter` missing, Python not found, etc.), open an issue and we’ll help!

---

## Features

- **Key Management:**
  - Generate new RSA 4096 keypairs
  - Import existing public/private keys
  - Export keys as ASCII-armored text
  - View keyring with name, email, and fingerprint

- **Encryption/Decryption:**
  - Encrypt messages to one or more recipient public keys
  - Decrypt messages using your private key
  - Support for multiple recipients

- **Signing/Verification:**
  - Create detached signatures
  - Create clear-signed messages
  - Verify signatures with public keys
  - Display signer information

- **Security:**
  - Completely offline (zero network requests)
  - Secure key storage with proper file permissions
  - Passphrase-protected private keys
  - No telemetry or auto-update mechanisms

## 💻 Technical Details

### Requirements

- Python 3.7 or higher
- `pgpy>=0.6.0` (pure Python PGP implementation - installed automatically)
- Tkinter (usually included with Python)

### For Developers: Installation

If you're comfortable with Git and Python:

1. **Clone the repository:**
   ```bash
   git clone https://github.com/palwoth/Hassle_Free_PGP.git
   cd Hassle_Free_PGP
   ```

2. **Create virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r setup/requirements.txt
   ```

4. **Run the application:**
   ```bash
   ./run.sh
   # OR: python -m hassle_free_pgp.app
   ```

## 📖 How to Use

### Creating a New Key

1. Click **Keys → Create New Key**
2. Enter:
   - Name (optional)
   - Email (required)
   - Passphrase (required)
3. Click **Create Key**

### Importing a Key

1. Click **Keys → Import Key**
2. Paste your ASCII-armored PGP key
3. Enter passphrase if importing a protected private key
4. Click **Import Key**

### Exporting a Key

1. Select a key from the keyring (left panel)
2. Click **Keys → Export Key**
3. Choose **Export Public Key** or **Export Private Key**
4. The key will appear in the output area

### Encrypting a Message

1. Click **Operations → Encrypt**
2. Enter your message in the input area
3. Select a recipient's public key from the keyring
4. Click **Encrypt**
5. The encrypted message appears in the output area

### Decrypting a Message

1. Click **Operations → Decrypt**
2. Paste the encrypted message in the input area
3. Select your private key from the keyring
4. Enter your passphrase when prompted
5. Click **Decrypt**
6. The decrypted message appears in the output area

### Signing a Message

1. Click **Operations → Sign**
2. Enter your message in the input area
3. Select your private key from the keyring
4. Enter your passphrase when prompted
5. Click **Sign**
6. The detached signature appears in the output area

### Verifying a Signature

1. Click **Operations → Verify**
2. Paste the signed message (or message + detached signature) in the input area
3. Select the signer's public key from the keyring
4. Click **Verify**
5. Verification result appears in the output area

## Key Storage

Keys are stored locally in:
- **Unix/Linux/macOS:** `~/.pgp_gui/keys/`
- **Windows:** `%USERPROFILE%\.pgp_gui\keys\`

Keys are stored with secure file permissions (600 on Unix systems).

## 🧪 Testing & Verification

### Run Cryptographic Tests

Test that all crypto operations work correctly:

```bash
source venv/bin/activate  # Activate virtual environment
python test_crypto.py
```

This tests:
- ✅ Key generation and export/import
- ✅ Encryption and decryption
- ✅ Signing and verification

### Run Security Tests

Verify protection against attacks:

```bash
source venv/bin/activate
python tests/test_security.py
```

This verifies:
- ✅ Path traversal attacks blocked (12 attack vectors)
- ✅ Input validation working (26 test cases)
- ✅ Malicious fingerprints rejected
- ✅ Command injection blocked

### Run Network Audit

Verify zero network access:

```bash
source venv/bin/activate
python scripts/audit_network_imports.py
```

Expected result: **No network-related imports found** ✅

This scans the entire codebase for:
- Network imports (socket, http, urllib, requests, etc.)
- Suspicious patterns (telemetry, auto-update, keyserver operations)

## Project Structure

```
Hassle_Free_PGP/
├── src/
│   └── hassle_free_pgp/    # Main application package
│       ├── crypto/          # Cryptographic operations
│       │   ├── keys.py
│       │   ├── encrypt_decrypt.py
│       │   └── sign_verify.py
│       ├── storage/         # Key storage
│       │   └── key_store.py
│       ├── gui/              # GUI components
│       │   └── keyring_view.py
│       ├── ui/               # UI utilities
│       │   └── colors.py
│       ├── app.py            # Main application
│       └── pgp_cli.py        # CLI interface
├── tests/                    # Test suite
│   └── test_security.py
├── scripts/                  # Utility scripts
│   ├── audit_network_imports.py
│   └── check_for_keys.sh
├── setup/                    # Setup and build files
│   ├── setup.py
│   ├── requirements.txt
│   └── dev_run.sh
├── config/                   # Configuration files
│   └── bandit.yaml
├── setup.cfg                 # Python tooling config (flake8, etc.)
├── run.sh                    # Quick start script
└── README.md
```

## 🔐 Security

### Security Guarantees

This application is designed with security as the top priority:

✅ **Completely Offline**
- Makes **ZERO** network requests under any circumstances
- No external API calls, no remote servers, no data exfiltration
- Verified by automated audit: `python scripts/audit_network_imports.py`

✅ **Open Source & Auditable**
- All source code available for inspection
- Comprehensive security testing included
- Automated security tests: `python tests/test_security.py`

✅ **Secure by Design**
- Keys stored with proper Unix permissions (600 for files, 700 for directories)
- Passphrases never logged or stored on disk
- No temporary files created (all operations in memory)
- Path traversal attacks blocked with input validation

✅ **Strong Cryptography**
- RSA 4096-bit keys
- AES-256 symmetric encryption
- SHA-256 hashing
- Pure Python implementation (pgpy library)

### What This App Protects Against

- ✅ Network eavesdropping (offline design)
- ✅ Cloud provider access (local storage only)
- ✅ Unauthorized key access (file permissions)
- ✅ Path traversal attacks (input validation)
- ✅ Code injection (no eval/exec/shell commands)

### What This App Cannot Protect Against

Like all software, this tool assumes a trusted local environment and cannot protect against:
- ❌ Physical access to unlocked computer
- ❌ Compromised operating system
- ❌ Keyloggers or screen capture malware
- ❌ Malicious clipboard managers

**⚠️ Security Notice:** When you copy private keys to clipboard, they remain there until manually cleared. Always clear your clipboard after copying sensitive data.

### For Maximum Security

1. **Use on air-gapped machine** - Install on a computer with no network connectivity
2. **Use strong passphrases** - Unique, long passphrases for each key
3. **Lock your computer** - When stepping away
4. **Use disk encryption** - Full disk encryption (FileVault, BitLocker, LUKS)
5. **Verify the code** - Review source before use in high-security environments
6. **Backup safely** - Store key backups on encrypted, offline media

For security concerns, please open a GitHub issue or contact the maintainer.

## Limitations

- Detached signature parsing uses simple heuristics
- Binary key formats not supported (ASCII-armored only)
- No keyserver integration (by design - offline only)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2025 Pierce Alworth (@palwoth)

## 🤝 Contributing

This is a security-focused application. Contributions are welcome, but must maintain the security and offline guarantees.

**Before contributing:**
1. ⚠️ **Understand security requirements** - Must maintain offline-only operation
2. 🚫 **No network dependencies** - Must remain completely offline
3. ✅ **Run security tests** - `python tests/test_security.py` must pass
4. ✅ **Run network audit** - `python scripts/audit_network_imports.py` must be clean
5. 🧪 **Test on air-gapped system** - If possible

**Security-critical changes** (crypto, key storage, input validation) require extra scrutiny.

## 🙏 Acknowledgments

Built with a focus on making solid encryption accessible to everyone. Special thanks to the `pgpy` library maintainers for providing a pure Python PGP implementation.

## 📞 Support & Issues

Found a bug? Have a feature request?
- Open an issue on GitHub
- For security vulnerabilities, please contact [@palwoth](https://github.com/palwoth) directly

**Note:** This is a passion project by Pierce Alworth ([@palwoth](https://github.com/palwoth)) to make encryption more accessible. Not affiliated with any company or organization.

---

**Made with 🔐 for privacy-conscious users everywhere.**

