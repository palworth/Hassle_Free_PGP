#!/usr/bin/env python3
"""
Command-line interface for PGP operations.
Works without Tkinter - perfect for servers and systems without GUI.
"""
import sys

from .crypto.keys import (
    ensure_private_key_is_protected,
    export_private_key,
    export_public_key,
    generate_keypair,
    import_key as crypto_import_key,
)
from .crypto.encrypt_decrypt import encrypt_message, decrypt_message
from .crypto.sign_verify import sign_message, verify_signature
from .storage.key_store import KeyStore


class PGPCLI:
    """Command-line PGP interface."""

    def __init__(self):
        self.key_store = KeyStore()

    def show_menu(self):
        """Display main menu."""
        print("\n" + "=" * 60)
        print("PGP CLI - Offline PGP Client")
        print("=" * 60)
        print("\n[Key Management]")
        print("  1. Create new key")
        print("  2. Import key")
        print("  3. Export key")
        print("  4. List keys")
        print("\n[Operations]")
        print("  5. Encrypt message")
        print("  6. Decrypt message")
        print("  7. Sign message")
        print("  8. Verify signature")
        print("\n  0. Exit")
        print("=" * 60)

    def create_key(self):
        """Create a new keypair."""
        print("\n--- Create New Key ---")
        name = input("Name (optional): ").strip()
        email = input("Email (required): ").strip()

        if not email:
            print("❌ Error: Email is required")
            return

        passphrase = input("Passphrase: ").strip()
        if not passphrase:
            print("❌ Error: Passphrase is required")
            return

        try:
            print("\n🔑 Generating RSA 4096 keypair (this may take a moment)...")
            key = generate_keypair(name, email, passphrase)
            self.key_store.add_key(key, name, email)
            print("✓ Key created successfully!")
            print(f"  Fingerprint: {key.fingerprint}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def import_key(self):
        """Import a key."""
        print("\n--- Import Key ---")
        print("Paste your ASCII-armored key (Ctrl+D when done):")

        lines = []
        try:
            while True:
                line = input()
                lines.append(line)
        except EOFError:
            pass

        armored_key = '\n'.join(lines).strip()

        if not armored_key:
            print("❌ Error: No key provided")
            return

        passphrase = input("\nPassphrase (if protected, otherwise press Enter): ").strip() or None

        try:
            key = crypto_import_key(armored_key, passphrase)
            if not key.is_public and not key.is_protected:
                new_passphrase = passphrase or input(
                    "\nThis private key is unprotected. Enter a new passphrase to secure it: ").strip()
                if not new_passphrase:
                    print("❌ Error: Private keys must be passphrase-protected before storage")
                    return
                ensure_private_key_is_protected(key, new_passphrase)
            name = ''
            email = ''
            if key.userids:
                uid = key.userids[0]
                name = uid.name or ''
                email = uid.email or ''

            self.key_store.add_key(key, name, email)
            print("✓ Key imported successfully!")
            print(f"  Fingerprint: {key.fingerprint}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def export_key(self):
        """Export a key."""
        keys = self.key_store.list_keys()
        if not keys:
            print("❌ No keys in keyring")
            return

        print("\n--- Export Key ---")
        print("\nAvailable keys:")
        for i, key_info in enumerate(keys, 1):
            print(f"  {i}. {key_info['name']} <{key_info['email']}> [{key_info['fingerprint'][-16:]}]")

        try:
            choice = int(input("\nSelect key number: "))
            if choice < 1 or choice > len(keys):
                print("❌ Invalid selection")
                return

            key_info = keys[choice - 1]
            fingerprint = key_info['fingerprint']

            print("\n  1. Export public key")
            if key_info.get('has_private'):
                print("  2. Export private key")

            export_choice = input("\nChoice: ").strip()

            if export_choice == '1':
                key = self.key_store.get_key(fingerprint, private=False)
                armored = export_public_key(key)
                print("\n--- Public Key ---")
                print(armored)
            elif export_choice == '2' and key_info.get('has_private'):
                key = self.key_store.get_key(fingerprint, private=True)
                armored = export_private_key(key)
                print("\n--- Private Key ---")
                print(armored)
            else:
                print("❌ Invalid choice")
        except (ValueError, Exception) as e:
            print(f"❌ Error: {e}")

    def list_keys(self):
        """List all keys."""
        keys = self.key_store.list_keys()
        if not keys:
            print("\n❌ No keys in keyring")
            return

        print("\n--- Keyring ---")
        for i, key_info in enumerate(keys, 1):
            private_marker = "🔐" if key_info.get('has_private') else "🔓"
            print(f"{i}. {private_marker} {key_info['name']} <{key_info['email']}>")
            print(f"   Fingerprint: {key_info['fingerprint']}")

    def encrypt_message(self):
        """Encrypt a message."""
        keys = self.key_store.list_keys()
        if not keys:
            print("❌ No keys in keyring")
            return

        print("\n--- Encrypt Message ---")
        print("\nAvailable public keys:")
        for i, key_info in enumerate(keys, 1):
            print(f"  {i}. {key_info['name']} <{key_info['email']}> [{key_info['fingerprint'][-16:]}]")

        try:
            choice = int(input("\nSelect recipient key number: "))
            if choice < 1 or choice > len(keys):
                print("❌ Invalid selection")
                return

            key_info = keys[choice - 1]
            fingerprint = key_info['fingerprint']

            print("\nEnter message (Ctrl+D when done):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass

            plaintext = '\n'.join(lines).strip()
            if not plaintext:
                print("❌ Error: No message provided")
                return

            public_key = self.key_store.get_key(fingerprint, private=False)
            encrypted = encrypt_message(plaintext, [public_key])

            print("\n--- Encrypted Message ---")
            print(encrypted)
        except Exception as e:
            print(f"❌ Error: {e}")

    def decrypt_message(self):
        """Decrypt a message."""
        keys = [k for k in self.key_store.list_keys() if k.get('has_private')]
        if not keys:
            print("❌ No private keys in keyring")
            return

        print("\n--- Decrypt Message ---")
        print("\nAvailable private keys:")
        for i, key_info in enumerate(keys, 1):
            print(f"  {i}. {key_info['name']} <{key_info['email']}> [{key_info['fingerprint'][-16:]}]")

        try:
            choice = int(input("\nSelect your private key number: "))
            if choice < 1 or choice > len(keys):
                print("❌ Invalid selection")
                return

            key_info = keys[choice - 1]
            fingerprint = key_info['fingerprint']

            print("\nPaste encrypted message (Ctrl+D when done):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass

            ciphertext = '\n'.join(lines).strip()
            if not ciphertext:
                print("❌ Error: No message provided")
                return

            passphrase = input("\nPassphrase: ").strip()
            if not passphrase:
                print("❌ Error: Passphrase required")
                return

            private_key = self.key_store.get_key(fingerprint, private=True)
            plaintext, metadata = decrypt_message(ciphertext, private_key, passphrase)

            print("\n--- Decrypted Message ---")
            print(plaintext)
            if metadata:
                print("\n--- Metadata ---")
                for key, value in metadata.items():
                    print(f"  {key}: {value}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def sign_message(self):
        """Sign a message."""
        keys = [k for k in self.key_store.list_keys() if k.get('has_private')]
        if not keys:
            print("❌ No private keys in keyring")
            return

        print("\n--- Sign Message ---")
        print("\nAvailable private keys:")
        for i, key_info in enumerate(keys, 1):
            print(f"  {i}. {key_info['name']} <{key_info['email']}> [{key_info['fingerprint'][-16:]}]")

        try:
            choice = int(input("\nSelect your private key number: "))
            if choice < 1 or choice > len(keys):
                print("❌ Invalid selection")
                return

            key_info = keys[choice - 1]
            fingerprint = key_info['fingerprint']

            print("\nEnter message to sign (Ctrl+D when done):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass

            message = '\n'.join(lines).strip()
            if not message:
                print("❌ Error: No message provided")
                return

            passphrase = input("\nPassphrase: ").strip()
            if not passphrase:
                print("❌ Error: Passphrase required")
                return

            private_key = self.key_store.get_key(fingerprint, private=True)
            signature = sign_message(message, private_key, passphrase, detached=True)

            print("\n--- Detached Signature ---")
            print(signature)
        except Exception as e:
            print(f"❌ Error: {e}")

    def verify_signature(self):
        """Verify a signature."""
        keys = self.key_store.list_keys()
        if not keys:
            print("❌ No keys in keyring")
            return

        print("\n--- Verify Signature ---")
        print("\nAvailable public keys:")
        for i, key_info in enumerate(keys, 1):
            print(f"  {i}. {key_info['name']} <{key_info['email']}> [{key_info['fingerprint'][-16:]}]")

        try:
            choice = int(input("\nSelect signer's public key number: "))
            if choice < 1 or choice > len(keys):
                print("❌ Invalid selection")
                return

            key_info = keys[choice - 1]
            fingerprint = key_info['fingerprint']

            print("\nPaste message and signature (Ctrl+D when done):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass

            content = '\n'.join(lines).strip()
            if not content:
                print("❌ Error: No content provided")
                return

            public_key = self.key_store.get_key(fingerprint, private=False)

            # Try to detect signature format
            if "-----BEGIN PGP SIGNATURE-----" in content:
                # Detached signature
                parts = content.split("-----BEGIN PGP SIGNATURE-----")
                message = parts[0].strip()
                signature = "-----BEGIN PGP SIGNATURE-----" + parts[1]
                verified, info = verify_signature(message, signature, public_key)
            else:
                # Clear-signed message
                verified, info = verify_signature(content, None, public_key)

            if verified:
                print("\n✓ SIGNATURE VERIFIED")
                print(f"  Signer: {info.get('signer_name', 'Unknown')} <{info.get('signer_email', 'Unknown')}>")
                print(f"  Key ID: {info.get('key_id', 'Unknown')}")
                print(f"  Fingerprint: {info.get('fingerprint', 'Unknown')}")
            else:
                print("\n✗ SIGNATURE VERIFICATION FAILED")
                if 'error' in info:
                    print(f"  Error: {info['error']}")
        except Exception as e:
            print(f"❌ Error: {e}")

    def run(self):
        """Main CLI loop."""
        while True:
            self.show_menu()
            choice = input("\nChoice: ").strip()

            if choice == '0':
                print("\nGoodbye!")
                break
            elif choice == '1':
                self.create_key()
            elif choice == '2':
                self.import_key()
            elif choice == '3':
                self.export_key()
            elif choice == '4':
                self.list_keys()
            elif choice == '5':
                self.encrypt_message()
            elif choice == '6':
                self.decrypt_message()
            elif choice == '7':
                self.sign_message()
            elif choice == '8':
                self.verify_signature()
            else:
                print("❌ Invalid choice")

            input("\nPress Enter to continue...")


def main():
    """Entry point."""
    try:
        cli = PGPCLI()
        cli.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
