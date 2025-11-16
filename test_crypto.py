#!/usr/bin/env python3
"""CLI test script for Phase 1 crypto layer."""
# Compatibility shim for Python 3.13+ (imghdr removed)
import compat_imghdr  # noqa: F401
import sys
from crypto.keys import generate_keypair, import_key, export_public_key, export_private_key
from crypto.encrypt_decrypt import encrypt_message, decrypt_message
from crypto.sign_verify import sign_message, verify_signature


def test_key_generation():
    """Test key generation and export."""
    print("=" * 60)
    print("Testing Key Generation")
    print("=" * 60)
    
    # Generate a test keypair
    print("\n1. Generating RSA 4096 keypair...")
    key = generate_keypair("Test User", "test@example.com", "test_passphrase_123")
    print("   ✓ Key generated successfully")
    
    # Export public key
    print("\n2. Exporting public key...")
    public_key_armored = export_public_key(key)
    print(f"   ✓ Public key exported ({len(public_key_armored)} chars)")
    print(f"   First 80 chars: {public_key_armored[:80]}...")
    
    # Export private key
    print("\n3. Exporting private key...")
    private_key_armored = export_private_key(key)
    print(f"   ✓ Private key exported ({len(private_key_armored)} chars)")
    print(f"   First 80 chars: {private_key_armored[:80]}...")
    
    # Import public key
    print("\n4. Importing public key...")
    imported_public = import_key(public_key_armored)
    print(f"   ✓ Public key imported successfully")
    print(f"   Fingerprint: {imported_public.fingerprint}")
    
    # Import private key
    print("\n5. Importing private key...")
    imported_private = import_key(private_key_armored, "test_passphrase_123")
    print(f"   ✓ Private key imported successfully")
    
    return key, imported_public, imported_private


def test_encryption_decryption(public_key, private_key):
    """Test encryption and decryption."""
    print("\n" + "=" * 60)
    print("Testing Encryption/Decryption")
    print("=" * 60)
    
    plaintext = "This is a test message for encryption!"
    print(f"\n1. Plaintext: {plaintext}")
    
    # Encrypt
    print("\n2. Encrypting message...")
    encrypted = encrypt_message(plaintext, [public_key])
    print(f"   ✓ Message encrypted ({len(encrypted)} chars)")
    print(f"   First 80 chars: {encrypted[:80]}...")
    
    # Decrypt
    print("\n3. Decrypting message...")
    decrypted, metadata = decrypt_message(encrypted, private_key, "test_passphrase_123")
    print(f"   ✓ Message decrypted")
    print(f"   Decrypted: {decrypted}")
    print(f"   Metadata: {metadata}")
    
    assert decrypted == plaintext, "Decrypted message doesn't match original!"
    print("\n   ✓ Encryption/Decryption test PASSED")


def test_signing_verification(public_key, private_key):
    """Test signing and verification."""
    print("\n" + "=" * 60)
    print("Testing Signing/Verification")
    print("=" * 60)
    
    message = "This is a test message to sign!"
    print(f"\n1. Message: {message}")
    
    # Sign (detached)
    print("\n2. Creating detached signature...")
    signature = sign_message(message, private_key, "test_passphrase_123", detached=True)
    print(f"   ✓ Signature created ({len(signature)} chars)")
    print(f"   First 80 chars: {signature[:80]}...")
    
    # Verify detached signature
    print("\n3. Verifying detached signature...")
    verified, info = verify_signature(message, signature, public_key)
    if verified:
        print(f"   ✓ Signature verified successfully")
        print(f"   Signer info: {info}")
    else:
        print(f"   ✗ Signature verification failed")
        print(f"   Info: {info}")
        sys.exit(1)
    
    # Test clear-signed message
    print("\n4. Creating clear-signed message...")
    clear_signed = sign_message(message, private_key, "test_passphrase_123", detached=False)
    print(f"   ✓ Clear-signed message created ({len(clear_signed)} chars)")
    
    # Verify clear-signed message
    print("\n5. Verifying clear-signed message...")
    verified, info = verify_signature(clear_signed, None, public_key)
    if verified:
        print(f"   ✓ Clear-signed message verified successfully")
        print(f"   Signer info: {info}")
    else:
        print(f"   ✗ Verification failed")
        print(f"   Info: {info}")
        sys.exit(1)
    
    print("\n   ✓ Signing/Verification test PASSED")


def main():
    """Run all crypto tests."""
    print("\n" + "=" * 60)
    print("PGP Crypto Layer Test Suite")
    print("=" * 60)
    
    try:
        # Test key operations
        key, public_key, private_key = test_key_generation()
        
        # Test encryption/decryption
        test_encryption_decryption(public_key, private_key)
        
        # Test signing/verification
        test_signing_verification(public_key, private_key)
        
        print("\n" + "=" * 60)
        print("ALL TESTS PASSED!")
        print("=" * 60)
        return 0
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

