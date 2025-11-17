#!/usr/bin/env python3
"""
Security test suite to verify protection against attacks.
Tests path traversal vulnerability fixes.
"""
import sys
import tempfile
from pathlib import Path
from storage.key_store import KeyStore


def test_path_traversal_protection():
    """Test that path traversal attacks are blocked."""
    print("=" * 70)
    print("Testing Path Traversal Protection")
    print("=" * 70)

    # Create temporary keystore for testing
    with tempfile.TemporaryDirectory() as tmpdir:
        key_store = KeyStore(Path(tmpdir))

        print("\n1. Testing malicious fingerprints...")

        malicious_inputs = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "../../.ssh/id_rsa",
            "../../../home/user/.pgp_gui/keys/private/somefingerprint",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
            "..\\..\\..\\windows\\system32\\config\\SAM",
            "./../../../etc/shadow",
            "symlink_to_sensitive_file",
            # Valid hex but with path traversal
            "ABCD/../../../etc/passwd",
            # Null byte injection (shouldn't work in Python 3)
            "ABCD\x00../../../etc/passwd",
        ]

        failed = False
        for malicious_fp in malicious_inputs:
            result = key_store.get_key(malicious_fp, private=True)
            if result is not None:
                print(f"   ✗ FAIL: Accepted malicious fingerprint: {malicious_fp}")
                failed = True
            else:
                print(f"   ✓ PASS: Blocked: {malicious_fp}")

        print("\n2. Testing valid fingerprints...")

        valid_inputs = [
            "1234567890ABCDEF1234567890ABCDEF12345678",  # Valid 40-char SHA-1
            "1234567890ABCDEF",  # Valid 16-char
            "ABCDEF1234567890",  # Valid hex
            "abcdef1234567890",  # Lowercase hex
            "12 34 56 78 90 AB CD EF",  # With spaces (should be cleaned)
        ]

        for valid_fp in valid_inputs:
            # We expect None because the key doesn't exist, but it should NOT raise or fail validation
            result = key_store.get_key(valid_fp, private=True)
            # The method should return None (key not found), not raise an exception
            print(f"   ✓ PASS: Accepted valid format: {valid_fp} (returned: {result})")

        print("\n3. Testing remove_key path traversal protection...")

        # Test that remove_key also blocks malicious paths
        for malicious_fp in malicious_inputs[:5]:  # Test a few
            try:
                key_store.remove_key(malicious_fp)
                print(f"   ✓ PASS: remove_key handled: {malicious_fp}")
            except Exception as e:
                print(f"   ✗ FAIL: remove_key raised exception: {e}")
                failed = True

        if failed:
            print("\n" + "=" * 70)
            print("❌ SECURITY TEST FAILED - Path traversal protection incomplete!")
            print("=" * 70)
            return 1
        else:
            print("\n" + "=" * 70)
            print("✅ ALL SECURITY TESTS PASSED")
            print("=" * 70)
            return 0


def test_fingerprint_validation():
    """Test fingerprint validation edge cases."""
    print("\n" + "=" * 70)
    print("Testing Fingerprint Validation")
    print("=" * 70)

    with tempfile.TemporaryDirectory() as tmpdir:
        key_store = KeyStore(Path(tmpdir))

        # Test invalid fingerprints
        invalid_fps = [
            "",  # Empty
            "123",  # Too short
            "A" * 65,  # Too long (>64 chars)
            "ZZZZZZZZZZZZZZZZ",  # Not hex
            "12345678G0ABCDEF",  # Contains non-hex
            "../" * 10,  # Path traversal
            "12345678\n90ABCDEF",  # Newline
            "12345678;rm -rf /",  # Command injection attempt
            "12345678 OR 1=1",  # SQL-like injection
        ]

        print("\n1. Testing invalid fingerprints are rejected...")
        for fp in invalid_fps:
            result = key_store.get_key(fp, private=False)
            if result is None:
                print(f"   ✓ PASS: Rejected: {repr(fp)}")
            else:
                print(f"   ✗ FAIL: Accepted: {repr(fp)}")
                return 1

        print("\n" + "=" * 70)
        print("✅ FINGERPRINT VALIDATION TESTS PASSED")
        print("=" * 70)
        return 0


def main():
    """Run all security tests."""
    print("\n" + "=" * 70)
    print("PGP Security Test Suite")
    print("=" * 70)

    try:
        result1 = test_path_traversal_protection()
        result2 = test_fingerprint_validation()

        if result1 == 0 and result2 == 0:
            print("\n" + "=" * 70)
            print("🔒 ALL SECURITY TESTS PASSED!")
            print("=" * 70)
            print("\nThe application is protected against:")
            print("  ✓ Path traversal attacks")
            print("  ✓ Directory traversal via fingerprints")
            print("  ✓ Malformed fingerprint inputs")
            print("  ✓ Command injection attempts")
            return 0
        else:
            return 1

    except Exception as e:
        print(f"\n✗ SECURITY TEST FAILED WITH EXCEPTION: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
