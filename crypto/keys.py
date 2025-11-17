"""Utility helpers for creating, importing, and exporting PGP keys."""
from __future__ import annotations

import copy
from typing import Optional

from pgpy import PGPKey, PGPUID
from pgpy.constants import (
    CompressionAlgorithm,
    HashAlgorithm,
    KeyFlags,
    PubKeyAlgorithm,
    SymmetricKeyAlgorithm,
)


def _validate_key_size(key_size: int) -> int:
    """Validate supported RSA key sizes and return the sanitized value."""
    if key_size not in {2048, 3072, 4096}:
        raise ValueError("Key size must be one of 2048, 3072, or 4096 bits")
    return key_size


def generate_keypair(name: str, email: str, passphrase: str, key_size: int = 4096) -> PGPKey:
    """
    Generate a new RSA keypair protected with AES-256 + SHA-256.

    Args:
        name: Optional name for the key
        email: Email address associated with the key
        passphrase: Passphrase to protect the private key
        key_size: RSA key size (2048, 3072, or 4096 bits)

    Returns:
        PGPKey object containing both public and private key
    """
    if not email:
        raise ValueError("Email is required when generating a key")
    if not passphrase:
        raise ValueError("Passphrase is required when generating a key")

    sanitized_key_size = _validate_key_size(key_size)

    # Create a new key with the requested size
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, sanitized_key_size)

    # Create a user ID with name and email
    uid = PGPUID.new(name or '', email)
    key.add_uid(
        uid,
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
        ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.Uncompressed],
    )

    # Protect the private key with passphrase
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    return key


def import_key(armored_key: str, passphrase: Optional[str] = None) -> PGPKey:
    """
    Import ASCII-armored public or private key.

    Args:
        armored_key: ASCII-armored PGP key string
        passphrase: Optional passphrase if importing a protected private key

    Returns:
        PGPKey object (may be public-only or contain private key)
    """
    key, _ = PGPKey.from_blob(armored_key)

    # If it's a private key and has a passphrase, unlock it
    if key.is_protected and passphrase:
        with key.unlock(passphrase):
            pass  # Key is unlocked in this context

    return key


def export_public_key(key: PGPKey) -> str:
    """
    Export public key as ASCII-armored string.

    Args:
        key: PGPKey object

    Returns:
        ASCII-armored public key string
    """
    return str(key.pubkey)


def export_private_key(key: PGPKey, passphrase: Optional[str] = None) -> str:
    """
    Export private key as ASCII-armored string.

    Args:
        key: PGPKey object containing private key
        passphrase: Passphrase to protect the exported private key (if not already protected)

    Returns:
        ASCII-armored private key string
    """
    if key.is_public:
        raise ValueError("Key does not contain a private key")

    key_to_export = copy.copy(key)

    # If key is not protected and passphrase is provided, protect the exported copy
    if passphrase and not key_to_export.is_protected:
        key_to_export.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)

    return str(key_to_export)


def ensure_private_key_is_protected(key: PGPKey, passphrase: Optional[str]) -> None:
    """Protect an unprotected private key using the provided passphrase."""
    if key.is_public or key.is_protected:
        return
    if not passphrase:
        raise ValueError("A passphrase is required to protect private keys before storage")
    key.protect(passphrase, SymmetricKeyAlgorithm.AES256, HashAlgorithm.SHA256)
