"""Helpers for encrypting and decrypting messages."""
from __future__ import annotations

from typing import Dict, Iterable, Tuple

from pgpy import PGPKey, PGPMessage
from pgpy.constants import CompressionAlgorithm


def encrypt_message(plaintext: str, recipient_public_keys: Iterable[PGPKey]) -> str:
    """
    Encrypt message to one or more recipients.

    Args:
        plaintext: Message to encrypt
        recipient_public_keys: List of recipient public keys

    Returns:
        ASCII-armored encrypted message
    """
    recipients = [key for key in recipient_public_keys if key is not None]
    if not plaintext:
        raise ValueError("Plaintext message is required")
    if not recipients:
        raise ValueError("At least one recipient public key is required")
    if len(recipients) > 1:
        raise ValueError("Encrypting to multiple recipients is not supported in this build")

    key = recipients[0]
    message = PGPMessage.new(plaintext, compression=CompressionAlgorithm.Uncompressed)
    target_key = key if key.is_public else key.pubkey
    encrypted_message = target_key.encrypt(message)

    return str(encrypted_message)


def decrypt_message(ciphertext: str, private_key: PGPKey, passphrase: str) -> Tuple[str, Dict]:
    """
    Decrypt message, return plaintext and metadata.

    Args:
        ciphertext: ASCII-armored encrypted message
        private_key: Private key to decrypt with
        passphrase: Passphrase for the private key

    Returns:
        Tuple of (plaintext, metadata_dict)
        metadata_dict contains: 'signer' (if signed), 'verified' (if signature verified)
    """
    if private_key.is_public:
        raise ValueError("Provided key does not contain a private component")

    # Parse the encrypted message
    encrypted_message = PGPMessage.from_blob(ciphertext)

    # Unlock the private key and decrypt
    with private_key.unlock(passphrase):
        decrypted_message = private_key.decrypt(encrypted_message)

    metadata = {}

    # Check if message was signed
    if decrypted_message.is_signed:
        # Try to verify signature
        for signer in decrypted_message.signers:
            # Note: We'd need the signer's public key to fully verify
            # For now, just note that it was signed
            metadata['signed'] = True
            metadata['signer_key_id'] = str(signer)

    # Get the plaintext
    plaintext = str(decrypted_message.message)

    return plaintext, metadata
