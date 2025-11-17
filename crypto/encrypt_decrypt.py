"""Encryption and decryption operations."""
import pgpy
from pgpy import PGPKey
from typing import List, Tuple, Dict


def encrypt_message(plaintext: str, recipient_public_keys: List[PGPKey]) -> str:
    """
    Encrypt message to one or more recipients.

    Args:
        plaintext: Message to encrypt
        recipient_public_keys: List of recipient public keys

    Returns:
        ASCII-armored encrypted message
    """
    if not recipient_public_keys:
        raise ValueError("At least one recipient public key is required")

    # Create a message object
    message = pgpy.PGPMessage.new(plaintext)

    # Encrypt for all recipients
    encrypted_message = message.encrypt(recipient_public_keys)

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
    if not private_key.is_private:
        raise ValueError("Provided key does not contain a private key")

    # Parse the encrypted message
    encrypted_message = pgpy.PGPMessage.from_blob(ciphertext)

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
