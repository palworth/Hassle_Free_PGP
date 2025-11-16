"""Key generation, import, and export operations."""
from pgpy import PGPKey
from pgpy.constants import PubKeyAlgorithm, KeyFlags
from pgpy.packet.types import Private
import pgpy


def generate_keypair(name: str, email: str, passphrase: str) -> PGPKey:
    """
    Generate new RSA 4096 keypair.
    
    Args:
        name: Optional name for the key
        email: Required email address
        passphrase: Passphrase to protect the private key
        
    Returns:
        PGPKey object containing both public and private key
    """
    # Create a new key with RSA 4096
    key = PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    
    # Create a user ID with name and email
    uid = pgpy.PGPUID.new(name or '', email)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage})
    
    # Protect the private key with passphrase
    key.protect(passphrase, pgpy.constants.SymmetricKeyAlgorithm.AES256, pgpy.constants.HashAlgorithm.SHA256)
    
    return key


def import_key(armored_key: str, passphrase: str = None) -> PGPKey:
    """
    Import ASCII-armored public or private key.
    
    Args:
        armored_key: ASCII-armored PGP key string
        passphrase: Optional passphrase if importing a protected private key
        
    Returns:
        PGPKey object (may be public-only or contain private key)
    """
    key, _ = pgpy.PGPKey.from_blob(armored_key)
    
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


def export_private_key(key: PGPKey, passphrase: str = None) -> str:
    """
    Export private key as ASCII-armored string.
    
    Args:
        key: PGPKey object containing private key
        passphrase: Passphrase to protect the exported private key (if not already protected)
        
    Returns:
        ASCII-armored private key string
    """
    if not isinstance(key._key, Private):
        raise ValueError("Key does not contain a private key")
    
    # If key is not protected and passphrase is provided, protect it
    if not key.is_protected and passphrase:
        key.protect(passphrase, pgpy.constants.SymmetricKeyAlgorithm.AES256, pgpy.constants.HashAlgorithm.SHA256)
    
    return str(key)

