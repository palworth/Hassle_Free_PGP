"""Signing and verification operations."""
import pgpy
from pgpy import PGPKey
from pgpy.packet.types import Private
from typing import Tuple, Dict


def sign_message(message: str, private_key: PGPKey, passphrase: str, detached: bool = True) -> str:
    """
    Sign message, return detached signature or clear-signed message.

    Args:
        message: Message to sign
        private_key: Private key to sign with
        passphrase: Passphrase for the private key
        detached: If True, return detached signature; if False, return clear-signed message

    Returns:
        ASCII-armored signature (detached) or clear-signed message
    """
    if not isinstance(private_key._key, Private):
        raise ValueError("Provided key does not contain a private key")

    # Create message object
    pgp_message = pgpy.PGPMessage.new(message)

    # Unlock private key and sign
    with private_key.unlock(passphrase):
        if detached:
            # Create detached signature
            signature = private_key.sign(pgp_message)
            return str(signature)
        else:
            # Create clear-signed message
            signed_message = pgpy.PGPMessage.new(message)
            signed_message |= private_key.sign(pgp_message)
            return str(signed_message)


def verify_signature(message: str, signature: str, public_key: PGPKey) -> Tuple[bool, Dict]:
    """
    Verify signature, return success status and signer info.

    Args:
        message: Original message (for detached signatures) or signed message (for clear-signed)
        signature: Detached signature (if detached=True) or None (if clear-signed)
        public_key: Public key to verify against

    Returns:
        Tuple of (success: bool, info_dict)
        info_dict contains: 'signer_name', 'signer_email', 'key_id', 'fingerprint'
    """
    info = {}

    # Strip leading/trailing whitespace from message
    message = message.strip()

    # Add debug info about message format
    info['message_starts_with'] = message[:50] if len(message) > 50 else message
    info['message_length'] = len(message)
    info['has_begin_pgp_signed'] = '-----BEGIN PGP SIGNED MESSAGE-----' in message
    info['has_begin_pgp_signature'] = '-----BEGIN PGP SIGNATURE-----' in message

    try:
        # Try to parse as clear-signed message first
        try:
            signed_message = pgpy.PGPMessage.from_blob(message)
            info['parse_method'] = 'clear-signed'
            info['is_signed'] = signed_message.is_signed

            if signed_message.is_signed:
                # Clear-signed message
                verified = public_key.verify(signed_message)
                info['verification_result'] = str(verified)

                if verified:
                    # Extract signer info
                    uid = public_key.userids[0] if public_key.userids else None
                    info['signer_name'] = uid.name if uid else ''
                    info['signer_email'] = uid.email if uid else ''
                    info['key_id'] = str(
                        public_key.fingerprint.keyid) if hasattr(
                        public_key.fingerprint,
                        'keyid') else str(
                        public_key.fingerprint)
                    info['fingerprint'] = str(public_key.fingerprint)
                    return True, info
                else:
                    info['error'] = 'Signature verification returned False (signature may not match this key)'
                    return False, info
        except Exception as e1:
            info['clear_signed_error'] = str(e1)

        # Try detached signature
        if signature:
            try:
                info['parse_method'] = 'detached'
                sig = pgpy.PGPSignature.from_blob(signature)
                pgp_message = pgpy.PGPMessage.new(message)
                pgp_message |= sig

                verified = public_key.verify(pgp_message)
                info['verification_result'] = str(verified)

                if verified:
                    uid = public_key.userids[0] if public_key.userids else None
                    info['signer_name'] = uid.name if uid else ''
                    info['signer_email'] = uid.email if uid else ''
                    info['key_id'] = str(
                        public_key.fingerprint.keyid) if hasattr(
                        public_key.fingerprint,
                        'keyid') else str(
                        public_key.fingerprint)
                    info['fingerprint'] = str(public_key.fingerprint)
                    return True, info
                else:
                    info['error'] = 'Detached signature verification returned False (signature may not match this key)'
                    return False, info
            except Exception as e2:
                info['detached_error'] = str(e2)

        info['error'] = 'Could not verify signature with any method'
        return False, info

    except Exception as e:
        info['error'] = f"Unexpected error: {str(e)}"
        return False, info
