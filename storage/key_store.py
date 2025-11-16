"""Keyring storage management."""
import os
import json
import re
from pathlib import Path
from typing import List, Dict, Optional
from pgpy import PGPKey
from pgpy.packet.types import Private


class KeyStore:
    """Manages local PGP key storage with secure file permissions."""
    
    def __init__(self, base_path: Optional[Path] = None):
        """
        Initialize keyring at OS-appropriate location.
        
        Args:
            base_path: Optional custom path, defaults to ~/.pgp_gui
        """
        if base_path is None:
            home = Path.home()
            self.base_path = home / '.pgp_gui'
        else:
            self.base_path = Path(base_path)
        
        # Create directory structure
        self.keys_dir = self.base_path / 'keys'
        self.public_dir = self.keys_dir / 'public'
        self.private_dir = self.keys_dir / 'private'
        self.metadata_file = self.keys_dir / 'metadata.json'
        
        # Create directories if they don't exist
        self.public_dir.mkdir(parents=True, exist_ok=True)
        self.private_dir.mkdir(parents=True, exist_ok=True)
        
        # Set secure permissions on directories (700 = rwx------)
        if os.name != 'nt':  # Unix-like systems
            os.chmod(self.base_path, 0o700)
            os.chmod(self.keys_dir, 0o700)
            os.chmod(self.public_dir, 0o700)
            os.chmod(self.private_dir, 0o700)
        
        # Initialize metadata file if it doesn't exist
        if not self.metadata_file.exists():
            self._save_metadata({})
    
    def _load_metadata(self) -> Dict:
        """Load metadata from JSON file."""
        if not self.metadata_file.exists():
            return {}
        try:
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    
    def _save_metadata(self, metadata: Dict):
        """Save metadata to JSON file."""
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        # Set secure permissions (600 = rw-------)
        if os.name != 'nt':
            os.chmod(self.metadata_file, 0o600)
    
    def _get_fingerprint(self, key: PGPKey) -> str:
        """Get fingerprint string from key."""
        return str(key.fingerprint).replace(' ', '')
    
    def _validate_fingerprint(self, fingerprint: str) -> bool:
        """
        Validate fingerprint contains only hex characters.
        Prevents path traversal attacks.
        
        Args:
            fingerprint: Fingerprint string to validate
            
        Returns:
            True if valid, False otherwise
        """
        fingerprint = fingerprint.replace(' ', '')
        # PGP fingerprints are hex strings, typically 40 chars (SHA-1) or 32 chars (MD5)
        # Allow reasonable length (8-64 chars) and only hex characters
        if not fingerprint or len(fingerprint) < 8 or len(fingerprint) > 64:
            return False
        return bool(re.match(r'^[0-9A-Fa-f]+$', fingerprint))
    
    def _set_file_permissions(self, file_path: Path):
        """Set secure file permissions (600) on Unix systems."""
        if os.name != 'nt':  # Unix-like systems
            os.chmod(file_path, 0o600)
    
    def add_key(self, key: PGPKey, name: Optional[str] = None, email: Optional[str] = None):
        """
        Store key with metadata.
        
        Args:
            key: PGPKey object to store
            name: Optional name for the key
            email: Optional email for the key
        """
        fingerprint = self._get_fingerprint(key)
        
        # Extract name and email from key if not provided
        if not name or not email:
            if key.userids:
                uid = key.userids[0]
                name = name or uid.name or ''
                email = email or uid.email or ''
        
        # Export and save public key
        public_key_armored = str(key.pubkey)
        public_key_file = self.public_dir / f"{fingerprint}.asc"
        with open(public_key_file, 'w') as f:
            f.write(public_key_armored)
        self._set_file_permissions(public_key_file)
        
        # Export and save private key if present
        if isinstance(key._key, Private):
            private_key_armored = str(key)
            private_key_file = self.private_dir / f"{fingerprint}.asc"
            with open(private_key_file, 'w') as f:
                f.write(private_key_armored)
            self._set_file_permissions(private_key_file)
        
        # Update metadata
        metadata = self._load_metadata()
        metadata[fingerprint] = {
            'name': name or '',
            'email': email or '',
            'has_private': isinstance(key._key, Private),
            'fingerprint': fingerprint,
        }
        self._save_metadata(metadata)
    
    def list_keys(self) -> List[Dict]:
        """
        Return list of key metadata.
        
        Returns:
            List of dictionaries with key information
        """
        metadata = self._load_metadata()
        return list(metadata.values())
    
    def get_key(self, fingerprint: str, private: bool = False, passphrase: Optional[str] = None) -> Optional[PGPKey]:
        """
        Retrieve key by fingerprint.
        
        Args:
            fingerprint: Key fingerprint (with or without spaces)
            private: If True, retrieve private key; if False, retrieve public key
            passphrase: Optional passphrase if retrieving protected private key
            
        Returns:
            PGPKey object or None if not found
        """
        fingerprint = fingerprint.replace(' ', '')
        
        # SECURITY: Validate fingerprint to prevent path traversal
        if not self._validate_fingerprint(fingerprint):
            return None
        
        if private:
            key_file = self.private_dir / f"{fingerprint}.asc"
        else:
            key_file = self.public_dir / f"{fingerprint}.asc"
        
        # SECURITY: Ensure resolved path is within expected directory
        try:
            key_file_resolved = key_file.resolve()
            expected_dir = self.private_dir if private else self.public_dir
            expected_dir_resolved = expected_dir.resolve()
            
            # Check if the resolved path is within the expected directory
            if not str(key_file_resolved).startswith(str(expected_dir_resolved)):
                return None
        except (OSError, RuntimeError):
            return None
        
        if not key_file.exists():
            return None
        
        try:
            with open(key_file, 'r') as f:
                armored_key = f.read()
            
            key, _ = PGPKey.from_blob(armored_key)
            
            # If it's a private key and has a passphrase, we don't unlock it here
            # The caller should unlock it when needed
            return key
            
        except Exception:
            return None
    
    def remove_key(self, fingerprint: str):
        """
        Delete key from keyring.
        
        Args:
            fingerprint: Key fingerprint (with or without spaces)
        """
        fingerprint = fingerprint.replace(' ', '')
        
        # SECURITY: Validate fingerprint to prevent path traversal
        if not self._validate_fingerprint(fingerprint):
            return
        
        # Remove files
        public_key_file = self.public_dir / f"{fingerprint}.asc"
        private_key_file = self.private_dir / f"{fingerprint}.asc"
        
        # SECURITY: Ensure resolved paths are within expected directories
        try:
            public_resolved = public_key_file.resolve()
            private_resolved = private_key_file.resolve()
            public_dir_resolved = self.public_dir.resolve()
            private_dir_resolved = self.private_dir.resolve()
            
            # Only delete if paths are within expected directories
            if public_key_file.exists():
                if str(public_resolved).startswith(str(public_dir_resolved)):
                    public_key_file.unlink()
            
            if private_key_file.exists():
                if str(private_resolved).startswith(str(private_dir_resolved)):
                    private_key_file.unlink()
        except (OSError, RuntimeError):
            return
        
        # Update metadata
        metadata = self._load_metadata()
        if fingerprint in metadata:
            del metadata[fingerprint]
            self._save_metadata(metadata)
    
    def get_storage_path(self) -> Path:
        """
        Return OS-appropriate storage path.
        
        Returns:
            Path to the keyring storage directory
        """
        return self.base_path

