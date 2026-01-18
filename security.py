#!/usr/bin/env python3
"""
Security module for Azure Permission Analyzer
Provides AES-256-GCM encryption for credential storage and management
"""

import os
import json
import secrets
import base64
from typing import Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
import hashlib

from repositories import CredentialRepository, get_credential_repository

# Security constants
KEY_SIZE = 32  # 256 bits for AES-256
NONCE_SIZE = 12  # 96 bits for GCM
SALT_SIZE = 16  # 128 bits
ITERATIONS = 100000  # PBKDF2 iterations
CREDENTIAL_EXPIRY_HOURS = 24  # Credentials expire after 24 hours

@dataclass
class AzureCredentials:
    """Secure container for Azure credentials"""
    tenant_id: str
    client_id: str
    client_secret: str
    organization_name: str
    created_at: datetime
    expires_at: datetime

    def is_expired(self) -> bool:
        """Check if credentials have expired"""
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for use with Azure SDKs"""
        return {
            'tenant_id': self.tenant_id,
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }

class SecureCredentialManager:
    """
    Manages Azure credentials with AES-256-GCM encryption

    Features:
    - AES-256-GCM encryption with authenticated encryption
    - PBKDF2 key derivation with 100,000 iterations
    - Secure random salt and nonce generation
    - Credential expiration and automatic cleanup
    - Memory-safe credential handling
    """

    def __init__(self, credential_repo: Optional[CredentialRepository] = None):
        self.credential_repo = credential_repo or get_credential_repository()
        self.master_key: Optional[bytes] = None

    def _generate_master_key(self, password: str, salt: bytes) -> bytes:
        """
        Generate master key using PBKDF2 with SHA-256

        Args:
            password: User-provided password for key derivation
            salt: Random salt for key derivation

        Returns:
            32-byte master key for AES-256
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    def _encrypt_data(self, data: bytes, key: bytes) -> Dict[str, str]:
        """
        Encrypt data using AES-256-GCM

        Args:
            data: Raw data to encrypt
            key: 32-byte encryption key

        Returns:
            Dictionary containing encrypted data, nonce, and metadata
        """
        # Generate random nonce
        nonce = os.urandom(NONCE_SIZE)

        # Initialize AES-GCM cipher
        aesgcm = AESGCM(key)

        # Encrypt data with authenticated encryption
        ciphertext = aesgcm.encrypt(nonce, data, None)

        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'algorithm': 'AES-256-GCM',
            'kdf': 'PBKDF2-SHA256',
            'iterations': str(ITERATIONS),
            'encrypted_at': datetime.utcnow().isoformat()
        }

    def _decrypt_data(self, encrypted_data: Dict[str, str], key: bytes) -> bytes:
        """
        Decrypt data using AES-256-GCM

        Args:
            encrypted_data: Dictionary containing encrypted data and metadata
            key: 32-byte decryption key

        Returns:
            Decrypted raw data

        Raises:
            InvalidSignature: If authentication fails or data is corrupted
        """
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])

            # Initialize AES-GCM cipher
            aesgcm = AESGCM(key)

            # Decrypt and authenticate data
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext

        except Exception as e:
            raise InvalidSignature(f"Failed to decrypt data: {str(e)}")

    def store_credentials(self,
                         tenant_id: str,
                         client_id: str,
                         client_secret: str,
                         organization_name: str,
                         master_password: str) -> bool:
        """
        Securely store Azure credentials with AES-256-GCM encryption

        Args:
            tenant_id: Azure AD Tenant ID
            client_id: Service Principal Client ID
            client_secret: Service Principal Client Secret
            master_password: Password for encrypting credentials

        Returns:
            True if credentials stored successfully, False otherwise
        """
        try:
            # Validate inputs
            if not all([tenant_id, client_id, client_secret, organization_name, master_password]):
                return False

            # Create credentials object with expiration
            now = datetime.utcnow()
            credentials = AzureCredentials(
                tenant_id=tenant_id.strip(),
                client_id=client_id.strip(),
                client_secret=client_secret.strip(),
                organization_name=organization_name.strip(),
                created_at=now,
                expires_at=now + timedelta(hours=CREDENTIAL_EXPIRY_HOURS)
            )

            # Generate random salt
            salt = os.urandom(SALT_SIZE)

            # Derive encryption key
            master_key = self._generate_master_key(master_password, salt)

            # Serialize credentials
            credentials_json = json.dumps({
                'tenant_id': credentials.tenant_id,
                'client_id': credentials.client_id,
                'client_secret': credentials.client_secret,
                'organization_name': credentials.organization_name,
                'created_at': credentials.created_at.isoformat(),
                'expires_at': credentials.expires_at.isoformat()
            }).encode('utf-8')

            # Encrypt credentials
            encrypted_data = self._encrypt_data(credentials_json, master_key)

            # Store encrypted credentials in database
            success = self.credential_repo.save_encrypted_credentials(
                tenant_id=tenant_id,
                encrypted_data=encrypted_data,
                salt=base64.b64encode(salt).decode('utf-8'),
                nonce=encrypted_data['nonce'],
                expires_at=credentials.expires_at
            )

            if success:
                # Store master key in memory for session use
                self.master_key = master_key
                return True
            
            return False

        except Exception as e:
            print(f"Error storing credentials: {e}")
            return False

    def retrieve_credentials(self, master_password: str) -> Optional[AzureCredentials]:
        """
        Retrieve and decrypt Azure credentials

        Args:
            master_password: Password used for encryption

        Returns:
            AzureCredentials object if successful, None otherwise
        """
        try:
            # Load encrypted data from database
            storage_data = self.credential_repo.get_encrypted_credentials()
            if not storage_data:
                return None

            # Extract salt and encrypted data
            salt = base64.b64decode(storage_data['salt'])
            encrypted_data = storage_data['encrypted_data']

            # Derive decryption key
            master_key = self._generate_master_key(master_password, salt)

            # Decrypt credentials
            credentials_json = self._decrypt_data(encrypted_data, master_key)
            credentials_data = json.loads(credentials_json.decode('utf-8'))

            # Create credentials object
            credentials = AzureCredentials(
                tenant_id=credentials_data['tenant_id'],
                client_id=credentials_data['client_id'],
                client_secret=credentials_data['client_secret'],
                organization_name=credentials_data.get('organization_name', 'Organization'),  # Default for backward compatibility
                created_at=datetime.fromisoformat(credentials_data['created_at']),
                expires_at=datetime.fromisoformat(credentials_data['expires_at'])
            )

            # Check if credentials have expired
            if credentials.is_expired():
                self.delete_credentials()
                return None

            # Store master key in memory for session use
            self.master_key = master_key

            return credentials

        except (json.JSONDecodeError, KeyError, InvalidSignature) as e:
            print(f"Error retrieving credentials: {e}")
            return None
        except Exception as e:
            print(f"Unexpected error retrieving credentials: {e}")
            return None

    def credentials_exist(self) -> bool:
        """Check if encrypted credentials exist in database"""
        return self.credential_repo.credentials_exist()

    def delete_credentials(self) -> bool:
        """
        Securely delete stored credentials

        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            # Delete credentials from database
            success = self.credential_repo.delete_credentials()

            # Clear master key from memory
            if self.master_key:
                # Overwrite key in memory (Python limitation: not guaranteed)
                self.master_key = b'\x00' * len(self.master_key)
                self.master_key = None

            return success

        except Exception as e:
            print(f"Error deleting credentials: {e}")
            return False

    def validate_credentials_format(self,
                                  tenant_id: str,
                                  client_id: str,
                                  client_secret: str) -> Dict[str, str]:
        """
        Validate Azure credentials format

        Args:
            tenant_id: Azure AD Tenant ID
            client_id: Service Principal Client ID
            client_secret: Service Principal Client Secret

        Returns:
            Dictionary with validation results and error messages
        """
        errors = {}

        # Validate Tenant ID (GUID format)
        if not tenant_id or len(tenant_id.strip()) == 0:
            errors['tenant_id'] = 'Tenant ID is required'
        elif not self._is_valid_guid(tenant_id.strip()):
            errors['tenant_id'] = 'Tenant ID must be a valid GUID format'

        # Validate Client ID (GUID format)
        if not client_id or len(client_id.strip()) == 0:
            errors['client_id'] = 'Client ID is required'
        elif not self._is_valid_guid(client_id.strip()):
            errors['client_id'] = 'Client ID must be a valid GUID format'

        # Validate Client Secret
        if not client_secret or len(client_secret.strip()) == 0:
            errors['client_secret'] = 'Client Secret is required'
        elif len(client_secret.strip()) < 10:
            errors['client_secret'] = 'Client Secret appears to be too short'

        return errors

    def _is_valid_guid(self, value: str) -> bool:
        """Validate GUID format for Azure IDs"""
        import re
        guid_pattern = re.compile(
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            re.IGNORECASE
        )
        return bool(guid_pattern.match(value))

    def get_credential_info(self) -> Optional[Dict[str, Any]]:
        """
        Get non-sensitive information about stored credentials

        Returns:
            Dictionary with credential metadata (no secrets)
        """
        try:
            credential_info = self.credential_repo.get_credential_info()
            if not credential_info:
                return None

            # Convert datetime objects to ISO format strings for JSON serialization
            created_at = credential_info.get('created_at')
            expires_at = credential_info.get('expires_at')
            
            if created_at and hasattr(created_at, 'isoformat'):
                created_at = created_at.isoformat()
            
            if expires_at and hasattr(expires_at, 'isoformat'):
                expires_at = expires_at.isoformat()

            return {
                'exists': True,
                'tenant_id': credential_info.get('tenant_id'),
                'created_at': created_at,
                'expires_at': expires_at,
                'is_expired': credential_info.get('is_expired', False)
            }

        except Exception:
            return None

# Global credential manager instance
credential_manager = SecureCredentialManager()

def generate_session_token() -> str:
    """Generate a secure session token"""
    return secrets.token_urlsafe(32)

def hash_password(password: str) -> str:
    """Generate a secure hash of a password for session validation"""
    salt = secrets.token_bytes(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt + pwd_hash).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its hash"""
    try:
        decoded = base64.b64decode(hashed.encode('utf-8'))
        salt = decoded[:32]
        stored_hash = decoded[32:]
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return secrets.compare_digest(stored_hash, pwd_hash)
    except Exception:
        return False