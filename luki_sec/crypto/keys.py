"""
Key management utilities for LUKi
Key generation, rotation, and secure storage
"""

import os
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import structlog

from .encrypt import generate_key
from ..config import get_security_config

logger = structlog.get_logger(__name__)


class KeyError(Exception):
    """Base exception for key management errors"""
    pass


class KeyManager:
    """Centralized key management for LUKi"""
    
    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or self._load_or_generate_master_key()
        self.derived_keys: Dict[str, bytes] = {}
        self.key_metadata: Dict[str, Dict[str, Any]] = {}
    
    def _load_or_generate_master_key(self) -> bytes:
        """Load master key from environment or generate new one"""
        # In production, this would load from secure key management service
        master_key_hex = os.getenv('LUKI_MASTER_KEY')
        
        if master_key_hex:
            try:
                return bytes.fromhex(master_key_hex)
            except ValueError:
                logger.warning("Invalid master key format, generating new one")
        
        # Generate new master key for development
        master_key = generate_key(256)
        logger.warning("Generated new master key - store securely!", 
                      key_hex=master_key.hex())
        return master_key
    
    def derive_key(self, purpose: str, salt: Optional[bytes] = None) -> bytes:
        """Derive a purpose-specific key from master key"""
        if purpose in self.derived_keys:
            return self.derived_keys[purpose]
        
        salt = salt or os.urandom(32)
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=purpose.encode('utf-8'),
        )
        
        derived_key = hkdf.derive(self.master_key)
        
        # Cache the derived key
        self.derived_keys[purpose] = derived_key
        self.key_metadata[purpose] = {
            'created_at': datetime.utcnow(),
            'salt': salt,
            'purpose': purpose
        }
        
        logger.info("Derived key for purpose", purpose=purpose)
        return derived_key
    
    def get_encryption_key(self) -> bytes:
        """Get key for general data encryption"""
        return self.derive_key('data_encryption')
    
    def get_jwt_secret(self) -> str:
        """Get secret for JWT signing"""
        key_bytes = self.derive_key('jwt_signing')
        return key_bytes.hex()
    
    def get_field_key(self, field_name: str) -> bytes:
        """Get key for specific field encryption"""
        return self.derive_key(f'field_{field_name}')
    
    def get_user_key(self, user_id: str) -> bytes:
        """Get user-specific encryption key"""
        return self.derive_key(f'user_{user_id}')
    
    def rotate_master_key(self, new_master_key: bytes) -> Dict[str, bytes]:
        """Rotate master key and re-derive all keys"""
        old_keys = self.derived_keys.copy()
        
        self.master_key = new_master_key
        self.derived_keys.clear()
        
        # Re-derive all keys with new master key
        for purpose, metadata in self.key_metadata.items():
            salt = metadata['salt']
            self.derive_key(purpose, salt)
        
        logger.info("Master key rotated", purposes=list(self.key_metadata.keys()))
        return old_keys
    
    def export_key_metadata(self) -> Dict[str, Any]:
        """Export key metadata for backup/audit"""
        return {
            'keys': {
                purpose: {
                    'created_at': metadata['created_at'].isoformat(),
                    'purpose': metadata['purpose'],
                    'salt_hex': metadata['salt'].hex()
                }
                for purpose, metadata in self.key_metadata.items()
            },
            'exported_at': datetime.utcnow().isoformat()
        }


def generate_password_key(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """Derive encryption key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode('utf-8'))


def generate_secure_token(length: int = 32) -> str:
    """Generate cryptographically secure random token"""
    return secrets.token_urlsafe(length)


def generate_api_key() -> str:
    """Generate API key with prefix"""
    token = generate_secure_token(32)
    return f"luki_{token}"


class KeyRotationScheduler:
    """Automated key rotation scheduler"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.rotation_schedule: Dict[str, timedelta] = {
            'jwt_signing': timedelta(days=90),
            'data_encryption': timedelta(days=365),
            'api_keys': timedelta(days=180)
        }
    
    def should_rotate(self, purpose: str) -> bool:
        """Check if key should be rotated"""
        if purpose not in self.key_manager.key_metadata:
            return False
        
        metadata = self.key_manager.key_metadata[purpose]
        created_at = metadata['created_at']
        rotation_interval = self.rotation_schedule.get(purpose, timedelta(days=365))
        
        return datetime.utcnow() - created_at > rotation_interval
    
    def get_rotation_status(self) -> Dict[str, Dict[str, Any]]:
        """Get rotation status for all keys"""
        status = {}
        
        for purpose in self.key_manager.key_metadata:
            metadata = self.key_manager.key_metadata[purpose]
            created_at = metadata['created_at']
            rotation_interval = self.rotation_schedule.get(purpose, timedelta(days=365))
            next_rotation = created_at + rotation_interval
            
            status[purpose] = {
                'created_at': created_at.isoformat(),
                'next_rotation': next_rotation.isoformat(),
                'should_rotate': self.should_rotate(purpose),
                'days_until_rotation': (next_rotation - datetime.utcnow()).days
            }
        
        return status


# Global key manager instance
_key_manager: Optional[KeyManager] = None


def get_key_manager() -> KeyManager:
    """Get the global key manager instance"""
    global _key_manager
    if _key_manager is None:
        _key_manager = KeyManager()
    return _key_manager


def rotate_keys() -> Dict[str, Any]:
    """Rotate all keys according to schedule"""
    key_manager = get_key_manager()
    scheduler = KeyRotationScheduler(key_manager)
    
    rotation_results = {}
    
    for purpose in key_manager.key_metadata:
        if scheduler.should_rotate(purpose):
            try:
                # Generate new salt for rotation
                new_salt = os.urandom(32)
                old_key = key_manager.derived_keys[purpose]
                
                # Re-derive with new salt
                new_key = key_manager.derive_key(purpose, new_salt)
                
                rotation_results[purpose] = {
                    'status': 'rotated',
                    'rotated_at': datetime.utcnow().isoformat()
                }
                
                logger.info("Key rotated", purpose=purpose)
                
            except Exception as e:
                rotation_results[purpose] = {
                    'status': 'failed',
                    'error': str(e)
                }
                logger.error("Key rotation failed", purpose=purpose, error=str(e))
        else:
            rotation_results[purpose] = {
                'status': 'not_due',
                'next_rotation': scheduler.get_rotation_status()[purpose]['next_rotation']
            }
    
    return rotation_results
