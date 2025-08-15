"""
Encryption utilities for LUKi
AES-GCM encryption for data at rest and in transit
"""

import os
from typing import TYPE_CHECKING
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    pass
from cryptography.exceptions import InvalidTag
import structlog

from ..config import get_security_config

logger = structlog.get_logger(__name__)


class EncryptionError(Exception):
    """Base exception for encryption-related errors"""
    pass


class DecryptionError(EncryptionError):
    """Raised when decryption fails"""
    pass


def generate_key(key_size: int = 256) -> bytes:
    """Generate a new AES encryption key"""
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits")
    
    return AESGCM.generate_key(bit_length=key_size)


def encrypt_bytes(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Encrypt bytes using AES-GCM
    
    Args:
        key: 32-byte encryption key
        plaintext: Data to encrypt
        associated_data: Optional associated data for authentication
        
    Returns:
        Encrypted data with nonce prepended (nonce + ciphertext + tag)
    """
    try:
        if len(key) != 32:
            raise EncryptionError("Key must be 32 bytes for AES-256")
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # 96-bit nonce for GCM
        
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        # Return nonce + ciphertext (ciphertext already includes auth tag)
        return nonce + ciphertext
        
    except Exception as e:
        logger.error("Encryption failed", error=str(e))
        raise EncryptionError(f"Encryption failed: {str(e)}")


def decrypt_bytes(key: bytes, encrypted_data: bytes, associated_data: bytes | None = None) -> bytes:
    """
    Decrypt bytes using AES-GCM
    
    Args:
        key: 32-byte encryption key
        encrypted_data: Encrypted data with nonce prepended
        associated_data: Optional associated data for authentication
        
    Returns:
        Decrypted plaintext
    """
    try:
        if len(key) != 32:
            raise DecryptionError("Key must be 32 bytes for AES-256")
        
        if len(encrypted_data) < 12:
            raise DecryptionError("Encrypted data too short")
        
        aesgcm = AESGCM(key)
        
        # Extract nonce and ciphertext
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
        
    except InvalidTag:
        logger.warning("Decryption failed - invalid authentication tag")
        raise DecryptionError("Invalid authentication tag - data may be corrupted or tampered")
    except Exception as e:
        logger.error("Decryption failed", error=str(e))
        raise DecryptionError(f"Decryption failed: {str(e)}")


def encrypt_string(key: bytes, plaintext: str, associated_data: bytes | None = None) -> bytes:
    """Encrypt a string using AES-GCM"""
    return encrypt_bytes(key, plaintext.encode('utf-8'), associated_data)


def decrypt_string(key: bytes, encrypted_data: bytes, associated_data: bytes | None = None) -> str:
    """Decrypt to a string using AES-GCM"""
    plaintext_bytes = decrypt_bytes(key, encrypted_data, associated_data)
    return plaintext_bytes.decode('utf-8')


class FieldEncryption:
    """Helper class for encrypting specific data fields"""
    
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt_field(self, field_name: str, value: str) -> bytes:
        """Encrypt a field with its name as associated data"""
        associated_data = field_name.encode('utf-8')
        return encrypt_string(self.key, value, associated_data)
    
    def decrypt_field(self, field_name: str, encrypted_value: bytes) -> str:
        """Decrypt a field with its name as associated data"""
        associated_data = field_name.encode('utf-8')
        return decrypt_string(self.key, encrypted_value, associated_data)


# Key derivation for different purposes
def derive_field_key(master_key: bytes, field_name: str) -> bytes:
    """Derive a field-specific key from master key"""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=field_name.encode('utf-8'),
    )
    return hkdf.derive(master_key)


def encrypt_elr_field(master_key: bytes, field_name: str, value: str) -> bytes:
    """Encrypt an ELR field with field-specific key derivation"""
    field_key = derive_field_key(master_key, field_name)
    return encrypt_string(field_key, value, field_name.encode('utf-8'))


def decrypt_elr_field(master_key: bytes, field_name: str, encrypted_value: bytes) -> str:
    """Decrypt an ELR field with field-specific key derivation"""
    field_key = derive_field_key(master_key, field_name)
    return decrypt_string(field_key, encrypted_value, field_name.encode('utf-8'))
