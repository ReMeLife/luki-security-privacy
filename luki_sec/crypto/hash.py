"""
Hashing utilities for LUKi
Password hashing, secure hashing, and data integrity
"""

import hashlib
import secrets
from typing import List
import bcrypt
import structlog

logger = structlog.get_logger(__name__)


class HashError(Exception):
    """Base exception for hashing-related errors"""
    pass


def hash_password(password: str, rounds: int = 12) -> str:
    """
    Hash a password using bcrypt
    
    Args:
        password: Plain text password
        rounds: bcrypt cost factor (default 12)
        
    Returns:
        Hashed password string
    """
    try:
        password_bytes = password.encode('utf-8')
        salt = bcrypt.gensalt(rounds=rounds)
        hashed = bcrypt.hashpw(password_bytes, salt)
        return hashed.decode('utf-8')
        
    except Exception as e:
        logger.error("Password hashing failed", error=str(e))
        raise HashError(f"Password hashing failed: {str(e)}")


def verify_password(password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash
    
    Args:
        password: Plain text password
        hashed_password: Previously hashed password
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        password_bytes = password.encode('utf-8')
        hashed_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_bytes)
        
    except Exception as e:
        logger.error("Password verification failed", error=str(e))
        return False


def secure_hash(data: bytes, algorithm: str = 'sha256') -> str:
    """
    Create secure hash of data
    
    Args:
        data: Data to hash
        algorithm: Hash algorithm (sha256, sha512, blake2b)
        
    Returns:
        Hex-encoded hash string
    """
    try:
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha512':
            hasher = hashlib.sha512()
        elif algorithm == 'blake2b':
            hasher = hashlib.blake2b()
        else:
            raise HashError(f"Unsupported hash algorithm: {algorithm}")
        
        hasher.update(data)
        return hasher.hexdigest()
        
    except Exception as e:
        logger.error("Secure hashing failed", algorithm=algorithm, error=str(e))
        raise HashError(f"Secure hashing failed: {str(e)}")


def hash_string(text: str, algorithm: str = 'sha256') -> str:
    """Hash a string using specified algorithm"""
    return secure_hash(text.encode('utf-8'), algorithm)


def hmac_hash(key: bytes, data: bytes, algorithm: str = 'sha256') -> str:
    """
    Create HMAC hash for message authentication
    
    Args:
        key: Secret key for HMAC
        data: Data to authenticate
        algorithm: Hash algorithm
        
    Returns:
        Hex-encoded HMAC hash
    """
    import hmac
    
    try:
        if algorithm == 'sha256':
            hasher = hashlib.sha256
        elif algorithm == 'sha512':
            hasher = hashlib.sha512
        else:
            raise HashError(f"Unsupported HMAC algorithm: {algorithm}")
        
        mac = hmac.new(key, data, hasher)
        return mac.hexdigest()
        
    except Exception as e:
        logger.error("HMAC hashing failed", algorithm=algorithm, error=str(e))
        raise HashError(f"HMAC hashing failed: {str(e)}")


def generate_salt(length: int = 32) -> bytes:
    """Generate cryptographically secure salt"""
    return secrets.token_bytes(length)


def hash_with_salt(data: bytes, salt: bytes | None = None, algorithm: str = 'sha256') -> tuple[str, str]:
    """
    Hash data with salt
    
    Args:
        data: Data to hash
        salt: Salt bytes (generated if None)
        algorithm: Hash algorithm
        
    Returns:
        Tuple of (hash_hex, salt_hex)
    """
    if salt is None:
        salt = generate_salt()
    
    salted_data = salt + data
    hash_hex = secure_hash(salted_data, algorithm)
    salt_hex = salt.hex()
    
    return hash_hex, salt_hex


def verify_salted_hash(data: bytes, hash_hex: str, salt_hex: str, 
                      algorithm: str = 'sha256') -> bool:
    """
    Verify data against salted hash
    
    Args:
        data: Data to verify
        hash_hex: Expected hash (hex)
        salt_hex: Salt used (hex)
        algorithm: Hash algorithm
        
    Returns:
        True if hash matches, False otherwise
    """
    try:
        salt = bytes.fromhex(salt_hex)
        computed_hash, _ = hash_with_salt(data, salt, algorithm)
        return computed_hash == hash_hex
        
    except Exception as e:
        logger.error("Salted hash verification failed", error=str(e))
        return False


class HashChain:
    """Hash chain for tamper-evident logging"""
    
    def __init__(self, initial_hash: str | None = None):
        self.current_hash = initial_hash or secure_hash(b"genesis")
        self.chain_length = 0
    
    def add_entry(self, data: bytes) -> str:
        """Add entry to hash chain"""
        combined = self.current_hash.encode('utf-8') + data
        self.current_hash = secure_hash(combined)
        self.chain_length += 1
        
        logger.debug("Added hash chain entry", 
                    length=self.chain_length, 
                    hash=self.current_hash[:16])
        
        return self.current_hash
    
    def verify_chain(self, entries: list[bytes], expected_final_hash: str) -> bool:
        """Verify integrity of hash chain"""
        temp_chain = HashChain(secure_hash(b"genesis"))
        
        for entry in entries:
            temp_chain.add_entry(entry)
        
        return temp_chain.current_hash == expected_final_hash


def hash_pii_for_analytics(pii_data: str, salt: str | None = None) -> str:
    """
    Hash PII data for analytics while preserving privacy
    
    Args:
        pii_data: Personal identifiable information
        salt: Optional salt (uses global salt if None)
        
    Returns:
        Irreversible hash suitable for analytics
    """
    if salt is None:
        # Use a global salt for consistent hashing across analytics
        salt = "luki_analytics_salt_v1"
    
    combined = f"{salt}:{pii_data}"
    return hash_string(combined, 'sha256')


def create_data_fingerprint(data: dict) -> str:
    """
    Create deterministic fingerprint of data structure
    
    Args:
        data: Dictionary to fingerprint
        
    Returns:
        Fingerprint hash
    """
    import json
    
    # Sort keys for deterministic output
    normalized = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hash_string(normalized, 'sha256')


def verify_data_integrity(data: bytes, expected_hash: str, 
                         algorithm: str = 'sha256') -> bool:
    """
    Verify data integrity against expected hash
    
    Args:
        data: Data to verify
        expected_hash: Expected hash value
        algorithm: Hash algorithm used
        
    Returns:
        True if data is intact, False if corrupted
    """
    computed_hash = secure_hash(data, algorithm)
    return computed_hash == expected_hash
