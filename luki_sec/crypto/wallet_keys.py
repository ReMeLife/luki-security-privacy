"""
Wallet-Derived Key Management for LUKi
Ed25519 signature verification and HKDF-based encryption key derivation

This module enables users to derive encryption keys from their Solana wallet
signatures, providing a trustless privacy model where the server never holds
user encryption keys.

Flow:
1. User signs a deterministic message with their Solana wallet
2. Server verifies the Ed25519 signature
3. Server derives AES-256 key via HKDF from the signature
4. Key is used for user's ELR encryption (held in memory, never persisted)
"""

import base64
import hashlib
import secrets
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, UTC, timedelta
from enum import Enum
import structlog

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

logger = structlog.get_logger(__name__)

# Key derivation version - allows future migration
KEY_DERIVATION_VERSION = "v1"

# Salt for HKDF - domain separation
HKDF_SALT = b"luki-wallet-encryption-v1"

# Message template for key derivation signatures
KEY_DERIVATION_MESSAGE_TEMPLATE = "LUKi ELR Key Derivation {version}:{user_id}"


class WalletType(str, Enum):
    """Supported wallet types"""
    SOLANA = "solana"
    # Future: ETHEREUM = "ethereum"


class SignatureVerificationError(Exception):
    """Raised when signature verification fails"""
    pass


class KeyDerivationError(Exception):
    """Raised when key derivation fails"""
    pass


def create_key_derivation_message(user_id: str, version: str = KEY_DERIVATION_VERSION) -> str:
    """
    Create the deterministic message that users must sign for key derivation.
    
    The message is deterministic so users can re-derive their key at any time
    by signing the same message again.
    
    Args:
        user_id: User's unique identifier
        version: Key derivation version for future migration
        
    Returns:
        Message string to be signed by wallet
    """
    return KEY_DERIVATION_MESSAGE_TEMPLATE.format(version=version, user_id=user_id)


def verify_solana_signature(
    public_key: bytes,
    message: bytes,
    signature: bytes
) -> bool:
    """
    Verify an Ed25519 signature from a Solana wallet.
    
    Solana uses Ed25519 (EdDSA on Curve25519) for all signatures.
    
    Args:
        public_key: 32-byte Ed25519 public key
        message: Original message that was signed
        signature: 64-byte Ed25519 signature
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        
        # Validate key size
        if len(public_key) != 32:
            logger.warning("Invalid public key size", 
                          expected=32, 
                          actual=len(public_key))
            return False
        
        # Validate signature size
        if len(signature) != 64:
            logger.warning("Invalid signature size",
                          expected=64,
                          actual=len(signature))
            return False
        
        # Create public key object and verify
        pk = Ed25519PublicKey.from_public_bytes(public_key)
        pk.verify(signature, message)
        
        logger.debug("Solana signature verified successfully")
        return True
        
    except InvalidSignature:
        logger.warning("Solana signature verification failed - invalid signature")
        return False
    except Exception as e:
        logger.error("Solana signature verification error", error=str(e))
        return False


def verify_solana_signature_base58(
    public_key_base58: str,
    message: str,
    signature_base64: str
) -> bool:
    """
    Verify a Solana signature with base58 public key and base64 signature.
    
    This is the typical format received from frontend wallet interactions.
    
    Args:
        public_key_base58: Solana public key in base58 format
        message: Original message string that was signed
        signature_base64: Signature in base64 format
        
    Returns:
        True if signature is valid
    """
    try:
        import base58
        
        public_key = base58.b58decode(public_key_base58)
        signature = base64.b64decode(signature_base64)
        message_bytes = message.encode('utf-8')
        
        return verify_solana_signature(public_key, message_bytes, signature)
        
    except ImportError:
        # Fallback if base58 not installed - try manual decode
        logger.warning("base58 library not installed, attempting fallback decode")
        try:
            # Simple base58 decode fallback
            public_key = _base58_decode_fallback(public_key_base58)
            signature = base64.b64decode(signature_base64)
            message_bytes = message.encode('utf-8')
            return verify_solana_signature(public_key, message_bytes, signature)
        except Exception as e:
            logger.error("Signature verification fallback failed", error=str(e))
            return False
    except Exception as e:
        logger.error("Signature verification with base58 failed", error=str(e))
        return False


def _base58_decode_fallback(data: str) -> bytes:
    """Simple base58 decode fallback if base58 library not available."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    
    num = 0
    for char in data:
        num = num * 58 + ALPHABET.index(char)
    
    # Convert to bytes
    result = []
    while num > 0:
        result.append(num % 256)
        num //= 256
    
    # Handle leading zeros
    for char in data:
        if char == '1':
            result.append(0)
        else:
            break
    
    return bytes(reversed(result))


def derive_encryption_key_from_signature(
    signature: bytes,
    user_id: str,
    version: str = KEY_DERIVATION_VERSION
) -> bytes:
    """
    Derive a 32-byte AES-256 encryption key from a wallet signature using HKDF.
    
    HKDF (HMAC-based Key Derivation Function) is the standard for deriving
    keys from high-entropy sources like signatures. It provides:
    - Cryptographic extraction of entropy
    - Domain separation via salt and info
    - Deterministic output (same input = same key)
    
    Args:
        signature: 64-byte Ed25519 signature
        user_id: User identifier (used as HKDF info for context binding)
        version: Key derivation version
        
    Returns:
        32-byte AES-256 encryption key
        
    Raises:
        KeyDerivationError: If key derivation fails
    """
    try:
        # Construct info parameter for HKDF (context binding)
        info = f"luki-elr-{version}:{user_id}".encode('utf-8')
        
        # Derive key using HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # AES-256 key size
            salt=HKDF_SALT,
            info=info,
            backend=default_backend()
        )
        
        derived_key = hkdf.derive(signature)
        
        logger.debug("Derived encryption key from signature",
                    user_id=user_id,
                    version=version,
                    key_length=len(derived_key))
        
        return derived_key
        
    except Exception as e:
        logger.error("Key derivation failed", error=str(e))
        raise KeyDerivationError(f"Failed to derive encryption key: {str(e)}")


def derive_key_from_base64_signature(
    signature_base64: str,
    user_id: str,
    version: str = KEY_DERIVATION_VERSION
) -> bytes:
    """
    Derive encryption key from a base64-encoded signature.
    
    Convenience function for typical frontend interaction format.
    
    Args:
        signature_base64: Signature in base64 format
        user_id: User identifier
        version: Key derivation version
        
    Returns:
        32-byte AES-256 encryption key
    """
    signature = base64.b64decode(signature_base64)
    return derive_encryption_key_from_signature(signature, user_id, version)


class WalletKeyDerivation:
    """
    Complete wallet-based key derivation workflow.
    
    This class handles the full flow of:
    1. Creating the message for signing
    2. Verifying the signature
    3. Deriving the encryption key
    """
    
    def __init__(self, version: str = KEY_DERIVATION_VERSION):
        self.version = version
    
    def get_signing_message(self, user_id: str) -> str:
        """Get the message that user must sign with their wallet."""
        return create_key_derivation_message(user_id, self.version)
    
    def verify_and_derive_key(
        self,
        user_id: str,
        public_key_base58: str,
        signature_base64: str
    ) -> Tuple[bool, Optional[bytes], Dict[str, Any]]:
        """
        Verify signature and derive encryption key in one operation.
        
        Args:
            user_id: User identifier
            public_key_base58: Solana public key (base58)
            signature_base64: Signature (base64)
            
        Returns:
            Tuple of (success, derived_key or None, metadata dict)
        """
        # Create expected message
        message = self.get_signing_message(user_id)
        
        # Verify signature
        is_valid = verify_solana_signature_base58(
            public_key_base58,
            message,
            signature_base64
        )
        
        if not is_valid:
            logger.warning("Wallet key derivation failed - invalid signature",
                         user_id=user_id)
            return False, None, {
                "error": "invalid_signature",
                "message": "Signature verification failed"
            }
        
        # Derive key
        try:
            signature = base64.b64decode(signature_base64)
            derived_key = derive_encryption_key_from_signature(
                signature, 
                user_id, 
                self.version
            )
            
            logger.info("Wallet key derivation successful",
                       user_id=user_id,
                       version=self.version)
            
            return True, derived_key, {
                "version": self.version,
                "wallet_public_key": public_key_base58,
                "derived_at": datetime.now(UTC).isoformat(),
            }
            
        except KeyDerivationError as e:
            logger.error("Key derivation failed after signature verification",
                        user_id=user_id,
                        error=str(e))
            return False, None, {
                "error": "derivation_failed",
                "message": str(e)
            }
    
    def create_registration_challenge(self, user_id: str) -> Dict[str, Any]:
        """
        Create a challenge for wallet registration.
        
        Returns the message that user must sign and metadata about the challenge.
        """
        message = self.get_signing_message(user_id)
        
        return {
            "message": message,
            "version": self.version,
            "user_id": user_id,
            "instructions": "Sign this message with your Solana wallet to enable wallet-derived encryption",
            "created_at": datetime.now(UTC).isoformat(),
        }


# Global instance
_wallet_key_derivation: Optional[WalletKeyDerivation] = None


def get_wallet_key_derivation() -> WalletKeyDerivation:
    """Get or create global wallet key derivation instance."""
    global _wallet_key_derivation
    if _wallet_key_derivation is None:
        _wallet_key_derivation = WalletKeyDerivation()
    return _wallet_key_derivation
