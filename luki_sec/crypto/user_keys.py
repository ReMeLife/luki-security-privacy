"""
Per-User Key Management for LUKi
Session key caching and user encryption mode tracking

This module manages:
- Session keys derived from wallet signatures (in-memory, never persisted)
- User encryption mode (server vs wallet)
- Wallet registration records
"""

import asyncio
import secrets
from typing import Dict, Any, Optional, List
from datetime import datetime, UTC, timedelta
from enum import Enum
from pydantic import BaseModel, Field
import structlog

from .wallet_keys import (
    get_wallet_key_derivation,
    WalletKeyDerivation,
    KEY_DERIVATION_VERSION,
)

logger = structlog.get_logger(__name__)

# Default session key TTL (1 hour)
DEFAULT_SESSION_KEY_TTL_SECONDS = 3600

# Maximum session keys per user
MAX_SESSION_KEYS_PER_USER = 5


class EncryptionMode(str, Enum):
    """User encryption mode"""
    SERVER = "server"       # Traditional server-held key (default)
    WALLET = "wallet"       # Wallet-derived per-user key
    HYBRID = "hybrid"       # Server key wrapped with wallet key (future)


class WalletRegistration(BaseModel):
    """Record of a user's wallet registration for encryption"""
    user_id: str
    wallet_public_key: str  # Base58 Solana public key
    wallet_type: str = "solana"
    registered_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    key_derivation_version: str = KEY_DERIVATION_VERSION
    is_active: bool = True
    
    # Audit fields
    registered_from_ip: Optional[str] = None
    registered_user_agent: Optional[str] = None


class SessionKeyEntry(BaseModel):
    """In-memory session key entry (never persisted to disk)"""
    key_id: str
    user_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    last_used_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    wallet_public_key: str
    
    # Note: The actual derived_key is stored separately in SessionKeyManager._keys
    # to avoid any chance of serialization
    
    def is_expired(self) -> bool:
        """Check if this session key has expired."""
        return datetime.now(UTC) > self.expires_at
    
    def touch(self) -> None:
        """Update last_used_at timestamp."""
        self.last_used_at = datetime.now(UTC)


class SessionKeyManager:
    """
    Manages derived encryption keys in memory with automatic expiration.
    
    CRITICAL: Derived keys are NEVER persisted to disk or database.
    They are held in memory only and expire after a configurable TTL.
    
    Security properties:
    - Keys exist only in process memory
    - Automatic cleanup of expired keys
    - Maximum keys per user to prevent abuse
    - Keys are discarded on process restart
    """
    
    def __init__(self, default_ttl_seconds: int = DEFAULT_SESSION_KEY_TTL_SECONDS):
        self._keys: Dict[str, bytes] = {}  # key_id -> derived_key
        self._entries: Dict[str, SessionKeyEntry] = {}  # key_id -> metadata
        self._user_keys: Dict[str, List[str]] = {}  # user_id -> [key_ids]
        self._lock = asyncio.Lock()
        self._default_ttl = default_ttl_seconds
        self._cleanup_task: Optional[asyncio.Task] = None
        
        logger.info("SessionKeyManager initialized",
                   default_ttl_seconds=default_ttl_seconds)
    
    def start_cleanup_task(self) -> None:
        """Start the background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.debug("Started session key cleanup task")
    
    async def _cleanup_loop(self) -> None:
        """Periodically remove expired session keys."""
        while True:
            try:
                await asyncio.sleep(60)  # Check every minute
                await self._cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Session key cleanup error", error=str(e))
    
    async def _cleanup_expired(self) -> int:
        """Remove all expired session keys."""
        async with self._lock:
            expired_keys = [
                key_id for key_id, entry in self._entries.items()
                if entry.is_expired()
            ]
            
            for key_id in expired_keys:
                self._remove_key_unsafe(key_id)
            
            if expired_keys:
                logger.debug("Cleaned up expired session keys", count=len(expired_keys))
            
            return len(expired_keys)
    
    def _remove_key_unsafe(self, key_id: str) -> None:
        """Remove a key without acquiring lock. Caller must hold lock."""
        if key_id in self._keys:
            # Zero out the key bytes before removing (defense in depth)
            key_bytes = self._keys[key_id]
            # Python doesn't allow true zeroing of immutable bytes,
            # but we can at least remove our reference
            del self._keys[key_id]
        
        if key_id in self._entries:
            entry = self._entries[key_id]
            # Remove from user's key list
            if entry.user_id in self._user_keys:
                self._user_keys[entry.user_id] = [
                    k for k in self._user_keys[entry.user_id] if k != key_id
                ]
            del self._entries[key_id]
    
    async def store_key(
        self,
        user_id: str,
        derived_key: bytes,
        wallet_public_key: str,
        ttl_seconds: Optional[int] = None
    ) -> str:
        """
        Store a derived key in memory with TTL.
        
        Args:
            user_id: User identifier
            derived_key: 32-byte AES-256 key
            wallet_public_key: Public key used for derivation
            ttl_seconds: Time to live (default: 1 hour)
            
        Returns:
            key_id for referencing this session key
        """
        ttl = ttl_seconds or self._default_ttl
        key_id = f"sk_{secrets.token_urlsafe(16)}"
        
        entry = SessionKeyEntry(
            key_id=key_id,
            user_id=user_id,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl),
            wallet_public_key=wallet_public_key,
        )
        
        async with self._lock:
            # Enforce max keys per user
            if user_id in self._user_keys:
                while len(self._user_keys[user_id]) >= MAX_SESSION_KEYS_PER_USER:
                    # Remove oldest key
                    oldest_key_id = self._user_keys[user_id][0]
                    self._remove_key_unsafe(oldest_key_id)
                    logger.debug("Removed oldest session key for user",
                               user_id=user_id,
                               removed_key_id=oldest_key_id)
            
            # Store the key
            self._keys[key_id] = derived_key
            self._entries[key_id] = entry
            
            # Track user's keys
            if user_id not in self._user_keys:
                self._user_keys[user_id] = []
            self._user_keys[user_id].append(key_id)
        
        logger.debug("Stored session key",
                    user_id=user_id,
                    key_id=key_id,
                    ttl_seconds=ttl)
        
        return key_id
    
    async def get_key(self, key_id: str) -> Optional[bytes]:
        """
        Retrieve a session key by ID.
        
        Returns None if key doesn't exist or is expired.
        """
        async with self._lock:
            if key_id not in self._entries:
                return None
            
            entry = self._entries[key_id]
            
            if entry.is_expired():
                self._remove_key_unsafe(key_id)
                return None
            
            entry.touch()
            return self._keys.get(key_id)
    
    async def get_user_active_key(self, user_id: str) -> Optional[Tuple[str, bytes]]:
        """
        Get the most recent active session key for a user.
        
        Returns:
            Tuple of (key_id, key_bytes) or None if no active key
        """
        async with self._lock:
            if user_id not in self._user_keys:
                return None
            
            # Find most recent non-expired key
            for key_id in reversed(self._user_keys[user_id]):
                if key_id in self._entries:
                    entry = self._entries[key_id]
                    if not entry.is_expired():
                        entry.touch()
                        key = self._keys.get(key_id)
                        if key:
                            return (key_id, key)
            
            return None
    
    async def invalidate_user_keys(self, user_id: str) -> int:
        """
        Invalidate all session keys for a user.
        
        Returns number of keys invalidated.
        """
        async with self._lock:
            if user_id not in self._user_keys:
                return 0
            
            key_ids = list(self._user_keys[user_id])
            for key_id in key_ids:
                self._remove_key_unsafe(key_id)
            
            logger.info("Invalidated user session keys",
                       user_id=user_id,
                       count=len(key_ids))
            
            return len(key_ids)
    
    async def get_key_info(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get metadata about a session key (without the key itself)."""
        async with self._lock:
            if key_id not in self._entries:
                return None
            
            entry = self._entries[key_id]
            return {
                "key_id": entry.key_id,
                "user_id": entry.user_id,
                "created_at": entry.created_at.isoformat(),
                "expires_at": entry.expires_at.isoformat(),
                "last_used_at": entry.last_used_at.isoformat(),
                "is_expired": entry.is_expired(),
                "wallet_public_key": entry.wallet_public_key[:8] + "...",  # Truncated
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about session key usage."""
        return {
            "total_keys": len(self._keys),
            "total_users": len(self._user_keys),
            "default_ttl_seconds": self._default_ttl,
            "max_keys_per_user": MAX_SESSION_KEYS_PER_USER,
        }


class UserKeyManager:
    """
    High-level manager for user encryption keys.
    
    Coordinates between:
    - Wallet key derivation (wallet_keys.py)
    - Session key caching (SessionKeyManager)
    - User encryption mode tracking
    """
    
    def __init__(self):
        self.session_keys = SessionKeyManager()
        self.wallet_derivation = get_wallet_key_derivation()
        
        # In-memory wallet registrations (would be persisted in production)
        self._registrations: Dict[str, WalletRegistration] = {}
        self._lock = asyncio.Lock()
    
    async def register_wallet(
        self,
        user_id: str,
        wallet_public_key: str,
        signature_base64: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register a wallet for encryption key derivation.
        
        Args:
            user_id: User identifier
            wallet_public_key: Solana public key (base58)
            signature_base64: Signature of key derivation message
            ip_address: Client IP for audit
            user_agent: Client user agent for audit
            
        Returns:
            Registration result dict
        """
        # Verify signature and derive key
        success, derived_key, metadata = self.wallet_derivation.verify_and_derive_key(
            user_id=user_id,
            public_key_base58=wallet_public_key,
            signature_base64=signature_base64,
        )
        
        if not success or derived_key is None:
            return {
                "success": False,
                "error": metadata.get("error", "verification_failed"),
                "message": metadata.get("message", "Wallet verification failed"),
            }
        
        # Create registration record
        registration = WalletRegistration(
            user_id=user_id,
            wallet_public_key=wallet_public_key,
            registered_from_ip=ip_address,
            registered_user_agent=user_agent,
        )
        
        async with self._lock:
            self._registrations[user_id] = registration
        
        # Store the derived key as a session key
        key_id = await self.session_keys.store_key(
            user_id=user_id,
            derived_key=derived_key,
            wallet_public_key=wallet_public_key,
        )
        
        logger.info("Wallet registered for encryption",
                   user_id=user_id,
                   wallet_public_key=wallet_public_key[:8] + "...")
        
        return {
            "success": True,
            "encryption_mode": EncryptionMode.WALLET.value,
            "wallet_public_key": wallet_public_key,
            "registered_at": registration.registered_at.isoformat(),
            "key_derivation_version": registration.key_derivation_version,
            "session_key_id": key_id,
        }
    
    async def derive_session_key(
        self,
        user_id: str,
        wallet_public_key: str,
        signature_base64: str,
    ) -> Dict[str, Any]:
        """
        Derive a new session key from a wallet signature.
        
        Used when user needs to refresh their session key.
        """
        # Verify the wallet is registered
        async with self._lock:
            registration = self._registrations.get(user_id)
        
        if not registration or not registration.is_active:
            return {
                "success": False,
                "error": "wallet_not_registered",
                "message": "No active wallet registration found for user",
            }
        
        if registration.wallet_public_key != wallet_public_key:
            return {
                "success": False,
                "error": "wallet_mismatch",
                "message": "Provided wallet does not match registered wallet",
            }
        
        # Verify and derive
        success, derived_key, metadata = self.wallet_derivation.verify_and_derive_key(
            user_id=user_id,
            public_key_base58=wallet_public_key,
            signature_base64=signature_base64,
        )
        
        if not success or derived_key is None:
            return {
                "success": False,
                "error": metadata.get("error", "derivation_failed"),
                "message": metadata.get("message", "Key derivation failed"),
            }
        
        # Store as session key
        key_id = await self.session_keys.store_key(
            user_id=user_id,
            derived_key=derived_key,
            wallet_public_key=wallet_public_key,
        )
        
        return {
            "success": True,
            "session_key_id": key_id,
            "expires_at": (datetime.now(UTC) + timedelta(seconds=DEFAULT_SESSION_KEY_TTL_SECONDS)).isoformat(),
        }
    
    async def get_user_encryption_key(
        self,
        user_id: str,
        signature_base64: Optional[str] = None,
    ) -> Optional[bytes]:
        """
        Get the encryption key for a user.
        
        If user has wallet mode and active session key, returns that.
        If signature provided, derives a new key.
        Otherwise returns None (caller should use server key).
        """
        # Check for active session key first
        result = await self.session_keys.get_user_active_key(user_id)
        if result:
            return result[1]
        
        # If signature provided and user is registered, derive new key
        if signature_base64:
            async with self._lock:
                registration = self._registrations.get(user_id)
            
            if registration and registration.is_active:
                derive_result = await self.derive_session_key(
                    user_id=user_id,
                    wallet_public_key=registration.wallet_public_key,
                    signature_base64=signature_base64,
                )
                
                if derive_result.get("success"):
                    key_id = derive_result["session_key_id"]
                    return await self.session_keys.get_key(key_id)
        
        return None
    
    async def get_user_encryption_mode(self, user_id: str) -> EncryptionMode:
        """Get the encryption mode for a user."""
        async with self._lock:
            registration = self._registrations.get(user_id)
        
        if registration and registration.is_active:
            return EncryptionMode.WALLET
        
        return EncryptionMode.SERVER
    
    async def get_wallet_status(self, user_id: str) -> Dict[str, Any]:
        """Get wallet encryption status for a user."""
        async with self._lock:
            registration = self._registrations.get(user_id)
        
        if not registration:
            return {
                "user_id": user_id,
                "encryption_mode": EncryptionMode.SERVER.value,
                "wallet_registered": False,
            }
        
        # Check for active session key
        active_key = await self.session_keys.get_user_active_key(user_id)
        
        return {
            "user_id": user_id,
            "encryption_mode": EncryptionMode.WALLET.value if registration.is_active else EncryptionMode.SERVER.value,
            "wallet_registered": True,
            "wallet_public_key": registration.wallet_public_key,
            "registered_at": registration.registered_at.isoformat(),
            "key_derivation_version": registration.key_derivation_version,
            "has_active_session_key": active_key is not None,
        }


# Global instance
_user_key_manager: Optional[UserKeyManager] = None


def get_user_key_manager() -> UserKeyManager:
    """Get or create global user key manager."""
    global _user_key_manager
    if _user_key_manager is None:
        _user_key_manager = UserKeyManager()
    return _user_key_manager


# Re-export for convenience
from typing import Tuple
