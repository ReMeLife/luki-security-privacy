"""
Cryptographic utilities for LUKi
JWT signing, encryption, hashing, and key management
"""

from .encrypt import encrypt_bytes, decrypt_bytes, generate_key

try:
    from .jwt import create_jwt, verify_jwt, JWTError
except ModuleNotFoundError:
    def _jwt_not_available(*args, **kwargs):  # type: ignore[override]
        raise RuntimeError("JWT functionality is not available (PyJWT / jwt module not installed)")

    create_jwt = _jwt_not_available  # type: ignore[assignment]
    verify_jwt = _jwt_not_available  # type: ignore[assignment]

    class JWTError(Exception):  # type: ignore[assignment]
        pass

from .keys import KeyManager, rotate_keys
from .hash import hash_password, verify_password, secure_hash

__all__ = [
    "encrypt_bytes",
    "decrypt_bytes", 
    "generate_key",
    "create_jwt",
    "verify_jwt",
    "JWTError",
    "KeyManager",
    "rotate_keys",
    "hash_password",
    "verify_password",
    "secure_hash",
]
