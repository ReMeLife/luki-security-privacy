"""
JWT utilities for LUKi
JWT token creation, verification, and management
"""

import jwt
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import structlog

from ..config import get_security_config

logger = structlog.get_logger(__name__)


class JWTError(Exception):
    """Base exception for JWT-related errors"""
    pass


class JWTExpiredError(JWTError):
    """Raised when JWT token has expired"""
    pass


class JWTInvalidError(JWTError):
    """Raised when JWT token is invalid"""
    pass


def create_jwt(payload: Dict[str, Any], secret_key: str, 
               algorithm: Optional[str] = None, 
               expires_in_minutes: Optional[int] = None) -> str:
    """
    Create a JWT token
    
    Args:
        payload: Token payload data
        secret_key: Secret key for signing
        algorithm: JWT algorithm (default from config)
        expires_in_minutes: Token expiry (default from config)
        
    Returns:
        Encoded JWT token string
    """
    try:
        config = get_security_config()
        algorithm = algorithm or config.jwt_algorithm
        expires_in_minutes = expires_in_minutes or config.jwt_expiry_minutes
        
        # Add standard claims
        now = datetime.utcnow()
        token_payload = {
            **payload,
            'iat': now,  # Issued at
            'exp': now + timedelta(minutes=expires_in_minutes),  # Expires
            'iss': 'luki-security',  # Issuer
        }
        
        token = jwt.encode(token_payload, secret_key, algorithm=algorithm)
        
        logger.info("Created JWT token", 
                   subject=payload.get('sub'), 
                   expires_in=expires_in_minutes)
        
        return token
        
    except Exception as e:
        logger.error("JWT creation failed", error=str(e))
        raise JWTError(f"Failed to create JWT: {str(e)}")


def verify_jwt(token: str, secret_key: str, 
               algorithm: Optional[str] = None) -> Dict[str, Any]:
    """
    Verify and decode a JWT token
    
    Args:
        token: JWT token string
        secret_key: Secret key for verification
        algorithm: JWT algorithm (default from config)
        
    Returns:
        Decoded token payload
        
    Raises:
        JWTExpiredError: If token has expired
        JWTInvalidError: If token is invalid
    """
    try:
        config = get_security_config()
        algorithm = algorithm or config.jwt_algorithm
        
        payload = jwt.decode(
            token, 
            secret_key, 
            algorithms=[algorithm],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'require_exp': True,
                'require_iat': True,
            }
        )
        
        logger.debug("JWT token verified", subject=payload.get('sub'))
        return payload
        
    except jwt.ExpiredSignatureError:
        logger.warning("JWT token expired")
        raise JWTExpiredError("Token has expired")
    except jwt.InvalidTokenError as e:
        logger.warning("JWT token invalid", error=str(e))
        raise JWTInvalidError(f"Invalid token: {str(e)}")
    except Exception as e:
        logger.error("JWT verification failed", error=str(e))
        raise JWTError(f"JWT verification failed: {str(e)}")


def create_access_token(user_id: str, role: str, scopes: list, 
                       secret_key: str) -> str:
    """Create an access token for API authentication"""
    payload = {
        'sub': user_id,  # Subject (user ID)
        'role': role,
        'scopes': scopes,
        'type': 'access'
    }
    return create_jwt(payload, secret_key)


def create_refresh_token(user_id: str, secret_key: str) -> str:
    """Create a refresh token for token renewal"""
    payload = {
        'sub': user_id,
        'type': 'refresh'
    }
    # Refresh tokens have longer expiry
    return create_jwt(payload, secret_key, expires_in_minutes=10080)  # 7 days


def verify_access_token(token: str, secret_key: str) -> Dict[str, Any]:
    """Verify an access token and return user info"""
    payload = verify_jwt(token, secret_key)
    
    if payload.get('type') != 'access':
        raise JWTInvalidError("Not an access token")
    
    return {
        'user_id': payload.get('sub'),
        'role': payload.get('role'),
        'scopes': payload.get('scopes', []),
        'expires_at': payload.get('exp')
    }


def verify_refresh_token(token: str, secret_key: str) -> str:
    """Verify a refresh token and return user ID"""
    payload = verify_jwt(token, secret_key)
    
    if payload.get('type') != 'refresh':
        raise JWTInvalidError("Not a refresh token")
    
    return payload.get('sub')


class JWTManager:
    """JWT token manager with key rotation support"""
    
    def __init__(self, current_key: str, previous_key: Optional[str] = None):
        self.current_key = current_key
        self.previous_key = previous_key
    
    def create_token(self, payload: Dict[str, Any]) -> str:
        """Create token with current key"""
        return create_jwt(payload, self.current_key)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify token with current or previous key"""
        try:
            # Try current key first
            return verify_jwt(token, self.current_key)
        except JWTInvalidError:
            if self.previous_key:
                try:
                    # Try previous key for graceful key rotation
                    logger.info("Verifying token with previous key")
                    return verify_jwt(token, self.previous_key)
                except JWTInvalidError:
                    pass
            raise
    
    def rotate_key(self, new_key: str) -> None:
        """Rotate to new key, keeping current as previous"""
        self.previous_key = self.current_key
        self.current_key = new_key
        logger.info("JWT key rotated")


def extract_bearer_token(authorization_header: str) -> str:
    """Extract JWT token from Authorization header"""
    if not authorization_header:
        raise JWTInvalidError("No authorization header")
    
    if not authorization_header.startswith('Bearer '):
        raise JWTInvalidError("Invalid authorization header format")
    
    return authorization_header[7:]  # Remove 'Bearer ' prefix
