"""
Request sanitization and validation for LUKi Security & Privacy
Provides input sanitization to prevent injection attacks
"""

import re
import html
import logging
from typing import Dict, Any, Optional, List
from enum import Enum
import json

logger = logging.getLogger(__name__)


class SanitizationLevel(str, Enum):
    """Sanitization strictness levels"""
    STRICT = "strict"    # Maximum sanitization, minimal allowed characters
    MODERATE = "moderate"  # Balanced sanitization
    LENIENT = "lenient"  # Minimal sanitization


class InputSanitizer:
    """Sanitize user inputs to prevent injection attacks"""
    
    # Common injection patterns
    SQL_INJECTION_PATTERNS = [
        r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b",
        r"(?i)(--|;|\/\*|\*\/)",
        r"(?i)\b(OR|AND)\s+\d+\s*=\s*\d+",
    ]
    
    XSS_PATTERNS = [
        r"(?i)<script[^>]*>.*?</script>",
        r"(?i)<iframe[^>]*>.*?</iframe>",
        r"(?i)javascript:",
        r"(?i)on\w+\s*=",
        r"(?i)<embed[^>]*>",
        r"(?i)<object[^>]*>",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"(?i)(;|\||&|`|\$\()",
        r"(?i)\b(bash|sh|cmd|powershell)\b",
    ]
    
    @classmethod
    def sanitize_string(
        cls,
        value: str,
        level: SanitizationLevel = SanitizationLevel.MODERATE,
        max_length: Optional[int] = None
    ) -> str:
        """
        Sanitize string input
        
        Args:
            value: Input string
            level: Sanitization level
            max_length: Maximum allowed length
        
        Returns:
            Sanitized string
        """
        if not value:
            return ""
        
        # Truncate if needed
        if max_length and len(value) > max_length:
            value = value[:max_length]
            logger.warning(f"String truncated to {max_length} characters")
        
        # Strip whitespace
        sanitized = value.strip()
        
        # HTML escape for XSS prevention
        sanitized = html.escape(sanitized)
        
        # Apply level-specific sanitization
        if level == SanitizationLevel.STRICT:
            # Only allow alphanumeric, spaces, and basic punctuation
            sanitized = re.sub(r'[^a-zA-Z0-9\s\.\,\!\?\-]', '', sanitized)
        
        elif level == SanitizationLevel.MODERATE:
            # Remove dangerous patterns
            for pattern in cls.XSS_PATTERNS:
                sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Normalize whitespace
        sanitized = " ".join(sanitized.split())
        
        return sanitized
    
    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """
        Sanitize filename to prevent path traversal
        
        Args:
            filename: Input filename
        
        Returns:
            Sanitized filename
        """
        if not filename:
            return "unnamed"
        
        # Remove path traversal patterns
        sanitized = filename
        for pattern in cls.PATH_TRAVERSAL_PATTERNS:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Remove directory separators
        sanitized = sanitized.replace('/', '').replace('\\', '')
        
        # Only allow safe characters
        sanitized = re.sub(r'[^a-zA-Z0-9\._\-]', '_', sanitized)
        
        # Ensure it's not empty
        if not sanitized:
            sanitized = "unnamed"
        
        # Limit length
        if len(sanitized) > 255:
            name, ext = sanitized.rsplit('.', 1) if '.' in sanitized else (sanitized, '')
            max_name_len = 250 - len(ext)
            sanitized = f"{name[:max_name_len]}.{ext}" if ext else name[:255]
        
        return sanitized
    
    @classmethod
    def sanitize_sql_value(cls, value: str) -> str:
        """
        Sanitize value for SQL (should still use parameterized queries!)
        
        Args:
            value: Input value
        
        Returns:
            Sanitized value
        """
        if not value:
            return ""
        
        # Remove SQL injection patterns
        sanitized = value
        for pattern in cls.SQL_INJECTION_PATTERNS:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        # Escape single quotes
        sanitized = sanitized.replace("'", "''")
        
        return sanitized
    
    @classmethod
    def sanitize_command(cls, command: str) -> str:
        """
        Sanitize command input (should avoid shell execution when possible!)
        
        Args:
            command: Input command
        
        Returns:
            Sanitized command
        """
        if not command:
            return ""
        
        # Remove command injection patterns
        sanitized = command
        for pattern in cls.COMMAND_INJECTION_PATTERNS:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    @classmethod
    def sanitize_email(cls, email: str) -> Optional[str]:
        """
        Sanitize and validate email address
        
        Args:
            email: Input email
        
        Returns:
            Sanitized email or None if invalid
        """
        if not email:
            return None
        
        email = email.strip().lower()
        
        # Basic email regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            logger.warning(f"Invalid email format: {email}")
            return None
        
        return email
    
    @classmethod
    def sanitize_url(cls, url: str, allowed_schemes: Optional[List[str]] = None) -> Optional[str]:
        """
        Sanitize and validate URL
        
        Args:
            url: Input URL
            allowed_schemes: Allowed URL schemes (default: http, https)
        
        Returns:
            Sanitized URL or None if invalid
        """
        if not url:
            return None
        
        url = url.strip()
        
        if allowed_schemes is None:
            allowed_schemes = ['http', 'https']
        
        # Check scheme
        scheme_match = re.match(r'^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/', url)
        if not scheme_match:
            logger.warning(f"No scheme in URL: {url}")
            return None
        
        scheme = scheme_match.group(1).lower()
        if scheme not in allowed_schemes:
            logger.warning(f"Disallowed URL scheme: {scheme}")
            return None
        
        # Remove javascript: and data: schemes (even if escaped)
        dangerous_schemes = ['javascript', 'data', 'vbscript']
        for dangerous in dangerous_schemes:
            if dangerous in url.lower():
                logger.warning(f"Dangerous scheme detected in URL: {url}")
                return None
        
        return url
    
    @classmethod
    def sanitize_json(cls, json_str: str, max_depth: int = 10) -> Optional[Dict[str, Any]]:
        """
        Sanitize and parse JSON input
        
        Args:
            json_str: JSON string
            max_depth: Maximum nesting depth
        
        Returns:
            Parsed JSON dict or None if invalid
        """
        if not json_str:
            return None
        
        try:
            data = json.loads(json_str)
            
            # Check depth
            if cls._get_dict_depth(data) > max_depth:
                logger.warning(f"JSON depth exceeds maximum: {max_depth}")
                return None
            
            return data
        
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON: {e}")
            return None
    
    @staticmethod
    def _get_dict_depth(d: Any, current_depth: int = 0) -> int:
        """Calculate maximum depth of nested dict/list"""
        if not isinstance(d, (dict, list)):
            return current_depth
        
        if isinstance(d, dict):
            if not d:
                return current_depth
            return max(InputSanitizer._get_dict_depth(v, current_depth + 1) for v in d.values())
        
        if isinstance(d, list):
            if not d:
                return current_depth
            return max(InputSanitizer._get_dict_depth(item, current_depth + 1) for item in d)
        
        return current_depth


class RequestValidator:
    """Validate request parameters"""
    
    @staticmethod
    def validate_user_id(user_id: str) -> bool:
        """Validate user ID format"""
        if not user_id or len(user_id) < 3 or len(user_id) > 128:
            return False
        
        # Allow alphanumeric with _ and -
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', user_id))
    
    @staticmethod
    def validate_resource_id(resource_id: str, resource_type: str) -> bool:
        """Validate resource ID format"""
        if not resource_id or len(resource_id) > 256:
            return False
        
        # Resource IDs should be alphanumeric with limited special chars
        return bool(re.match(r'^[a-zA-Z0-9_\-:\.]+$', resource_id))
    
    @staticmethod
    def validate_pagination(limit: int, offset: int) -> bool:
        """Validate pagination parameters"""
        if limit < 1 or limit > 1000:
            logger.warning(f"Invalid limit: {limit}")
            return False
        
        if offset < 0:
            logger.warning(f"Invalid offset: {offset}")
            return False
        
        return True
    
    @staticmethod
    def validate_content_type(content_type: str, allowed_types: List[str]) -> bool:
        """Validate content type"""
        if not content_type:
            return False
        
        # Normalize content type
        content_type = content_type.split(';')[0].strip().lower()
        
        return content_type in allowed_types
    
    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """Validate API key format"""
        if not api_key:
            return False
        
        # API keys should be alphanumeric or base64
        # Minimum 32 characters for security
        if len(api_key) < 32:
            return False
        
        return bool(re.match(r'^[a-zA-Z0-9+/=_-]+$', api_key))


def sanitize_dict(data: Dict[str, Any], level: SanitizationLevel = SanitizationLevel.MODERATE) -> Dict[str, Any]:
    """
    Recursively sanitize dictionary values
    
    Args:
        data: Input dictionary
        level: Sanitization level
    
    Returns:
        Sanitized dictionary
    """
    sanitized = {}
    
    for key, value in data.items():
        # Sanitize key
        safe_key = InputSanitizer.sanitize_string(key, level=SanitizationLevel.STRICT, max_length=100)
        
        # Sanitize value based on type
        if isinstance(value, str):
            sanitized[safe_key] = InputSanitizer.sanitize_string(value, level=level)
        elif isinstance(value, dict):
            sanitized[safe_key] = sanitize_dict(value, level=level)
        elif isinstance(value, list):
            sanitized[safe_key] = [
                InputSanitizer.sanitize_string(item, level=level) if isinstance(item, str) else item
                for item in value
            ]
        else:
            # Keep other types as-is (numbers, booleans, None)
            sanitized[safe_key] = value
    
    return sanitized
