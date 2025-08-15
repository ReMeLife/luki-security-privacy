"""
PII sanitization and data redaction for LUKi
Remove or tokenize personally identifiable information
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import hashlib
import structlog

from ..crypto.hash import hash_pii_for_analytics
from ..config import get_security_config

logger = structlog.get_logger(__name__)


class PIIType(str, Enum):
    """Types of personally identifiable information"""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    NAME = "name"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    IP_ADDRESS = "ip_address"
    MEDICAL_ID = "medical_id"
    CUSTOM = "custom"


class RedactionMethod(str, Enum):
    """Methods for redacting PII"""
    MASK = "mask"           # Replace with ***
    REMOVE = "remove"       # Remove entirely
    HASH = "hash"          # Replace with hash
    TOKEN = "token"        # Replace with token
    PARTIAL = "partial"    # Show only partial (e.g., first 2 chars)


class PIIPattern:
    """PII detection pattern"""
    
    def __init__(self, pii_type: PIIType, pattern: str, description: str, 
                 confidence: float = 1.0):
        self.pii_type = pii_type
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.description = description
        self.confidence = confidence
    
    def find_matches(self, text: str) -> List[Tuple[int, int, str]]:
        """Find all matches in text"""
        matches = []
        for match in self.pattern.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
        return matches


class PIISanitizer:
    """PII sanitization engine"""
    
    def __init__(self):
        self.patterns: Dict[PIIType, List[PIIPattern]] = {}
        self.token_map: Dict[str, str] = {}
        self.token_counter = 0
        self._initialize_patterns()
    
    def _initialize_patterns(self) -> None:
        """Initialize default PII detection patterns"""
        
        # Email patterns
        email_patterns = [
            PIIPattern(
                PIIType.EMAIL,
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                "Standard email format"
            )
        ]
        
        # Phone patterns
        phone_patterns = [
            PIIPattern(
                PIIType.PHONE,
                r'\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b',
                "US phone number"
            ),
            PIIPattern(
                PIIType.PHONE,
                r'\b\d{3}-\d{3}-\d{4}\b',
                "Phone with dashes"
            )
        ]
        
        # SSN patterns
        ssn_patterns = [
            PIIPattern(
                PIIType.SSN,
                r'\b\d{3}-\d{2}-\d{4}\b',
                "SSN with dashes"
            ),
            PIIPattern(
                PIIType.SSN,
                r'\b\d{9}\b',
                "SSN without separators",
                confidence=0.7
            )
        ]
        
        # Credit card patterns
        cc_patterns = [
            PIIPattern(
                PIIType.CREDIT_CARD,
                r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
                "Credit card number"
            )
        ]
        
        # IP address patterns
        ip_patterns = [
            PIIPattern(
                PIIType.IP_ADDRESS,
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                "IPv4 address"
            )
        ]
        
        # Date of birth patterns
        dob_patterns = [
            PIIPattern(
                PIIType.DATE_OF_BIRTH,
                r'\b(?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b',
                "Date MM/DD/YYYY or MM-DD-YYYY"
            )
        ]
        
        # Medical ID patterns
        medical_patterns = [
            PIIPattern(
                PIIType.MEDICAL_ID,
                r'\b(?:MRN|MR|PATIENT)\s*:?\s*([A-Z0-9]{6,12})\b',
                "Medical record number",
                confidence=0.8
            )
        ]
        
        self.patterns = {
            PIIType.EMAIL: email_patterns,
            PIIType.PHONE: phone_patterns,
            PIIType.SSN: ssn_patterns,
            PIIType.CREDIT_CARD: cc_patterns,
            PIIType.IP_ADDRESS: ip_patterns,
            PIIType.DATE_OF_BIRTH: dob_patterns,
            PIIType.MEDICAL_ID: medical_patterns
        }
    
    def add_custom_pattern(self, pii_type: PIIType, pattern: str, 
                          description: str, confidence: float = 1.0) -> None:
        """Add custom PII detection pattern"""
        custom_pattern = PIIPattern(pii_type, pattern, description, confidence)
        
        if pii_type not in self.patterns:
            self.patterns[pii_type] = []
        
        self.patterns[pii_type].append(custom_pattern)
        logger.info("Added custom PII pattern", pii_type=pii_type, description=description)
    
    def detect_pii(self, text: str, min_confidence: float = 0.7) -> List[Dict[str, Any]]:
        """Detect PII in text"""
        detections = []
        
        for pii_type, patterns in self.patterns.items():
            for pattern in patterns:
                if pattern.confidence >= min_confidence:
                    matches = pattern.find_matches(text)
                    
                    for start, end, match_text in matches:
                        detections.append({
                            "type": pii_type,
                            "text": match_text,
                            "start": start,
                            "end": end,
                            "confidence": pattern.confidence,
                            "description": pattern.description
                        })
        
        # Sort by position in text
        detections.sort(key=lambda x: x["start"])
        return detections
    
    def _generate_token(self, pii_type: PIIType, original_text: str) -> str:
        """Generate consistent token for PII"""
        # Use hash of original text for consistency
        text_hash = hashlib.sha256(original_text.encode()).hexdigest()[:8]
        self.token_counter += 1
        return f"[{pii_type.upper()}_{self.token_counter}_{text_hash}]"
    
    def _redact_match(self, match_text: str, pii_type: PIIType, 
                     method: RedactionMethod) -> str:
        """Redact a single PII match"""
        if method == RedactionMethod.MASK:
            if len(match_text) <= 4:
                return "*" * len(match_text)
            else:
                return match_text[:2] + "*" * (len(match_text) - 4) + match_text[-2:]
        
        elif method == RedactionMethod.REMOVE:
            return ""
        
        elif method == RedactionMethod.HASH:
            return hash_pii_for_analytics(match_text)[:16]
        
        elif method == RedactionMethod.TOKEN:
            if match_text not in self.token_map:
                self.token_map[match_text] = self._generate_token(pii_type, match_text)
            return self.token_map[match_text]
        
        elif method == RedactionMethod.PARTIAL:
            if len(match_text) <= 2:
                return match_text
            elif len(match_text) <= 6:
                return match_text[:2] + "*" * (len(match_text) - 2)
            else:
                return match_text[:2] + "*" * (len(match_text) - 4) + match_text[-2:]
        
        return match_text
    
    def sanitize_text(self, text: str, 
                     redaction_rules: Dict[PIIType, RedactionMethod] | None = None,
                     min_confidence: float = 0.7) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Sanitize text by redacting PII
        
        Returns:
            Tuple of (sanitized_text, detected_pii_list)
        """
        if redaction_rules is None:
            redaction_rules = {pii_type: RedactionMethod.MASK for pii_type in PIIType}
        
        detections = self.detect_pii(text, min_confidence)
        
        if not detections:
            return text, []
        
        # Apply redactions in reverse order to preserve positions
        sanitized_text = text
        for detection in reversed(detections):
            pii_type = PIIType(detection["type"])
            method = redaction_rules.get(pii_type, RedactionMethod.MASK)
            
            start, end = detection["start"], detection["end"]
            original_text = detection["text"]
            
            redacted_text = self._redact_match(original_text, pii_type, method)
            sanitized_text = sanitized_text[:start] + redacted_text + sanitized_text[end:]
        
        logger.info("Sanitized text", 
                   original_length=len(text),
                   sanitized_length=len(sanitized_text),
                   pii_detected=len(detections))
        
        return sanitized_text, detections
    
    def sanitize_dict(self, data: Dict[str, Any], 
                     field_rules: Dict[str, Dict[PIIType, RedactionMethod]] | None = None) -> Dict[str, Any]:
        """Sanitize dictionary data"""
        sanitized = {}
        
        for key, value in data.items():
            if isinstance(value, str):
                rules = field_rules.get(key, {}) if field_rules else {}
                sanitized_value, _ = self.sanitize_text(value, rules)
                sanitized[key] = sanitized_value
            elif isinstance(value, dict):
                sanitized[key] = self.sanitize_dict(value, field_rules)
            elif isinstance(value, list):
                sanitized[key] = [
                    self.sanitize_dict(item, field_rules) if isinstance(item, dict)
                    else self.sanitize_text(str(item))[0] if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized
    
    def get_token_mapping(self) -> Dict[str, str]:
        """Get mapping of original PII to tokens"""
        return self.token_map.copy()
    
    def reverse_tokenization(self, text: str) -> str:
        """Reverse tokenization (use with extreme caution)"""
        reverse_map = {token: original for original, token in self.token_map.items()}
        
        result = text
        for token, original in reverse_map.items():
            result = result.replace(token, original)
        
        logger.warning("PII tokenization reversed", token_count=len(reverse_map))
        return result


# Global sanitizer instance
_pii_sanitizer: Optional[PIISanitizer] = None


def get_pii_sanitizer() -> PIISanitizer:
    """Get the global PII sanitizer instance"""
    global _pii_sanitizer
    if _pii_sanitizer is None:
        _pii_sanitizer = PIISanitizer()
    return _pii_sanitizer


def redact_pii(text: str, 
               redaction_rules: Dict[PIIType, RedactionMethod] | None = None,
               min_confidence: float = 0.7) -> str:
    """Redact PII from text"""
    sanitizer = get_pii_sanitizer()
    sanitized_text, _ = sanitizer.sanitize_text(text, redaction_rules, min_confidence)
    return sanitized_text


def tokenize_pii(text: str, min_confidence: float = 0.7) -> Tuple[str, Dict[str, str]]:
    """Tokenize PII in text and return token mapping"""
    sanitizer = get_pii_sanitizer()
    
    # Use tokenization for all PII types
    token_rules = {pii_type: RedactionMethod.TOKEN for pii_type in PIIType}
    
    sanitized_text, _ = sanitizer.sanitize_text(text, token_rules, min_confidence)
    token_mapping = sanitizer.get_token_mapping()
    
    return sanitized_text, token_mapping


def detect_pii_types(text: str, min_confidence: float = 0.7) -> List[PIIType]:
    """Detect types of PII present in text"""
    sanitizer = get_pii_sanitizer()
    detections = sanitizer.detect_pii(text, min_confidence)
    
    return list(set(PIIType(d["type"]) for d in detections))


class ELRSanitizer:
    """Specialized sanitizer for ELR data"""
    
    def __init__(self):
        self.sanitizer = get_pii_sanitizer()
        
        # Add ELR-specific patterns
        self.sanitizer.add_custom_pattern(
            PIIType.MEDICAL_ID,
            r'\b(?:PATIENT|PT)\s+(?:ID|#)?\s*:?\s*([A-Z0-9]{4,12})\b',
            "Patient ID format"
        )
        
        self.sanitizer.add_custom_pattern(
            PIIType.NAME,
            r'\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b',
            "Formal name with title"
        )
    
    def sanitize_elr_record(self, elr_data: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize ELR record with field-specific rules"""
        
        # Define field-specific redaction rules
        field_rules = {
            "name": {PIIType.NAME: RedactionMethod.TOKEN},
            "email": {PIIType.EMAIL: RedactionMethod.HASH},
            "phone": {PIIType.PHONE: RedactionMethod.PARTIAL},
            "address": {PIIType.ADDRESS: RedactionMethod.PARTIAL},
            "medical_notes": {
                PIIType.NAME: RedactionMethod.TOKEN,
                PIIType.MEDICAL_ID: RedactionMethod.TOKEN,
                PIIType.DATE_OF_BIRTH: RedactionMethod.PARTIAL
            },
            "comments": {
                PIIType.NAME: RedactionMethod.TOKEN,
                PIIType.PHONE: RedactionMethod.MASK,
                PIIType.EMAIL: RedactionMethod.MASK
            }
        }
        
        return self.sanitizer.sanitize_dict(elr_data, field_rules)
