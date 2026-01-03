"""
Security configuration management for LUKi
Toggles for DP, FL, crypto backends and security settings
"""

import os
from enum import Enum
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class CryptoBackend(str, Enum):
    """Supported cryptographic backends"""
    CRYPTOGRAPHY = "cryptography"
    PYNACL = "pynacl"
    

class DPMechanism(str, Enum):
    """Differential Privacy mechanisms"""
    LAPLACE = "laplace"
    GAUSSIAN = "gaussian"
    DISABLED = "disabled"


class FLBackend(str, Enum):
    """Federated Learning backends"""
    FLOWER = "flower"
    PYSYFT = "pysyft"
    DISABLED = "disabled"


class QuantumMode(str, Enum):
    """Quantum-safe encryption operational modes"""
    DISABLED = "disabled"           # No PQC features active
    GROUNDWORK = "groundwork"       # Infrastructure ready, monitoring only
    HYBRID_OPTIONAL = "hybrid_opt"  # Hybrid encryption available for opt-in
    HYBRID_DEFAULT = "hybrid_def"   # Hybrid encryption by default
    FULL_PQC = "full_pqc"          # Full post-quantum (future)


class QuantumSecurityLevel(str, Enum):
    """NIST security levels for post-quantum cryptography"""
    KYBER_512 = "kyber512"    # NIST Level 1 (~AES-128)
    KYBER_768 = "kyber768"    # NIST Level 3 (~AES-192)
    KYBER_1024 = "kyber1024"  # NIST Level 5 (~AES-256) - Recommended


class SecurityConfig(BaseSettings):
    """Security and privacy configuration settings"""
    
    # Crypto settings
    crypto_backend: CryptoBackend = Field(default=CryptoBackend.CRYPTOGRAPHY)
    encryption_key_size: int = Field(default=256, description="AES key size in bits")
    jwt_algorithm: str = Field(default="HS256")
    jwt_expiry_minutes: int = Field(default=15)
    
    # Differential Privacy settings
    dp_mechanism: DPMechanism = Field(default=DPMechanism.LAPLACE)
    dp_epsilon: float = Field(default=1.0, description="Privacy budget epsilon")
    dp_delta: float = Field(default=1e-5, description="Privacy budget delta")
    dp_sensitivity: float = Field(default=1.0, description="Query sensitivity")
    
    # Federated Learning settings
    fl_backend: FLBackend = Field(default=FLBackend.DISABLED)
    fl_rounds: int = Field(default=5)
    fl_min_clients: int = Field(default=2)
    fl_secure_aggregation: bool = Field(default=True)
    
    # Consent & Policy settings
    consent_expiry_days: int = Field(default=365)
    audit_retention_days: int = Field(default=2555)  # 7 years
    rbac_enabled: bool = Field(default=True)
    abac_enabled: bool = Field(default=False)
    
    # Anomaly Detection settings
    anomaly_detection_enabled: bool = Field(default=True)
    anomaly_threshold: float = Field(default=0.1)
    anomaly_retrain_days: int = Field(default=30)
    
    # Quantum-Safe Cryptography settings
    quantum_mode: QuantumMode = Field(
        default=QuantumMode.GROUNDWORK,
        description="Quantum-safe encryption operational mode"
    )
    quantum_security_level: QuantumSecurityLevel = Field(
        default=QuantumSecurityLevel.KYBER_1024,
        description="NIST security level for Kyber (kyber512, kyber768, kyber1024)"
    )
    quantum_hybrid_enabled: bool = Field(
        default=True,
        description="Enable hybrid classical+quantum key encapsulation"
    )
    quantum_status_public: bool = Field(
        default=True,
        description="Make quantum status endpoints publicly accessible"
    )
    
    # Environment-specific overrides
    debug_mode: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    model_config = {"env_prefix": "LUKI_SEC_", "case_sensitive": False}


# Global configuration instance
_config = SecurityConfig()


def get_security_config() -> SecurityConfig:
    """Get the global security configuration"""
    return _config


def update_security_config(new_config: SecurityConfig) -> None:
    """Update the global security configuration"""
    global _config
    _config = new_config


def validate_crypto_settings() -> list[str]:
    """
    Validate cryptographic settings.
    
    Returns:
        List of validation warnings
    """
    warnings = []
    config = get_security_config()
    
    if config.encryption_key_size not in [128, 192, 256]:
        warnings.append(f"Invalid encryption key size: {config.encryption_key_size}")
    
    if config.dp_epsilon <= 0:
        warnings.append(f"DP epsilon must be positive: {config.dp_epsilon}")
    
    if config.dp_delta < 0 or config.dp_delta >= 1:
        warnings.append(f"DP delta must be between 0 and 1: {config.dp_delta}")
    
    return warnings


def is_quantum_safe_enabled() -> bool:
    """Check if quantum-safe cryptography is enabled."""
    config = get_security_config()
    return config.quantum_mode != QuantumMode.DISABLED


def get_recommended_security_level() -> QuantumSecurityLevel:
    """Get recommended quantum security level."""
    return QuantumSecurityLevel.KYBER_1024
