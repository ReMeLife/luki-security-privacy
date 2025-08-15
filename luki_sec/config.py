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
    
    # Environment-specific overrides
    debug_mode: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    model_config = {"env_prefix": "LUKI_SEC_", "case_sensitive": False}


# Global configuration instance
security_config = SecurityConfig()


def get_security_config() -> SecurityConfig:
    """Get the global security configuration instance"""
    return security_config


def update_security_config(**kwargs) -> SecurityConfig:
    """Update security configuration with new values"""
    global security_config
    for key, value in kwargs.items():
        if hasattr(security_config, key):
            setattr(security_config, key, value)
    return security_config
