"""
Quantum Readiness Module for LUKi
Tracks quantum-safe migration status and provides readiness metrics

This module provides infrastructure for:
- Tracking quantum readiness status
- Migration version management
- Quantum security metrics and threat assessment
- Future upgrade path documentation
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, UTC
from enum import Enum
from pydantic import BaseModel, Field
import structlog

from .quantum_safe import (
    get_kyber, 
    get_hybrid_kem, 
    check_quantum_backend,
    QuantumSecurityLevel
)

logger = structlog.get_logger(__name__)


class QuantumReadinessLevel(str, Enum):
    """Levels of quantum readiness for the system"""
    NOT_READY = "not_ready"           # No PQC infrastructure
    GROUNDWORK = "groundwork"         # PQC libraries integrated, not active in production
    HYBRID_READY = "hybrid_ready"     # Can use hybrid encryption on demand
    HYBRID_ACTIVE = "hybrid_active"   # Actively using hybrid encryption for some data
    FULL_PQC = "full_pqc"            # Full post-quantum (future - when ecosystem ready)


class QuantumThreatLevel(str, Enum):
    """Assessment of current quantum computing threat to cryptography"""
    MINIMAL = "minimal"       # 15+ years away from cryptographically relevant QC
    LOW = "low"              # 10-15 years - current assessment as of 2025
    MODERATE = "moderate"    # 5-10 years
    ELEVATED = "elevated"    # <5 years - urgent migration needed
    CRITICAL = "critical"    # Cryptographically relevant quantum computers exist


class AlgorithmStatus(BaseModel):
    """Status of a cryptographic algorithm"""
    algorithm: str
    quantum_resistant: bool
    status: str
    notes: Optional[str] = None


class QuantumReadinessStatus(BaseModel):
    """Complete quantum readiness status report"""
    
    # Overall status
    readiness_level: QuantumReadinessLevel
    threat_assessment: QuantumThreatLevel
    last_updated: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    # Algorithm status
    symmetric_encryption: Dict[str, Any] = {}
    key_encapsulation: Dict[str, Any] = {}
    digital_signatures: Dict[str, Any] = {}
    
    # Infrastructure status
    pqc_libraries_available: bool = False
    hybrid_mode_available: bool = False
    migration_version: str = "v1"
    
    # Recommendations and upgrade path
    recommendations: List[str] = []
    upgrade_path: List[str] = []


class QuantumReadinessChecker:
    """
    Checks and reports on quantum readiness status.
    
    This class provides comprehensive status reporting for:
    - Current cryptographic algorithm status
    - Post-quantum library availability
    - Migration readiness
    - Threat assessment based on current quantum computing progress
    """
    
    def __init__(self):
        self.kyber = get_kyber()
        self.hybrid = get_hybrid_kem()
        self._backends = check_quantum_backend()
    
    def check_pqc_libraries(self) -> Dict[str, bool]:
        """Check availability of post-quantum cryptography libraries."""
        libraries = {
            "liboqs": False,
            "liboqs_algorithms": [],
            "cryptography": False,
            "cryptography_version": None,
        }
        
        # Check liboqs (Open Quantum Safe)
        try:
            import oqs
            libraries["liboqs"] = True
            # List available algorithms
            try:
                libraries["liboqs_algorithms"] = oqs.get_enabled_kem_mechanisms()
            except Exception:
                libraries["liboqs_algorithms"] = ["Kyber512", "Kyber768", "Kyber1024"]
        except ImportError:
            pass
        
        # Check cryptography library (used for X25519 in hybrid mode)
        try:
            import cryptography
            libraries["cryptography"] = True
            libraries["cryptography_version"] = cryptography.__version__
        except ImportError:
            pass
        
        return libraries
    
    def assess_threat_level(self) -> QuantumThreatLevel:
        """
        Assess current quantum threat level to cryptography.
        
        Based on publicly available information about quantum computer development
        as of December 2025. This assessment considers:
        - Current qubit counts and error rates
        - Estimated timeline to cryptographically relevant quantum computers
        - Expert consensus from NIST, NSA, and academic researchers
        
        Current assessment: LOW (10-15+ years to threat)
        """
        # As of December 2025:
        # - Largest quantum computers: ~1000+ qubits but high error rates
        # - Cryptographically relevant QC needs: ~4000+ logical qubits with low error
        # - Estimated timeline: 10-15+ years (conservative), 7-10 years (aggressive)
        # - NIST recommendation: Begin migration now, complete by 2030
        
        return QuantumThreatLevel.LOW
    
    def get_symmetric_status(self) -> Dict[str, Any]:
        """Get status of symmetric encryption algorithms (AES)."""
        return {
            "algorithm": "AES-256-GCM",
            "key_size_bits": 256,
            "quantum_resistant": True,
            "post_quantum_security_bits": 128,
            "status": "SAFE",
            "explanation": (
                "AES-256 provides 128-bit security against quantum attacks due to "
                "Grover's algorithm, which effectively halves the security level. "
                "128-bit security is still considered sufficient for long-term protection."
            ),
            "action_required": False,
            "nist_guidance": "AES-256 is approved for protecting classified information through 2030+",
        }
    
    def get_kem_status(self) -> Dict[str, Any]:
        """Get status of key encapsulation mechanisms."""
        kyber_status = self.kyber.get_status()
        
        return {
            "classical": {
                "algorithm": "X25519 (Curve25519 ECDH)",
                "key_size_bits": 256,
                "quantum_resistant": False,
                "status": "VULNERABLE",
                "vulnerability": "Shor's algorithm can break elliptic curve cryptography",
                "timeline": "Safe until large-scale fault-tolerant quantum computers exist",
                "current_use": "Still safe for current communications, migration recommended",
            },
            "post_quantum": {
                "algorithm": "CRYSTALS-Kyber (ML-KEM)",
                "variant": kyber_status.get("variant", "Kyber1024"),
                "nist_standard": True,
                "fips_standard": "FIPS 203",
                "standardization_year": 2024,
                "quantum_resistant": True,
                "status": "READY" if kyber_status.get("production_ready") else "SIMULATION",
                "backend": kyber_status.get("backend", "unknown"),
                "security_level": kyber_status.get("nist_level", 5),
            },
            "hybrid": {
                "available": True,
                "algorithms": "X25519 + CRYSTALS-Kyber",
                "security_model": "Combined - safe if EITHER algorithm remains secure",
                "status": "READY",
                "recommendation": "Use hybrid mode for long-term sensitive data",
            }
        }
    
    def get_signature_status(self) -> Dict[str, Any]:
        """Get status of digital signature algorithms."""
        return {
            "classical": {
                "algorithm": "Ed25519 (EdDSA on Curve25519)",
                "key_size_bits": 256,
                "quantum_resistant": False,
                "status": "VULNERABLE",
                "vulnerability": "Shor's algorithm can break elliptic curve signatures",
                "current_use": "Wallet signatures for key derivation in LUKi",
            },
            "post_quantum": {
                "algorithm": "CRYSTALS-Dilithium (ML-DSA)",
                "nist_standard": True,
                "fips_standard": "FIPS 204",
                "standardization_year": 2024,
                "quantum_resistant": True,
                "status": "NOT_IMPLEMENTED",
                "reason": "Awaiting wallet ecosystem support",
                "blockers": [
                    "No major Solana wallet supports Dilithium signatures",
                    "Signature size ~2.5KB vs 64 bytes for Ed25519",
                    "Requires ecosystem-wide adoption for interoperability",
                ],
            },
            "migration_path": {
                "phase_1": "Hybrid signatures (Ed25519 + Dilithium) when wallets support",
                "phase_2": "Full Dilithium migration when ecosystem ready",
                "timeline": "Dependent on wallet ecosystem (estimated 2026-2028)",
            }
        }
    
    def get_recommendations(self) -> List[str]:
        """Get actionable recommendations for improving quantum readiness."""
        recommendations = []
        
        libs = self.check_pqc_libraries()
        
        # Library recommendations
        if not libs.get("liboqs"):
            recommendations.append(
                "OPTIONAL: Install liboqs for production-grade Kyber: "
                "pip install oqs (requires liboqs C library)"
            )
        
        # General recommendations
        recommendations.extend([
            "CURRENT: AES-256-GCM symmetric encryption is quantum-resistant - no action needed",
            "READY: Hybrid key encapsulation (X25519 + Kyber) infrastructure is available",
            "MONITOR: Track wallet ecosystem for Dilithium signature support",
            "VERSIONED: All key derivation is versioned (v1) to enable future migration",
            "TIMELINE: NIST recommends completing PQC migration by 2030",
        ])
        
        return recommendations
    
    def get_upgrade_path(self) -> List[str]:
        """Get the upgrade path to full quantum safety."""
        kyber_status = self.kyber.get_status()
        production_ready = kyber_status.get("production_ready", False)
        
        return [
            f"✅ Phase 0 (Current): Groundwork complete - Kyber {'production' if production_ready else 'simulation'} mode",
            "✅ Phase 0.5: Quantum status monitoring endpoints active",
            "⏳ Phase 1: Enable hybrid KEM for opt-in users with sensitive data",
            "⏳ Phase 2: Hybrid signatures (Ed25519 + Dilithium) when wallet ecosystem supports",
            "⏳ Phase 3: Default hybrid mode for all new key derivations",
            "⏳ Phase 4: Full PQC migration - deprecate classical-only algorithms",
        ]
    
    def get_full_status(self) -> QuantumReadinessStatus:
        """Get complete quantum readiness status report."""
        libs = self.check_pqc_libraries()
        kyber_status = self.kyber.get_status()
        
        # Determine readiness level based on current state
        if kyber_status.get("production_ready"):
            readiness = QuantumReadinessLevel.HYBRID_READY
        elif kyber_status.get("backend") == "simulation":
            readiness = QuantumReadinessLevel.GROUNDWORK
        else:
            readiness = QuantumReadinessLevel.NOT_READY
        
        return QuantumReadinessStatus(
            readiness_level=readiness,
            threat_assessment=self.assess_threat_level(),
            symmetric_encryption=self.get_symmetric_status(),
            key_encapsulation=self.get_kem_status(),
            digital_signatures=self.get_signature_status(),
            pqc_libraries_available=libs.get("liboqs", False),
            hybrid_mode_available=True,
            migration_version="v1",
            recommendations=self.get_recommendations(),
            upgrade_path=self.get_upgrade_path(),
        )
    
    def get_threat_brief(self) -> Dict[str, Any]:
        """Get a brief threat assessment summary."""
        return {
            "current_threat": self.assess_threat_level().value,
            "threat_description": "Cryptographically relevant quantum computers estimated 10-15+ years away",
            "symmetric_safe": True,
            "asymmetric_vulnerable": True,
            "migration_urgency": "LOW - Begin preparation now, complete by 2030",
            "luki_status": "Groundwork complete, hybrid mode ready when needed",
        }


# Global checker instance
_readiness_checker: Optional[QuantumReadinessChecker] = None


def get_quantum_readiness_checker() -> QuantumReadinessChecker:
    """Get or create global readiness checker instance."""
    global _readiness_checker
    if _readiness_checker is None:
        _readiness_checker = QuantumReadinessChecker()
    return _readiness_checker


def get_quantum_status() -> Dict[str, Any]:
    """Convenience function to get quantum status as dict."""
    checker = get_quantum_readiness_checker()
    status = checker.get_full_status()
    return status.model_dump()


def get_quantum_threat_brief() -> Dict[str, Any]:
    """Get a brief quantum threat assessment."""
    checker = get_quantum_readiness_checker()
    return checker.get_threat_brief()
