"""
Role-Based Access Control (RBAC) for LUKi
User roles, permissions, and access control enforcement
"""

from enum import Enum
from typing import Set, Dict, List, Optional
from datetime import datetime, UTC
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)


class Permission(str, Enum):
    """System permissions"""
    # ELR Data Access
    READ_ELR_BASIC = "read_elr_basic"
    READ_ELR_INTERESTS = "read_elr_interests"
    READ_ELR_MEMORIES = "read_elr_memories"
    READ_ELR_HEALTH = "read_elr_health"
    READ_ELR_FAMILY = "read_elr_family"
    READ_ELR_LOCATION = "read_elr_location"
    
    WRITE_ELR_BASIC = "write_elr_basic"
    WRITE_ELR_INTERESTS = "write_elr_interests"
    WRITE_ELR_MEMORIES = "write_elr_memories"
    WRITE_ELR_HEALTH = "write_elr_health"
    WRITE_ELR_FAMILY = "write_elr_family"
    WRITE_ELR_LOCATION = "write_elr_location"
    
    # Analytics & Processing
    ANALYTICS_ACCESS = "analytics_access"
    PERSONALIZATION_ACCESS = "personalization_access"
    RESEARCH_ACCESS = "research_access"
    
    # AI/ML Operations
    MODEL_TRAINING = "model_training"
    FEDERATED_LEARNING = "federated_learning"
    DIFFERENTIAL_PRIVACY = "differential_privacy"
    
    # Administrative
    MANAGE_USERS = "manage_users"
    MANAGE_CONSENT = "manage_consent"
    MANAGE_KEYS = "manage_keys"
    VIEW_AUDIT_LOGS = "view_audit_logs"
    
    # Care Coordination
    CARE_COORDINATION = "care_coordination"
    EMERGENCY_ACCESS = "emergency_access"


class Role(BaseModel):
    """User role definition"""
    name: str
    description: str
    permissions: Set[Permission]
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if role has specific permission"""
        return self.is_active and permission in self.permissions
    
    def add_permission(self, permission: Permission) -> None:
        """Add permission to role"""
        self.permissions.add(permission)
    
    def remove_permission(self, permission: Permission) -> None:
        """Remove permission from role"""
        self.permissions.discard(permission)


class UserRole(BaseModel):
    """User role assignment"""
    user_id: str
    role_name: str
    assigned_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assigned_by: str
    expires_at: Optional[datetime] = None
    is_active: bool = True
    
    def is_valid(self) -> bool:
        """Check if role assignment is currently valid"""
        if not self.is_active:
            return False
        
        if self.expires_at and datetime.now(UTC) > self.expires_at:
            return False
        
        return True


class RBACManager:
    """Role-Based Access Control manager"""
    
    def __init__(self):
        self.roles: Dict[str, Role] = {}
        self.user_roles: Dict[str, List[UserRole]] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self) -> None:
        """Initialize default system roles"""
        
        # Patient/User role - basic ELR access
        patient_permissions = {
            Permission.READ_ELR_BASIC,
            Permission.READ_ELR_INTERESTS,
            Permission.READ_ELR_MEMORIES,
            Permission.WRITE_ELR_BASIC,
            Permission.WRITE_ELR_INTERESTS,
            Permission.WRITE_ELR_MEMORIES,
            Permission.PERSONALIZATION_ACCESS,
        }
        
        self.roles["patient"] = Role(
            name="patient",
            description="Patient/user with access to own ELR data",
            permissions=patient_permissions
        )
        
        # Care Team role - broader ELR access
        care_team_permissions = {
            Permission.READ_ELR_BASIC,
            Permission.READ_ELR_INTERESTS,
            Permission.READ_ELR_MEMORIES,
            Permission.READ_ELR_HEALTH,
            Permission.READ_ELR_FAMILY,
            Permission.WRITE_ELR_HEALTH,
            Permission.CARE_COORDINATION,
            Permission.ANALYTICS_ACCESS,
        }
        
        self.roles["care_team"] = Role(
            name="care_team",
            description="Care team member with health data access",
            permissions=care_team_permissions
        )
        
        # Emergency role - emergency access
        emergency_permissions = {
            Permission.READ_ELR_BASIC,
            Permission.READ_ELR_HEALTH,
            Permission.READ_ELR_FAMILY,
            Permission.EMERGENCY_ACCESS,
        }
        
        self.roles["emergency"] = Role(
            name="emergency",
            description="Emergency access for critical situations",
            permissions=emergency_permissions
        )
        
        # Researcher role - analytics and research
        researcher_permissions = {
            Permission.ANALYTICS_ACCESS,
            Permission.RESEARCH_ACCESS,
            Permission.DIFFERENTIAL_PRIVACY,
            Permission.FEDERATED_LEARNING,
        }
        
        self.roles["researcher"] = Role(
            name="researcher",
            description="Researcher with anonymized data access",
            permissions=researcher_permissions
        )
        
        # Agent role - AI agent permissions
        agent_permissions = {
            Permission.READ_ELR_BASIC,
            Permission.READ_ELR_INTERESTS,
            Permission.READ_ELR_MEMORIES,
            Permission.PERSONALIZATION_ACCESS,
            Permission.ANALYTICS_ACCESS,
        }
        
        self.roles["agent"] = Role(
            name="agent",
            description="AI agent with personalization access",
            permissions=agent_permissions
        )
        
        # Admin role - full system access
        admin_permissions = set(Permission)
        
        self.roles["admin"] = Role(
            name="admin",
            description="System administrator with full access",
            permissions=admin_permissions
        )
    
    def create_role(self, name: str, description: str, 
                   permissions: Set[Permission]) -> Role:
        """Create a new role"""
        role = Role(
            name=name,
            description=description,
            permissions=permissions
        )
        
        self.roles[name] = role
        logger.info("Created role", role_name=name, permissions=len(permissions))
        return role
    
    def assign_role(self, user_id: str, role_name: str, assigned_by: str,
                   expires_at: Optional[datetime] = None) -> bool:
        """Assign role to user"""
        if role_name not in self.roles:
            logger.error("Role not found", role_name=role_name)
            return False
        
        user_role = UserRole(
            user_id=user_id,
            role_name=role_name,
            assigned_by=assigned_by,
            expires_at=expires_at
        )
        
        if user_id not in self.user_roles:
            self.user_roles[user_id] = []
        
        self.user_roles[user_id].append(user_role)
        
        logger.info("Assigned role", user_id=user_id, role_name=role_name,
                   assigned_by=assigned_by)
        return True
    
    def revoke_role(self, user_id: str, role_name: str) -> bool:
        """Revoke role from user"""
        if user_id not in self.user_roles:
            return False
        
        for user_role in self.user_roles[user_id]:
            if user_role.role_name == role_name and user_role.is_active:
                user_role.is_active = False
                logger.info("Revoked role", user_id=user_id, role_name=role_name)
                return True
        
        return False
    
    def get_user_permissions(self, user_id: str) -> Set[Permission]:
        """Get all permissions for user across all roles"""
        permissions = set()
        
        if user_id not in self.user_roles:
            return permissions
        
        for user_role in self.user_roles[user_id]:
            if user_role.is_valid() and user_role.role_name in self.roles:
                role = self.roles[user_role.role_name]
                permissions.update(role.permissions)
        
        return permissions
    
    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        user_permissions = self.get_user_permissions(user_id)
        return permission in user_permissions
    
    def get_user_roles(self, user_id: str) -> List[str]:
        """Get active role names for user"""
        if user_id not in self.user_roles:
            return []
        
        return [
            user_role.role_name 
            for user_role in self.user_roles[user_id]
            if user_role.is_valid()
        ]
    
    def cleanup_expired_roles(self) -> int:
        """Clean up expired role assignments"""
        cleanup_count = 0
        
        for user_id, user_roles in self.user_roles.items():
            for user_role in user_roles:
                if not user_role.is_valid() and user_role.is_active:
                    user_role.is_active = False
                    cleanup_count += 1
        
        if cleanup_count > 0:
            logger.info("Cleaned up expired roles", count=cleanup_count)
        
        return cleanup_count


# Global RBAC manager instance
_rbac_manager: Optional[RBACManager] = None


def get_rbac_manager() -> RBACManager:
    """Get the global RBAC manager instance"""
    global _rbac_manager
    if _rbac_manager is None:
        _rbac_manager = RBACManager()
    return _rbac_manager


def check_permission(user_id: str, permission: Permission) -> bool:
    """Check if user has specific permission"""
    return get_rbac_manager().check_permission(user_id, permission)


def assign_role(user_id: str, role_name: str, assigned_by: str,
               expires_at: Optional[datetime] = None) -> bool:
    """Assign role to user"""
    return get_rbac_manager().assign_role(user_id, role_name, assigned_by, expires_at)


def get_user_permissions(user_id: str) -> Set[Permission]:
    """Get all permissions for user"""
    return get_rbac_manager().get_user_permissions(user_id)
