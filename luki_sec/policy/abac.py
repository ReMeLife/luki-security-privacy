"""
Attribute-Based Access Control (ABAC) for LUKi
Context-aware access control using attributes and policies
"""

from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, UTC, time
from enum import Enum
from pydantic import BaseModel, Field
import structlog

logger = structlog.get_logger(__name__)


class AttributeType(str, Enum):
    """Types of attributes for ABAC evaluation"""
    USER = "user"
    RESOURCE = "resource"
    ENVIRONMENT = "environment"
    ACTION = "action"


class PolicyEffect(str, Enum):
    """Policy evaluation effects"""
    ALLOW = "allow"
    DENY = "deny"


class AttributeContext(BaseModel):
    """Context containing attributes for policy evaluation"""
    user_attributes: Dict[str, Any] = {}
    resource_attributes: Dict[str, Any] = {}
    environment_attributes: Dict[str, Any] = {}
    action_attributes: Dict[str, Any] = {}
    
    def get_attribute(self, attr_type: AttributeType, name: str, default: Any = None) -> Any:
        """Get attribute value by type and name"""
        if attr_type == AttributeType.USER:
            return self.user_attributes.get(name, default)
        elif attr_type == AttributeType.RESOURCE:
            return self.resource_attributes.get(name, default)
        elif attr_type == AttributeType.ENVIRONMENT:
            return self.environment_attributes.get(name, default)
        elif attr_type == AttributeType.ACTION:
            return self.action_attributes.get(name, default)
        return default
    
    def set_attribute(self, attr_type: AttributeType, name: str, value: Any) -> None:
        """Set attribute value by type and name"""
        if attr_type == AttributeType.USER:
            self.user_attributes[name] = value
        elif attr_type == AttributeType.RESOURCE:
            self.resource_attributes[name] = value
        elif attr_type == AttributeType.ENVIRONMENT:
            self.environment_attributes[name] = value
        elif attr_type == AttributeType.ACTION:
            self.action_attributes[name] = value


class PolicyCondition(BaseModel):
    """Individual condition in a policy rule"""
    attribute_type: AttributeType
    attribute_name: str
    operator: str  # eq, ne, gt, lt, gte, lte, in, not_in, contains, regex
    value: Any
    
    def evaluate(self, context: AttributeContext) -> bool:
        """Evaluate condition against context"""
        attr_value = context.get_attribute(self.attribute_type, self.attribute_name)
        
        if attr_value is None:
            return False
        
        try:
            if self.operator == "eq":
                return attr_value == self.value
            elif self.operator == "ne":
                return attr_value != self.value
            elif self.operator == "gt":
                return attr_value > self.value
            elif self.operator == "lt":
                return attr_value < self.value
            elif self.operator == "gte":
                return attr_value >= self.value
            elif self.operator == "lte":
                return attr_value <= self.value
            elif self.operator == "in":
                return attr_value in self.value
            elif self.operator == "not_in":
                return attr_value not in self.value
            elif self.operator == "contains":
                return self.value in str(attr_value)
            elif self.operator == "regex":
                import re
                return bool(re.match(self.value, str(attr_value)))
            else:
                logger.warning("Unknown operator", operator=self.operator)
                return False
                
        except Exception as e:
            logger.error("Condition evaluation failed", 
                        condition=self.model_dump(), error=str(e))
            return False


class PolicyRule(BaseModel):
    """ABAC policy rule"""
    id: str
    name: str
    description: str
    effect: PolicyEffect
    conditions: List[PolicyCondition]
    priority: int = 0
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    
    def evaluate(self, context: AttributeContext) -> Optional[PolicyEffect]:
        """Evaluate rule against context"""
        if not self.is_active:
            return None
        
        # All conditions must be true for rule to apply
        for condition in self.conditions:
            if not condition.evaluate(context):
                return None
        
        logger.debug("Policy rule matched", rule_id=self.id, effect=self.effect)
        return self.effect


class ABACManager:
    """Attribute-Based Access Control manager"""
    
    def __init__(self):
        self.rules: List[PolicyRule] = []
        self._initialize_default_rules()
    
    def _initialize_default_rules(self) -> None:
        """Initialize default ABAC rules"""
        
        # Business hours access rule
        business_hours_rule = PolicyRule(
            id="business_hours",
            name="Business Hours Access",
            description="Allow access during business hours",
            effect=PolicyEffect.ALLOW,
            conditions=[
                PolicyCondition(
                    attribute_type=AttributeType.ENVIRONMENT,
                    attribute_name="current_hour",
                    operator="gte",
                    value=9
                ),
                PolicyCondition(
                    attribute_type=AttributeType.ENVIRONMENT,
                    attribute_name="current_hour",
                    operator="lte",
                    value=17
                ),
                PolicyCondition(
                    attribute_type=AttributeType.ENVIRONMENT,
                    attribute_name="is_weekday",
                    operator="eq",
                    value=True
                )
            ],
            priority=10
        )
        
        # Emergency access rule
        emergency_rule = PolicyRule(
            id="emergency_access",
            name="Emergency Access",
            description="Allow emergency access regardless of time",
            effect=PolicyEffect.ALLOW,
            conditions=[
                PolicyCondition(
                    attribute_type=AttributeType.USER,
                    attribute_name="role",
                    operator="eq",
                    value="emergency"
                ),
                PolicyCondition(
                    attribute_type=AttributeType.ACTION,
                    attribute_name="type",
                    operator="eq",
                    value="emergency_access"
                )
            ],
            priority=100  # Higher priority
        )
        
        # Location-based access rule
        location_rule = PolicyRule(
            id="location_access",
            name="Location-Based Access",
            description="Restrict access based on location",
            effect=PolicyEffect.DENY,
            conditions=[
                PolicyCondition(
                    attribute_type=AttributeType.ENVIRONMENT,
                    attribute_name="location_country",
                    operator="not_in",
                    value=["US", "CA", "GB", "AU"]  # Allowed countries
                ),
                PolicyCondition(
                    attribute_type=AttributeType.RESOURCE,
                    attribute_name="sensitivity",
                    operator="eq",
                    value="high"
                )
            ],
            priority=50
        )
        
        # Data sensitivity rule
        sensitivity_rule = PolicyRule(
            id="data_sensitivity",
            name="Data Sensitivity Access",
            description="Restrict access to sensitive data",
            effect=PolicyEffect.DENY,
            conditions=[
                PolicyCondition(
                    attribute_type=AttributeType.RESOURCE,
                    attribute_name="data_type",
                    operator="in",
                    value=["health", "financial", "biometric"]
                ),
                PolicyCondition(
                    attribute_type=AttributeType.USER,
                    attribute_name="clearance_level",
                    operator="lt",
                    value=3
                )
            ],
            priority=75
        )
        
        self.rules.extend([
            business_hours_rule,
            emergency_rule,
            location_rule,
            sensitivity_rule
        ])
    
    def add_rule(self, rule: PolicyRule) -> None:
        """Add policy rule"""
        self.rules.append(rule)
        # Sort by priority (higher priority first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info("Added ABAC rule", rule_id=rule.id, priority=rule.priority)
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove policy rule"""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                del self.rules[i]
                logger.info("Removed ABAC rule", rule_id=rule_id)
                return True
        return False
    
    def evaluate_access(self, context: AttributeContext) -> PolicyEffect:
        """Evaluate access request against all rules"""
        
        # Add environment attributes automatically
        now = datetime.utcnow()
        context.set_attribute(AttributeType.ENVIRONMENT, "current_hour", now.hour)
        context.set_attribute(AttributeType.ENVIRONMENT, "current_day", now.weekday())
        context.set_attribute(AttributeType.ENVIRONMENT, "is_weekday", now.weekday() < 5)
        context.set_attribute(AttributeType.ENVIRONMENT, "timestamp", now.isoformat())
        
        # Evaluate rules in priority order
        for rule in self.rules:
            effect = rule.evaluate(context)
            if effect is not None:
                logger.info("ABAC decision", rule_id=rule.id, effect=effect,
                           user_id=context.user_attributes.get("user_id"))
                return effect
        
        # Default deny if no rules match
        logger.info("ABAC default deny - no rules matched",
                   user_id=context.user_attributes.get("user_id"))
        return PolicyEffect.DENY
    
    def check_access(self, user_id: str, resource_id: str, action: str,
                    user_attrs: Dict[str, Any] | None = None,
                    resource_attrs: Dict[str, Any] | None = None,
                    env_attrs: Dict[str, Any] | None = None) -> bool:
        """Convenience method to check access"""
        
        context = AttributeContext(
            user_attributes={"user_id": user_id, **(user_attrs or {})},
            resource_attributes={"resource_id": resource_id, **(resource_attrs or {})},
            environment_attributes=env_attrs or {},
            action_attributes={"type": action}
        )
        
        effect = self.evaluate_access(context)
        return effect == PolicyEffect.ALLOW
    
    def get_applicable_rules(self, context: AttributeContext) -> List[PolicyRule]:
        """Get all rules that would apply to context"""
        applicable = []
        
        for rule in self.rules:
            if rule.evaluate(context) is not None:
                applicable.append(rule)
        
        return applicable


# Predefined attribute extractors
class AttributeExtractor:
    """Extract attributes from various sources"""
    
    @staticmethod
    def extract_user_attributes(user_id: str, user_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Extract user attributes"""
        attrs = {"user_id": user_id}
        
        if user_data:
            user_attrs = {
                "role": user_data.get("role"),
                "department": user_data.get("department"),
                "clearance_level": user_data.get("clearance_level", 1),
                "location": user_data.get("location"),
                "last_login": user_data.get("last_login"),
            }
            attrs.update(user_attrs)
        
        return attrs
    
    @staticmethod
    def extract_resource_attributes(resource_id: str, resource_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Extract resource attributes"""
        attrs = {"resource_id": resource_id}
        
        if resource_data:
            resource_attrs = {
                "data_type": resource_data.get("data_type"),
                "sensitivity": resource_data.get("sensitivity", "low"),
                "owner_id": resource_data.get("owner_id"),
                "classification": resource_data.get("classification"),
                "created_at": resource_data.get("created_at"),
            }
            attrs.update(resource_attrs)
        
        return attrs
    
    @staticmethod
    def extract_environment_attributes(request_data: Dict[str, Any] | None = None) -> Dict[str, Any]:
        """Extract environment attributes"""
        attrs = {}
        
        if request_data:
            attrs.update({
                "ip_address": request_data.get("ip_address"),
                "user_agent": request_data.get("user_agent"),
                "location_country": request_data.get("location_country"),
                "is_vpn": request_data.get("is_vpn", False),
                "risk_score": request_data.get("risk_score", 0),
            })
        
        return attrs


# Global ABAC manager instance
_abac_manager: Optional[ABACManager] = None


def get_abac_manager() -> ABACManager:
    """Get the global ABAC manager instance"""
    global _abac_manager
    if _abac_manager is None:
        _abac_manager = ABACManager()
    return _abac_manager


def check_abac_access(user_id: str, resource_id: str, action: str,
                     user_attrs: Dict[str, Any] | None = None,
                     resource_attrs: Dict[str, Any] | None = None,
                     env_attrs: Dict[str, Any] | None = None) -> bool:
    """Check ABAC access"""
    return get_abac_manager().check_access(
        user_id, resource_id, action, user_attrs, resource_attrs, env_attrs
    )
