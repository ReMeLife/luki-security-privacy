"""
Differential Privacy mechanisms for LUKi
Noise addition, clipping, and privacy budget management
"""

import numpy as np
from typing import Union, List, Optional
from enum import Enum
import structlog

from ..config import get_security_config

logger = structlog.get_logger(__name__)


class NoiseType(str, Enum):
    """Types of differential privacy noise"""
    LAPLACE = "laplace"
    GAUSSIAN = "gaussian"


def laplace_noise(scale: float, size: Union[int, tuple] = None) -> Union[float, np.ndarray]:
    """
    Generate Laplace noise for differential privacy
    
    Args:
        scale: Scale parameter (sensitivity / epsilon)
        size: Shape of output array
        
    Returns:
        Noise value(s)
    """
    return np.random.laplace(0, scale, size)


def gaussian_noise(scale: float, size: Union[int, tuple] = None) -> Union[float, np.ndarray]:
    """
    Generate Gaussian noise for differential privacy
    
    Args:
        scale: Standard deviation (sensitivity * sqrt(2 * ln(1.25/delta)) / epsilon)
        size: Shape of output array
        
    Returns:
        Noise value(s)
    """
    return np.random.normal(0, scale, size)


def clip_values(values: np.ndarray, clip_bound: float) -> np.ndarray:
    """
    Clip values to bound for differential privacy
    
    Args:
        values: Input values
        clip_bound: Clipping bound
        
    Returns:
        Clipped values
    """
    return np.clip(values, -clip_bound, clip_bound)


class DPMechanism:
    """Differential Privacy mechanism with budget tracking"""
    
    def __init__(self, epsilon: float, delta: float = 1e-5, sensitivity: float = 1.0):
        self.epsilon = epsilon
        self.delta = delta
        self.sensitivity = sensitivity
        self.budget_used = 0.0
        self.query_count = 0
        
        config = get_security_config()
        self.noise_type = NoiseType(config.dp_mechanism)
    
    def _check_budget(self, epsilon_cost: float) -> bool:
        """Check if privacy budget allows this query"""
        return (self.budget_used + epsilon_cost) <= self.epsilon
    
    def _consume_budget(self, epsilon_cost: float) -> None:
        """Consume privacy budget"""
        self.budget_used += epsilon_cost
        self.query_count += 1
        
        logger.debug("Privacy budget consumed", 
                    cost=epsilon_cost, 
                    used=self.budget_used, 
                    remaining=self.epsilon - self.budget_used)
    
    def add_noise(self, value: Union[float, np.ndarray], 
                  epsilon_cost: Optional[float] = None) -> Union[float, np.ndarray]:
        """
        Add differential privacy noise to value
        
        Args:
            value: True value to protect
            epsilon_cost: Privacy budget cost (uses remaining budget if None)
            
        Returns:
            Noisy value
        """
        if epsilon_cost is None:
            epsilon_cost = self.epsilon - self.budget_used
        
        if not self._check_budget(epsilon_cost):
            raise ValueError(f"Insufficient privacy budget. Requested: {epsilon_cost}, Available: {self.epsilon - self.budget_used}")
        
        if self.noise_type == NoiseType.LAPLACE:
            scale = self.sensitivity / epsilon_cost
            noise = laplace_noise(scale, np.shape(value) if hasattr(value, 'shape') else None)
        else:  # Gaussian
            scale = self.sensitivity * np.sqrt(2 * np.log(1.25 / self.delta)) / epsilon_cost
            noise = gaussian_noise(scale, np.shape(value) if hasattr(value, 'shape') else None)
        
        self._consume_budget(epsilon_cost)
        
        noisy_value = value + noise
        
        logger.info("Added DP noise", 
                   noise_type=self.noise_type,
                   epsilon_cost=epsilon_cost,
                   scale=scale if self.noise_type == NoiseType.LAPLACE else scale)
        
        return noisy_value
    
    def noisy_count(self, count: int, epsilon_cost: Optional[float] = None) -> float:
        """Add noise to count query"""
        return self.add_noise(float(count), epsilon_cost)
    
    def noisy_sum(self, values: List[float], clip_bound: Optional[float] = None,
                  epsilon_cost: Optional[float] = None) -> float:
        """Add noise to sum query with optional clipping"""
        if clip_bound:
            values = clip_values(np.array(values), clip_bound)
        
        return self.add_noise(np.sum(values), epsilon_cost)
    
    def noisy_mean(self, values: List[float], clip_bound: Optional[float] = None,
                   epsilon_cost: Optional[float] = None) -> float:
        """Add noise to mean query with optional clipping"""
        if clip_bound:
            values = clip_values(np.array(values), clip_bound)
        
        # For mean, we need to split budget between count and sum
        if epsilon_cost is None:
            epsilon_cost = (self.epsilon - self.budget_used) / 2
        else:
            epsilon_cost = epsilon_cost / 2
        
        noisy_sum = self.add_noise(np.sum(values), epsilon_cost)
        noisy_count = self.add_noise(len(values), epsilon_cost)
        
        return noisy_sum / noisy_count if noisy_count != 0 else 0.0
    
    def get_budget_status(self) -> dict:
        """Get privacy budget status"""
        return {
            "total_epsilon": self.epsilon,
            "used_epsilon": self.budget_used,
            "remaining_epsilon": self.epsilon - self.budget_used,
            "query_count": self.query_count,
            "delta": self.delta
        }
    
    def reset_budget(self) -> None:
        """Reset privacy budget (use with caution)"""
        logger.warning("Privacy budget reset", 
                      previous_used=self.budget_used,
                      previous_queries=self.query_count)
        self.budget_used = 0.0
        self.query_count = 0


class DPQueryEngine:
    """Differential privacy query engine for datasets"""
    
    def __init__(self, epsilon: float, delta: float = 1e-5):
        self.epsilon = epsilon
        self.delta = delta
        self.mechanisms: dict = {}
    
    def create_mechanism(self, name: str, sensitivity: float) -> DPMechanism:
        """Create a DP mechanism for specific query type"""
        mechanism = DPMechanism(self.epsilon, self.delta, sensitivity)
        self.mechanisms[name] = mechanism
        return mechanism
    
    def get_mechanism(self, name: str) -> Optional[DPMechanism]:
        """Get existing DP mechanism"""
        return self.mechanisms.get(name)
    
    def query_count(self, dataset: List[dict], filter_func: callable = None,
                   mechanism_name: str = "count") -> float:
        """Execute differentially private count query"""
        if mechanism_name not in self.mechanisms:
            self.create_mechanism(mechanism_name, sensitivity=1.0)
        
        mechanism = self.mechanisms[mechanism_name]
        
        if filter_func:
            count = sum(1 for item in dataset if filter_func(item))
        else:
            count = len(dataset)
        
        return mechanism.noisy_count(count)
    
    def query_histogram(self, dataset: List[dict], field: str, bins: List[str],
                       mechanism_name: str = "histogram") -> dict:
        """Execute differentially private histogram query"""
        if mechanism_name not in self.mechanisms:
            self.create_mechanism(mechanism_name, sensitivity=1.0)
        
        mechanism = self.mechanisms[mechanism_name]
        
        # Count items in each bin
        histogram = {}
        for bin_name in bins:
            count = sum(1 for item in dataset if item.get(field) == bin_name)
            histogram[bin_name] = mechanism.noisy_count(count, self.epsilon / len(bins))
        
        return histogram
    
    def get_total_budget_used(self) -> float:
        """Get total privacy budget used across all mechanisms"""
        return sum(m.budget_used for m in self.mechanisms.values())


class DPDataProcessor:
    """Process datasets with differential privacy"""
    
    def __init__(self, epsilon: float, delta: float = 1e-5):
        self.epsilon = epsilon
        self.delta = delta
    
    def sanitize_numeric_field(self, values: List[float], clip_bound: float) -> List[float]:
        """Sanitize numeric field with DP noise"""
        mechanism = DPMechanism(self.epsilon, self.delta, sensitivity=clip_bound)
        
        clipped_values = clip_values(np.array(values), clip_bound)
        noisy_values = []
        
        epsilon_per_value = self.epsilon / len(values)
        
        for value in clipped_values:
            noisy_value = mechanism.add_noise(value, epsilon_per_value)
            noisy_values.append(float(noisy_value))
        
        return noisy_values
    
    def sanitize_categorical_field(self, values: List[str], categories: List[str]) -> List[str]:
        """Sanitize categorical field with randomized response"""
        # Simple randomized response mechanism
        p = np.exp(self.epsilon) / (np.exp(self.epsilon) + len(categories) - 1)
        
        sanitized = []
        for value in values:
            if np.random.random() < p:
                # Keep true value
                sanitized.append(value)
            else:
                # Random response
                other_categories = [c for c in categories if c != value]
                sanitized.append(np.random.choice(other_categories))
        
        return sanitized


# Global DP configuration
def get_dp_mechanism(epsilon: Optional[float] = None, 
                    delta: Optional[float] = None,
                    sensitivity: Optional[float] = None) -> DPMechanism:
    """Get DP mechanism with default configuration"""
    config = get_security_config()
    
    return DPMechanism(
        epsilon=epsilon or config.dp_epsilon,
        delta=delta or config.dp_delta,
        sensitivity=sensitivity or config.dp_sensitivity
    )


def add_dp_noise(value: Union[float, np.ndarray], 
                epsilon: Optional[float] = None,
                sensitivity: Optional[float] = None) -> Union[float, np.ndarray]:
    """Convenience function to add DP noise"""
    mechanism = get_dp_mechanism(epsilon=epsilon, sensitivity=sensitivity)
    return mechanism.add_noise(value)
