"""
K-anonymity and quasi-identifier analysis for LUKi
Privacy protection through data generalization and suppression
"""

from typing import List, Dict, Any, Set, Tuple, Optional
from collections import defaultdict, Counter
import pandas as pd
import structlog

logger = structlog.get_logger(__name__)


class QuasiIdentifier:
    """Quasi-identifier field definition"""
    
    def __init__(self, field_name: str, field_type: str = "categorical", 
                 hierarchy: Dict[str, str] = None):
        self.field_name = field_name
        self.field_type = field_type  # categorical, numeric, date
        self.hierarchy = hierarchy or {}  # Generalization hierarchy
    
    def generalize_value(self, value: Any, level: int = 1) -> Any:
        """Generalize value based on hierarchy level"""
        if self.field_type == "categorical" and self.hierarchy:
            current = str(value)
            for _ in range(level):
                if current in self.hierarchy:
                    current = self.hierarchy[current]
                else:
                    break
            return current
        
        elif self.field_type == "numeric":
            # Numeric generalization by rounding
            if isinstance(value, (int, float)):
                factor = 10 ** level
                return round(value / factor) * factor
        
        elif self.field_type == "date":
            # Date generalization (year only, decade, etc.)
            if hasattr(value, 'year'):
                if level == 1:
                    return f"{value.year}"
                elif level == 2:
                    decade = (value.year // 10) * 10
                    return f"{decade}s"
                elif level >= 3:
                    return "Historical"
        
        return value


class KAnonymizer:
    """K-anonymity analyzer and enforcer"""
    
    def __init__(self, k: int = 3):
        self.k = k
        self.quasi_identifiers: Dict[str, QuasiIdentifier] = {}
        self._setup_default_hierarchies()
    
    def _setup_default_hierarchies(self) -> None:
        """Setup default generalization hierarchies"""
        
        # Age hierarchy
        age_hierarchy = {}
        for age in range(0, 120):
            if age < 18:
                age_hierarchy[str(age)] = "Minor"
            elif age < 30:
                age_hierarchy[str(age)] = "Young Adult"
            elif age < 50:
                age_hierarchy[str(age)] = "Adult"
            elif age < 65:
                age_hierarchy[str(age)] = "Middle Age"
            else:
                age_hierarchy[str(age)] = "Senior"
        
        # Further generalization
        age_hierarchy.update({
            "Minor": "Under 30",
            "Young Adult": "Under 30",
            "Adult": "30-65",
            "Middle Age": "30-65",
            "Senior": "Over 65"
        })
        
        # Location hierarchy (example)
        location_hierarchy = {
            # Cities to states
            "New York": "NY",
            "Los Angeles": "CA",
            "Chicago": "IL",
            "Houston": "TX",
            # States to regions
            "NY": "Northeast",
            "CA": "West",
            "IL": "Midwest",
            "TX": "South",
            # Regions to country
            "Northeast": "USA",
            "West": "USA",
            "Midwest": "USA",
            "South": "USA"
        }
        
        # Education hierarchy
        education_hierarchy = {
            "High School": "Secondary",
            "Some College": "Secondary",
            "Bachelor's": "Higher Education",
            "Master's": "Higher Education",
            "PhD": "Higher Education",
            "Secondary": "Educated",
            "Higher Education": "Educated"
        }
        
        # Default quasi-identifiers
        self.quasi_identifiers = {
            "age": QuasiIdentifier("age", "numeric"),
            "location": QuasiIdentifier("location", "categorical", location_hierarchy),
            "education": QuasiIdentifier("education", "categorical", education_hierarchy),
            "occupation": QuasiIdentifier("occupation", "categorical"),
            "income": QuasiIdentifier("income", "numeric")
        }
    
    def add_quasi_identifier(self, qi: QuasiIdentifier) -> None:
        """Add quasi-identifier definition"""
        self.quasi_identifiers[qi.field_name] = qi
        logger.info("Added quasi-identifier", field=qi.field_name, type=qi.field_type)
    
    def check_k_anonymity(self, data: List[Dict[str, Any]], 
                         qi_fields: List[str] = None) -> Dict[str, Any]:
        """
        Check k-anonymity of dataset
        
        Returns:
            Analysis results including violations and statistics
        """
        if qi_fields is None:
            qi_fields = list(self.quasi_identifiers.keys())
        
        # Filter to only include records with all QI fields
        filtered_data = []
        for record in data:
            if all(field in record for field in qi_fields):
                filtered_data.append(record)
        
        if not filtered_data:
            return {
                "k_anonymous": True,
                "min_group_size": 0,
                "violations": [],
                "total_records": 0,
                "qi_fields": qi_fields
            }
        
        # Group records by quasi-identifier combinations
        groups = defaultdict(list)
        
        for i, record in enumerate(filtered_data):
            qi_tuple = tuple(str(record.get(field, "")) for field in qi_fields)
            groups[qi_tuple].append(i)
        
        # Analyze groups
        group_sizes = [len(group) for group in groups.values()]
        min_group_size = min(group_sizes) if group_sizes else 0
        violations = []
        
        for qi_combo, record_indices in groups.items():
            if len(record_indices) < self.k:
                violations.append({
                    "qi_combination": dict(zip(qi_fields, qi_combo)),
                    "group_size": len(record_indices),
                    "record_indices": record_indices
                })
        
        result = {
            "k_anonymous": len(violations) == 0,
            "k_value": self.k,
            "min_group_size": min_group_size,
            "max_group_size": max(group_sizes) if group_sizes else 0,
            "avg_group_size": sum(group_sizes) / len(group_sizes) if group_sizes else 0,
            "total_groups": len(groups),
            "violations": violations,
            "violation_count": len(violations),
            "total_records": len(filtered_data),
            "qi_fields": qi_fields
        }
        
        logger.info("K-anonymity check completed", 
                   k_anonymous=result["k_anonymous"],
                   violations=len(violations),
                   min_group_size=min_group_size)
        
        return result
    
    def enforce_k_anonymity(self, data: List[Dict[str, Any]], 
                           qi_fields: List[str] = None,
                           max_generalization_level: int = 3) -> List[Dict[str, Any]]:
        """
        Enforce k-anonymity through generalization and suppression
        
        Returns:
            K-anonymous dataset
        """
        if qi_fields is None:
            qi_fields = list(self.quasi_identifiers.keys())
        
        working_data = [record.copy() for record in data]
        
        # Try increasing levels of generalization
        for level in range(1, max_generalization_level + 1):
            # Apply generalization at current level
            generalized_data = []
            for record in working_data:
                generalized_record = record.copy()
                
                for field in qi_fields:
                    if field in self.quasi_identifiers and field in record:
                        qi = self.quasi_identifiers[field]
                        generalized_record[field] = qi.generalize_value(record[field], level)
                
                generalized_data.append(generalized_record)
            
            # Check if k-anonymous
            analysis = self.check_k_anonymity(generalized_data, qi_fields)
            
            if analysis["k_anonymous"]:
                logger.info("K-anonymity achieved", 
                           generalization_level=level,
                           total_records=len(generalized_data))
                return generalized_data
            
            working_data = generalized_data
        
        # If generalization didn't work, apply suppression
        logger.warning("Generalization insufficient, applying suppression")
        return self._apply_suppression(working_data, qi_fields)
    
    def _apply_suppression(self, data: List[Dict[str, Any]], 
                          qi_fields: List[str]) -> List[Dict[str, Any]]:
        """Apply record suppression to achieve k-anonymity"""
        
        # Group records and suppress small groups
        groups = defaultdict(list)
        
        for i, record in enumerate(data):
            qi_tuple = tuple(str(record.get(field, "")) for field in qi_fields)
            groups[qi_tuple].append((i, record))
        
        suppressed_data = []
        suppressed_count = 0
        
        for qi_combo, group_records in groups.items():
            if len(group_records) >= self.k:
                # Keep this group
                suppressed_data.extend([record for _, record in group_records])
            else:
                # Suppress this group
                suppressed_count += len(group_records)
        
        logger.warning("Applied record suppression", 
                      suppressed_records=suppressed_count,
                      remaining_records=len(suppressed_data))
        
        return suppressed_data
    
    def analyze_qi_distribution(self, data: List[Dict[str, Any]], 
                               field: str) -> Dict[str, Any]:
        """Analyze distribution of quasi-identifier values"""
        
        if field not in self.quasi_identifiers:
            return {"error": f"Field {field} not defined as quasi-identifier"}
        
        values = [record.get(field) for record in data if field in record]
        value_counts = Counter(values)
        
        return {
            "field": field,
            "total_values": len(values),
            "unique_values": len(value_counts),
            "most_common": value_counts.most_common(10),
            "singleton_count": sum(1 for count in value_counts.values() if count == 1),
            "distribution": dict(value_counts)
        }
    
    def suggest_generalization(self, data: List[Dict[str, Any]], 
                              qi_fields: List[str] = None) -> Dict[str, Any]:
        """Suggest generalization strategy to achieve k-anonymity"""
        
        if qi_fields is None:
            qi_fields = list(self.quasi_identifiers.keys())
        
        analysis = self.check_k_anonymity(data, qi_fields)
        
        if analysis["k_anonymous"]:
            return {"status": "already_k_anonymous", "analysis": analysis}
        
        suggestions = []
        
        # Analyze each QI field
        for field in qi_fields:
            if field in self.quasi_identifiers:
                distribution = self.analyze_qi_distribution(data, field)
                
                # Calculate how much generalization might help
                singleton_ratio = distribution["singleton_count"] / distribution["total_values"]
                
                suggestions.append({
                    "field": field,
                    "singleton_ratio": singleton_ratio,
                    "unique_values": distribution["unique_values"],
                    "recommendation": "high_priority" if singleton_ratio > 0.5 else "medium_priority"
                })
        
        # Sort by priority
        suggestions.sort(key=lambda x: x["singleton_ratio"], reverse=True)
        
        return {
            "status": "needs_generalization",
            "current_analysis": analysis,
            "field_suggestions": suggestions,
            "recommended_approach": "generalize_high_priority_fields_first"
        }


def check_k_anonymity(data: List[Dict[str, Any]], k: int = 3, 
                     qi_fields: List[str] = None) -> bool:
    """Convenience function to check k-anonymity"""
    anonymizer = KAnonymizer(k)
    analysis = anonymizer.check_k_anonymity(data, qi_fields)
    return analysis["k_anonymous"]


def enforce_k_anonymity(data: List[Dict[str, Any]], k: int = 3,
                       qi_fields: List[str] = None) -> List[Dict[str, Any]]:
    """Convenience function to enforce k-anonymity"""
    anonymizer = KAnonymizer(k)
    return anonymizer.enforce_k_anonymity(data, qi_fields)


class LDiversityAnalyzer:
    """L-diversity analyzer for sensitive attributes"""
    
    def __init__(self, l: int = 2):
        self.l = l
    
    def check_l_diversity(self, data: List[Dict[str, Any]], 
                         qi_fields: List[str], sensitive_field: str) -> Dict[str, Any]:
        """Check l-diversity for sensitive attribute"""
        
        # Group by quasi-identifiers
        groups = defaultdict(list)
        
        for record in data:
            if all(field in record for field in qi_fields) and sensitive_field in record:
                qi_tuple = tuple(str(record.get(field, "")) for field in qi_fields)
                groups[qi_tuple].append(record[sensitive_field])
        
        violations = []
        
        for qi_combo, sensitive_values in groups.items():
            unique_sensitive = len(set(sensitive_values))
            
            if unique_sensitive < self.l:
                violations.append({
                    "qi_combination": dict(zip(qi_fields, qi_combo)),
                    "group_size": len(sensitive_values),
                    "unique_sensitive_values": unique_sensitive,
                    "sensitive_values": list(set(sensitive_values))
                })
        
        return {
            "l_diverse": len(violations) == 0,
            "l_value": self.l,
            "violations": violations,
            "violation_count": len(violations),
            "total_groups": len(groups),
            "sensitive_field": sensitive_field
        }


class TClosenessAnalyzer:
    """T-closeness analyzer for distribution similarity"""
    
    def __init__(self, t: float = 0.2):
        self.t = t
    
    def calculate_earth_movers_distance(self, dist1: Dict[str, float], 
                                       dist2: Dict[str, float]) -> float:
        """Calculate Earth Mover's Distance between distributions"""
        # Simplified EMD calculation
        all_values = set(dist1.keys()) | set(dist2.keys())
        
        cumulative_diff = 0.0
        cumulative_sum = 0.0
        
        for value in sorted(all_values):
            prob1 = dist1.get(value, 0.0)
            prob2 = dist2.get(value, 0.0)
            
            cumulative_sum += prob1 - prob2
            cumulative_diff += abs(cumulative_sum)
        
        return cumulative_diff
    
    def check_t_closeness(self, data: List[Dict[str, Any]], 
                         qi_fields: List[str], sensitive_field: str) -> Dict[str, Any]:
        """Check t-closeness for sensitive attribute"""
        
        # Calculate global distribution
        all_sensitive_values = [record[sensitive_field] for record in data 
                               if sensitive_field in record]
        
        global_counts = Counter(all_sensitive_values)
        total_count = len(all_sensitive_values)
        global_dist = {value: count / total_count 
                      for value, count in global_counts.items()}
        
        # Group by quasi-identifiers
        groups = defaultdict(list)
        
        for record in data:
            if all(field in record for field in qi_fields) and sensitive_field in record:
                qi_tuple = tuple(str(record.get(field, "")) for field in qi_fields)
                groups[qi_tuple].append(record[sensitive_field])
        
        violations = []
        
        for qi_combo, sensitive_values in groups.items():
            group_counts = Counter(sensitive_values)
            group_total = len(sensitive_values)
            group_dist = {value: count / group_total 
                         for value, count in group_counts.items()}
            
            # Calculate distance from global distribution
            distance = self.calculate_earth_movers_distance(group_dist, global_dist)
            
            if distance > self.t:
                violations.append({
                    "qi_combination": dict(zip(qi_fields, qi_combo)),
                    "group_size": len(sensitive_values),
                    "distance": distance,
                    "threshold": self.t,
                    "group_distribution": group_dist
                })
        
        return {
            "t_close": len(violations) == 0,
            "t_value": self.t,
            "violations": violations,
            "violation_count": len(violations),
            "total_groups": len(groups),
            "global_distribution": global_dist,
            "sensitive_field": sensitive_field
        }
