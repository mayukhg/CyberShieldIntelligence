"""
Rule engine for cybersecurity policy enforcement and threat detection
Implements configurable security rules and automated decision making
"""

import re
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, asdict
from enum import Enum
import pandas as pd
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RuleSeverity(Enum):
    """Rule severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class RuleAction(Enum):
    """Available rule actions"""
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    LOG = "log"
    NOTIFY = "notify"
    ESCALATE = "escalate"

@dataclass
class SecurityRule:
    """Security rule definition"""
    id: str
    name: str
    description: str
    category: str
    severity: RuleSeverity
    conditions: List[Dict[str, Any]]
    actions: List[RuleAction]
    enabled: bool = True
    created_at: datetime = None
    updated_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass
class RuleMatch:
    """Rule match result"""
    rule_id: str
    rule_name: str
    severity: RuleSeverity
    matched_conditions: List[str]
    actions_triggered: List[RuleAction]
    event_data: Dict[str, Any]
    timestamp: datetime
    confidence: float = 1.0

class RuleEngine:
    """Main rule engine for cybersecurity policy enforcement"""
    
    def __init__(self):
        self.rules: Dict[str, SecurityRule] = {}
        self.rule_matches: List[RuleMatch] = []
        self.operators = {
            'eq': lambda x, y: x == y,
            'ne': lambda x, y: x != y,
            'gt': lambda x, y: float(x) > float(y),
            'lt': lambda x, y: float(x) < float(y),
            'gte': lambda x, y: float(x) >= float(y),
            'lte': lambda x, y: float(x) <= float(y),
            'contains': lambda x, y: str(y).lower() in str(x).lower(),
            'not_contains': lambda x, y: str(y).lower() not in str(x).lower(),
            'regex': lambda x, y: bool(re.search(str(y), str(x), re.IGNORECASE)),
            'in': lambda x, y: x in y if isinstance(y, (list, tuple)) else str(x) in str(y),
            'not_in': lambda x, y: x not in y if isinstance(y, (list, tuple)) else str(x) not in str(y),
            'starts_with': lambda x, y: str(x).lower().startswith(str(y).lower()),
            'ends_with': lambda x, y: str(x).lower().endswith(str(y).lower())
        }
        
        # Load default rules
        self._load_default_rules()
    
    def add_rule(self, rule: SecurityRule) -> bool:
        """
        Add a new security rule
        
        Args:
            rule: SecurityRule object
            
        Returns:
            Success status
        """
        try:
            # Validate rule
            if not self._validate_rule(rule):
                return False
            
            self.rules[rule.id] = rule
            logger.info(f"Added security rule: {rule.id} - {rule.name}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding rule {rule.id}: {str(e)}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a security rule
        
        Args:
            rule_id: ID of rule to remove
            
        Returns:
            Success status
        """
        try:
            if rule_id in self.rules:
                del self.rules[rule_id]
                logger.info(f"Removed security rule: {rule_id}")
                return True
            else:
                logger.warning(f"Rule {rule_id} not found")
                return False
                
        except Exception as e:
            logger.error(f"Error removing rule {rule_id}: {str(e)}")
            return False
    
    def enable_rule(self, rule_id: str) -> bool:
        """Enable a security rule"""
        try:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = True
                self.rules[rule_id].updated_at = datetime.now()
                logger.info(f"Enabled rule: {rule_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error enabling rule {rule_id}: {str(e)}")
            return False
    
    def disable_rule(self, rule_id: str) -> bool:
        """Disable a security rule"""
        try:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = False
                self.rules[rule_id].updated_at = datetime.now()
                logger.info(f"Disabled rule: {rule_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error disabling rule {rule_id}: {str(e)}")
            return False
    
    def evaluate_event(self, event_data: Dict[str, Any]) -> List[RuleMatch]:
        """
        Evaluate an event against all active rules
        
        Args:
            event_data: Event data to evaluate
            
        Returns:
            List of rule matches
        """
        try:
            matches = []
            
            for rule_id, rule in self.rules.items():
                if not rule.enabled:
                    continue
                
                # Evaluate rule conditions
                matched_conditions = self._evaluate_rule_conditions(rule, event_data)
                
                if matched_conditions:
                    # Calculate confidence based on number of matched conditions
                    confidence = len(matched_conditions) / len(rule.conditions)
                    
                    match = RuleMatch(
                        rule_id=rule_id,
                        rule_name=rule.name,
                        severity=rule.severity,
                        matched_conditions=matched_conditions,
                        actions_triggered=rule.actions,
                        event_data=event_data.copy(),
                        timestamp=datetime.now(),
                        confidence=confidence
                    )
                    
                    matches.append(match)
                    self.rule_matches.append(match)
                    
                    logger.info(f"Rule matched: {rule.name} (confidence: {confidence:.2f})")
            
            return matches
            
        except Exception as e:
            logger.error(f"Error evaluating event: {str(e)}")
            return []
    
    def _evaluate_rule_conditions(self, rule: SecurityRule, event_data: Dict[str, Any]) -> List[str]:
        """
        Evaluate rule conditions against event data
        
        Args:
            rule: Security rule to evaluate
            event_data: Event data
            
        Returns:
            List of matched condition descriptions
        """
        try:
            matched_conditions = []
            
            for condition in rule.conditions:
                if self._evaluate_condition(condition, event_data):
                    condition_desc = f"{condition.get('field', 'unknown')} {condition.get('operator', 'unknown')} {condition.get('value', 'unknown')}"
                    matched_conditions.append(condition_desc)
            
            # Check if all conditions are met (AND logic) or any condition (OR logic)
            logic = rule.conditions[0].get('logic', 'AND') if rule.conditions else 'AND'
            
            if logic == 'AND' and len(matched_conditions) == len(rule.conditions):
                return matched_conditions
            elif logic == 'OR' and len(matched_conditions) > 0:
                return matched_conditions
            else:
                return []
                
        except Exception as e:
            logger.error(f"Error evaluating rule conditions for {rule.id}: {str(e)}")
            return []
    
    def _evaluate_condition(self, condition: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
        """
        Evaluate a single condition
        
        Args:
            condition: Condition to evaluate
            event_data: Event data
            
        Returns:
            True if condition matches
        """
        try:
            field = condition.get('field')
            operator = condition.get('operator')
            expected_value = condition.get('value')
            
            if not all([field, operator]):
                return False
            
            # Get actual value from event data (support nested fields with dot notation)
            actual_value = self._get_nested_value(event_data, field)
            
            if actual_value is None:
                return False
            
            # Apply operator
            if operator in self.operators:
                return self.operators[operator](actual_value, expected_value)
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
                
        except Exception as e:
            logger.error(f"Error evaluating condition: {str(e)}")
            return False
    
    def _get_nested_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """
        Get value from nested dictionary using dot notation
        
        Args:
            data: Dictionary to search
            field_path: Dot-separated field path
            
        Returns:
            Field value or None if not found
        """
        try:
            keys = field_path.split('.')
            value = data
            
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
            
            return value
            
        except Exception:
            return None
    
    def _validate_rule(self, rule: SecurityRule) -> bool:
        """
        Validate a security rule
        
        Args:
            rule: Rule to validate
            
        Returns:
            True if rule is valid
        """
        try:
            # Check required fields
            if not all([rule.id, rule.name, rule.category]):
                logger.error("Rule missing required fields")
                return False
            
            # Check conditions
            if not rule.conditions:
                logger.error("Rule must have at least one condition")
                return False
            
            # Validate condition format
            for condition in rule.conditions:
                if not all(key in condition for key in ['field', 'operator', 'value']):
                    logger.error("Invalid condition format")
                    return False
                
                if condition['operator'] not in self.operators:
                    logger.error(f"Unknown operator: {condition['operator']}")
                    return False
            
            # Check actions
            if not rule.actions:
                logger.error("Rule must have at least one action")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating rule: {str(e)}")
            return False
    
    def _load_default_rules(self):
        """Load default security rules"""
        try:
            default_rules = [
                # Failed login attempts
                SecurityRule(
                    id="failed_login_threshold",
                    name="Multiple Failed Login Attempts",
                    description="Detect multiple failed login attempts from same source",
                    category="authentication",
                    severity=RuleSeverity.HIGH,
                    conditions=[
                        {
                            'field': 'event_type',
                            'operator': 'contains',
                            'value': 'failed_login',
                            'logic': 'AND'
                        },
                        {
                            'field': 'attempt_count',
                            'operator': 'gte',
                            'value': 5
                        }
                    ],
                    actions=[RuleAction.ALERT, RuleAction.BLOCK]
                ),
                
                # Privilege escalation
                SecurityRule(
                    id="privilege_escalation",
                    name="Privilege Escalation Attempt",
                    description="Detect potential privilege escalation activities",
                    category="privilege_abuse",
                    severity=RuleSeverity.CRITICAL,
                    conditions=[
                        {
                            'field': 'command',
                            'operator': 'regex',
                            'value': r'(sudo|su|runas|psexec)',
                            'logic': 'OR'
                        },
                        {
                            'field': 'process_name',
                            'operator': 'in',
                            'value': ['cmd.exe', 'powershell.exe', 'bash', 'sh']
                        }
                    ],
                    actions=[RuleAction.ALERT, RuleAction.LOG]
                ),
                
                # Suspicious network activity
                SecurityRule(
                    id="suspicious_network_activity",
                    name="Suspicious Network Activity",
                    description="Detect unusual network connections",
                    category="network",
                    severity=RuleSeverity.MEDIUM,
                    conditions=[
                        {
                            'field': 'destination_port',
                            'operator': 'in',
                            'value': [4444, 5555, 6666, 7777, 8888, 9999],
                            'logic': 'OR'
                        },
                        {
                            'field': 'bytes_transferred',
                            'operator': 'gt',
                            'value': 1000000  # 1MB
                        }
                    ],
                    actions=[RuleAction.ALERT, RuleAction.LOG]
                ),
                
                # Malware indicators
                SecurityRule(
                    id="malware_indicators",
                    name="Malware Indicators Detected",
                    description="Detect known malware indicators",
                    category="malware",
                    severity=RuleSeverity.CRITICAL,
                    conditions=[
                        {
                            'field': 'file_hash',
                            'operator': 'in',
                            'value': [
                                '5d41402abc4b2a76b9719d911017c592',  # Example MD5
                                'e3b0c44298fc1c149afbf4c8996fb924'   # Example SHA256
                            ],
                            'logic': 'OR'
                        },
                        {
                            'field': 'file_name',
                            'operator': 'regex',
                            'value': r'(\.exe|\.bat|\.scr|\.pif)$'
                        }
                    ],
                    actions=[RuleAction.ALERT, RuleAction.QUARANTINE, RuleAction.BLOCK]
                ),
                
                # Data exfiltration
                SecurityRule(
                    id="data_exfiltration",
                    name="Potential Data Exfiltration",
                    description="Detect potential data exfiltration attempts",
                    category="data_loss",
                    severity=RuleSeverity.HIGH,
                    conditions=[
                        {
                            'field': 'outbound_bytes',
                            'operator': 'gt',
                            'value': 10000000,  # 10MB
                            'logic': 'AND'
                        },
                        {
                            'field': 'is_business_hours',
                            'operator': 'eq',
                            'value': False
                        }
                    ],
                    actions=[RuleAction.ALERT, RuleAction.BLOCK, RuleAction.ESCALATE]
                ),
                
                # Brute force attack
                SecurityRule(
                    id="brute_force_attack",
                    name="Brute Force Attack Detection",
                    description="Detect brute force login attempts",
                    category="authentication",
                    severity=RuleSeverity.HIGH,
                    conditions=[
                        {
                            'field': 'failed_login_count',
                            'operator': 'gte',
                            'value': 10,
                            'logic': 'AND'
                        },
                        {
                            'field': 'time_window',
                            'operator': 'lte',
                            'value': 300  # 5 minutes
                        }
                    ],
                    actions=[RuleAction.ALERT, RuleAction.BLOCK, RuleAction.NOTIFY]
                )
            ]
            
            for rule in default_rules:
                self.add_rule(rule)
            
            logger.info(f"Loaded {len(default_rules)} default security rules")
            
        except Exception as e:
            logger.error(f"Error loading default rules: {str(e)}")
    
    def get_rule_statistics(self) -> Dict[str, Any]:
        """
        Get rule engine statistics
        
        Returns:
            Dictionary containing rule statistics
        """
        try:
            total_rules = len(self.rules)
            enabled_rules = sum(1 for rule in self.rules.values() if rule.enabled)
            
            # Count by severity
            severity_counts = {}
            for severity in RuleSeverity:
                severity_counts[severity.name] = sum(
                    1 for rule in self.rules.values() 
                    if rule.severity == severity and rule.enabled
                )
            
            # Count by category
            category_counts = {}
            for rule in self.rules.values():
                if rule.enabled:
                    category_counts[rule.category] = category_counts.get(rule.category, 0) + 1
            
            # Recent matches
            recent_matches = [
                match for match in self.rule_matches 
                if match.timestamp > datetime.now() - timedelta(hours=24)
            ]
            
            # Match statistics by severity
            match_severity_counts = {}
            for severity in RuleSeverity:
                match_severity_counts[severity.name] = sum(
                    1 for match in recent_matches if match.severity == severity
                )
            
            return {
                'total_rules': total_rules,
                'enabled_rules': enabled_rules,
                'disabled_rules': total_rules - enabled_rules,
                'severity_distribution': severity_counts,
                'category_distribution': category_counts,
                'matches_last_24h': len(recent_matches),
                'match_severity_distribution': match_severity_counts,
                'average_confidence': np.mean([match.confidence for match in recent_matches]) if recent_matches else 0
            }
            
        except Exception as e:
            logger.error(f"Error getting rule statistics: {str(e)}")
            return {}
    
    def export_rules(self, file_path: str) -> bool:
        """
        Export rules to JSON file
        
        Args:
            file_path: Path to export file
            
        Returns:
            Success status
        """
        try:
            rules_data = {}
            for rule_id, rule in self.rules.items():
                rule_dict = asdict(rule)
                # Convert enum values to strings
                rule_dict['severity'] = rule.severity.name
                rule_dict['actions'] = [action.value for action in rule.actions]
                # Convert datetime to string
                rule_dict['created_at'] = rule.created_at.isoformat()
                rule_dict['updated_at'] = rule.updated_at.isoformat()
                rules_data[rule_id] = rule_dict
            
            with open(file_path, 'w') as f:
                json.dump(rules_data, f, indent=2)
            
            logger.info(f"Exported {len(rules_data)} rules to {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting rules: {str(e)}")
            return False
    
    def import_rules(self, file_path: str) -> bool:
        """
        Import rules from JSON file
        
        Args:
            file_path: Path to import file
            
        Returns:
            Success status
        """
        try:
            with open(file_path, 'r') as f:
                rules_data = json.load(f)
            
            imported_count = 0
            for rule_id, rule_dict in rules_data.items():
                try:
                    # Convert string values back to enums
                    rule_dict['severity'] = RuleSeverity[rule_dict['severity']]
                    rule_dict['actions'] = [RuleAction(action) for action in rule_dict['actions']]
                    # Convert string back to datetime
                    rule_dict['created_at'] = datetime.fromisoformat(rule_dict['created_at'])
                    rule_dict['updated_at'] = datetime.fromisoformat(rule_dict['updated_at'])
                    
                    rule = SecurityRule(**rule_dict)
                    if self.add_rule(rule):
                        imported_count += 1
                        
                except Exception as e:
                    logger.warning(f"Failed to import rule {rule_id}: {str(e)}")
            
            logger.info(f"Imported {imported_count} rules from {file_path}")
            return imported_count > 0
            
        except Exception as e:
            logger.error(f"Error importing rules: {str(e)}")
            return False

def create_custom_rule(name: str, description: str, category: str, 
                      severity: str, conditions: List[Dict], actions: List[str]) -> SecurityRule:
    """
    Helper function to create custom security rules
    
    Args:
        name: Rule name
        description: Rule description
        category: Rule category
        severity: Rule severity (LOW, MEDIUM, HIGH, CRITICAL)
        conditions: List of condition dictionaries
        actions: List of action strings
        
    Returns:
        SecurityRule object
    """
    try:
        rule_id = f"custom_{name.lower().replace(' ', '_')}_{int(datetime.now().timestamp())}"
        
        rule = SecurityRule(
            id=rule_id,
            name=name,
            description=description,
            category=category,
            severity=RuleSeverity[severity.upper()],
            conditions=conditions,
            actions=[RuleAction(action) for action in actions]
        )
        
        return rule
        
    except Exception as e:
        logger.error(f"Error creating custom rule: {str(e)}")
        raise

def evaluate_bulk_events(events: List[Dict[str, Any]], rule_engine: RuleEngine = None) -> Dict[str, Any]:
    """
    Evaluate multiple events against security rules
    
    Args:
        events: List of event dictionaries
        rule_engine: Optional rule engine instance
        
    Returns:
        Bulk evaluation results
    """
    try:
        if rule_engine is None:
            rule_engine = RuleEngine()
        
        all_matches = []
        event_count = len(events)
        
        for event in events:
            matches = rule_engine.evaluate_event(event)
            all_matches.extend(matches)
        
        # Aggregate results
        results = {
            'total_events': event_count,
            'total_matches': len(all_matches),
            'match_rate': (len(all_matches) / event_count * 100) if event_count > 0 else 0,
            'matches_by_severity': {},
            'matches_by_rule': {},
            'unique_rules_triggered': len(set(match.rule_id for match in all_matches))
        }
        
        # Count by severity
        for severity in RuleSeverity:
            results['matches_by_severity'][severity.name] = sum(
                1 for match in all_matches if match.severity == severity
            )
        
        # Count by rule
        for match in all_matches:
            results['matches_by_rule'][match.rule_name] = results['matches_by_rule'].get(match.rule_name, 0) + 1
        
        return results
        
    except Exception as e:
        logger.error(f"Error in bulk event evaluation: {str(e)}")
        return {'error': str(e)}
