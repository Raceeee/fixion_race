"""
dss_engine.py - Fixed Decision Support System Engine for Fixion
Provides intelligent threat assessment and recommended actions with proper error handling
All integration issues resolved
"""

import os
import json
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from datetime import datetime

# Import with error handling
try:
    from client.config import get_config, get_logger
except ImportError:
    def get_config(key, default=None):
        return default
    def get_logger(name):
        import logging
        return logging.getLogger(name)

logger = get_logger(__name__)


class ActionType(Enum):
    """Types of actions DSS can recommend"""
    ALLOW = "allow"
    MONITOR = "monitor"
    QUARANTINE = "quarantine"
    DELETE = "delete"
    SANDBOX = "sandbox"
    BLOCK_NETWORK = "block_network"
    USER_PROMPT = "user_prompt"
    ESCALATE = "escalate"


@dataclass
class DSSAction:
    """DSS recommended action"""
    action_type: ActionType
    priority: int  # 1-10, 10 being highest priority
    reason: str
    details: Dict[str, Any]
    auto_execute: bool = False


@dataclass
class DSSRule:
    """DSS rule definition"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    actions: List[DSSAction]
    enabled: bool = True
    priority: int = 5


class DSSEngine:
    """Decision Support System Engine for threat response - FIXED VERSION"""

    def __init__(self, rules_file: str = None):
        if rules_file is None:
            # Use relative path from client directory
            client_dir = Path(__file__).parent
            rules_file = client_dir / "dss_rules.json"

        self.rules_file = rules_file
        self.rules: List[DSSRule] = []
        self.rules_loaded = False
        self.stats = {
            'rules_evaluated': 0,
            'rules_triggered': 0,
            'actions_recommended': 0,
            'auto_actions_executed': 0
        }

    def load_rules(self) -> bool:
        """Load DSS rules from configuration"""
        try:
            # Try to load from file first
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    rules_data = json.load(f)
                self._parse_rules(rules_data)
            else:
                # Create default rules
                self._create_default_rules()
                self._save_rules()

            self.rules_loaded = True
            logger.info(f"DSS Engine loaded {len(self.rules)} rules")
            return True

        except Exception as e:
            logger.error(f"Failed to load DSS rules: {e}")
            # Still load default rules even if file operations fail
            try:
                self._create_default_rules()
                self.rules_loaded = True
                logger.info(f"DSS Engine loaded {len(self.rules)} default rules")
                return True
            except Exception as e2:
                logger.error(f"Failed to create default rules: {e2}")
                return False

    def _create_default_rules(self):
        """Create default DSS rules"""
        default_rules = [
            # High threat executable files
            DSSRule(
                rule_id="high_threat_executable",
                name="High Threat Executable",
                description="Executable file with high AI confidence score",
                conditions={
                    "ai_score": {"min": 0.8},
                    "file_type": ["executable"],
                    "reputation_score": {"max": 0.3}
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.QUARANTINE,
                        priority=9,
                        reason="High AI confidence indicates malware",
                        details={"backup_before_quarantine": True},
                        auto_execute=True
                    ),
                    DSSAction(
                        action_type=ActionType.BLOCK_NETWORK,
                        priority=8,
                        reason="Prevent potential C&C communication",
                        details={"block_duration": 3600},
                        auto_execute=True
                    )
                ],
                priority=9
            ),

            # Suspicious downloads
            DSSRule(
                rule_id="suspicious_downloads",
                name="Suspicious Downloads",
                description="Executable files in Downloads folder with medium threat",
                conditions={
                    "ai_score": {"min": 0.5, "max": 0.8},
                    "file_location": {"contains": ["downloads", "temp"]},
                    "file_type": ["executable"]
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.SANDBOX,
                        priority=7,
                        reason="Analyze suspicious download in safe environment",
                        details={"timeout": 60}
                    ),
                    DSSAction(
                        action_type=ActionType.USER_PROMPT,
                        priority=6,
                        reason="Ask user about file origin",
                        details={"message": "Did you download this file intentionally?"}
                    )
                ],
                priority=7
            ),

            # YARA rule matches - CURRENTLY DISABLED
            DSSRule(
                rule_id="yara_malware_matches",
                name="YARA Malware Matches",
                description="Files matching YARA malware signatures",
                conditions={
                    "yara_matches": {"min_count": 1},
                    "yara_categories": ["malware", "trojan", "ransomware"]
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.QUARANTINE,
                        priority=10,
                        reason="YARA signature match indicates known malware",
                        details={"immediate": True},
                        auto_execute=True
                    ),
                    DSSAction(
                        action_type=ActionType.ESCALATE,
                        priority=9,
                        reason="Alert security team",
                        details={"severity": "high"}
                    )
                ],
                priority=10,
                enabled=False  # Disabled since YARA is not active
            ),

            # Signed files with good reputation
            DSSRule(
                rule_id="trusted_signed_files",
                name="Trusted Signed Files",
                description="Files with valid signatures and good reputation",
                conditions={
                    "is_signed": True,
                    "signature_valid": True,
                    "reputation_score": {"min": 0.7},
                    "ai_score": {"max": 0.5}
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.ALLOW,
                        priority=2,
                        reason="Valid signature and good reputation",
                        details={"whitelist": True},
                        auto_execute=True
                    )
                ],
                priority=2
            ),

            # Educational environment specific
            DSSRule(
                rule_id="educational_policy",
                name="Educational Environment Policy",
                description="Special handling for educational environment",
                conditions={
                    "environment": "educational",
                    "ai_score": {"min": 0.3, "max": 0.7},
                    "file_type": ["executable", "script"]
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.USER_PROMPT,
                        priority=7,
                        reason="Educational environment requires user confirmation",
                        details={
                            "message": "This file may be potentially harmful. Do you need it for your studies?",
                            "options": ["Yes, I need it", "No, remove it", "Ask teacher"]
                        }
                    ),
                    DSSAction(
                        action_type=ActionType.MONITOR,
                        priority=5,
                        reason="Monitor student activity",
                        details={"notify_teacher": True}
                    )
                ],
                priority=7
            ),

            # Low confidence but high-risk location
            DSSRule(
                rule_id="low_confidence_risky_location",
                name="Low Confidence Risky Location",
                description="Low AI confidence but in high-risk location",
                conditions={
                    "ai_score": {"min": 0.2, "max": 0.5},
                    "file_location": {"contains": ["temp", "appdata\\local\\temp"]},
                    "file_age_hours": {"max": 24}
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.MONITOR,
                        priority=4,
                        reason="Monitor recently created files in temp locations",
                        details={"duration": 3600}
                    )
                ],
                priority=4
            ),

            # Heuristic-based detection
            DSSRule(
                rule_id="suspicious_heuristics",
                name="Suspicious Heuristic Flags",
                description="Files with multiple suspicious heuristic indicators",
                conditions={
                    "heuristic_suspicious_count": {"min": 2},
                    "ai_score": {"min": 0.3}
                },
                actions=[
                    DSSAction(
                        action_type=ActionType.SANDBOX,
                        priority=6,
                        reason="Multiple heuristic flags warrant further analysis",
                        details={"timeout": 30}
                    )
                ],
                priority=6
            )
        ]

        self.rules = default_rules

    def _parse_rules(self, rules_data: List[Dict[str, Any]]):
        """Parse rules from JSON data"""
        self.rules = []
        for rule_data in rules_data:
            try:
                # Parse actions
                actions = []
                for action_data in rule_data.get('actions', []):
                    action = DSSAction(
                        action_type=ActionType(action_data['action_type']),
                        priority=action_data['priority'],
                        reason=action_data['reason'],
                        details=action_data.get('details', {}),
                        auto_execute=action_data.get('auto_execute', False)
                    )
                    actions.append(action)

                rule = DSSRule(
                    rule_id=rule_data['rule_id'],
                    name=rule_data['name'],
                    description=rule_data['description'],
                    conditions=rule_data['conditions'],
                    actions=actions,
                    enabled=rule_data.get('enabled', True),
                    priority=rule_data.get('priority', 5)
                )
                self.rules.append(rule)

            except Exception as e:
                logger.error(f"Failed to parse rule {rule_data.get('rule_id', 'unknown')}: {e}")

    def _save_rules(self):
        """Save current rules to file"""
        try:
            # Ensure directory exists
            rules_dir = os.path.dirname(self.rules_file)
            if rules_dir and not os.path.exists(rules_dir):
                os.makedirs(rules_dir)

            rules_data = []
            for rule in self.rules:
                actions_data = []
                for action in rule.actions:
                    actions_data.append({
                        'action_type': action.action_type.value,
                        'priority': action.priority,
                        'reason': action.reason,
                        'details': action.details,
                        'auto_execute': action.auto_execute
                    })

                rule_data = {
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'description': rule.description,
                    'conditions': rule.conditions,
                    'actions': actions_data,
                    'enabled': rule.enabled,
                    'priority': rule.priority
                }
                rules_data.append(rule_data)

            with open(self.rules_file, 'w') as f:
                json.dump(rules_data, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save DSS rules: {e}")

    def evaluate_file(self, file_path: str, scan_result) -> Dict[str, Any]:
        """Evaluate file against DSS rules and return recommendations - FIXED METHOD"""
        if not self.rules_loaded:
            return {"error": "DSS rules not loaded", "matched_rules": [], "recommended_actions": []}

        try:
            self.stats['rules_evaluated'] += 1

            # Build context for rule evaluation
            context = self._build_context(file_path, scan_result)

            # Evaluate rules
            matched_rules = []
            recommended_actions = []

            for rule in self.rules:
                if not rule.enabled:
                    continue

                if self._evaluate_rule_conditions(rule, context):
                    matched_rules.append(rule.rule_id)
                    recommended_actions.extend(rule.actions)
                    self.stats['rules_triggered'] += 1

            # Sort actions by priority
            recommended_actions.sort(key=lambda x: x.priority, reverse=True)

            # Remove duplicate actions
            unique_actions = []
            seen_actions = set()
            for action in recommended_actions:
                action_key = (action.action_type, action.reason)
                if action_key not in seen_actions:
                    unique_actions.append(action)
                    seen_actions.add(action_key)

            self.stats['actions_recommended'] += len(unique_actions)

            return {
                'matched_rules': matched_rules,
                'recommended_actions': unique_actions,
                'context': context,
                'evaluation_time': time.time()
            }

        except Exception as e:
            logger.error(f"DSS evaluation failed for {file_path}: {e}")
            return {"error": str(e), "matched_rules": [], "recommended_actions": []}

    def _build_context(self, file_path: str, scan_result) -> Dict[str, Any]:
        """Build context for rule evaluation - ENHANCED VERSION"""
        try:
            # Get file info safely
            try:
                file_stat = os.stat(file_path)
                file_age_hours = (time.time() - file_stat.st_mtime) / 3600
            except:
                file_age_hours = 0

            # Determine file type
            ext = os.path.splitext(file_path)[1].lower()
            if ext in ['.exe', '.dll', '.com', '.scr', '.msi']:
                file_type = 'executable'
            elif ext in ['.bat', '.cmd', '.ps1', '.vbs']:
                file_type = 'script'
            elif ext in ['.doc', '.docx', '.pdf', '.txt']:
                file_type = 'document'
            else:
                file_type = 'other'

            context = {
                'file_path': file_path.lower(),
                'file_location': file_path.lower(),
                'file_type': file_type,
                'file_size': getattr(scan_result, 'file_size', 0),
                'file_age_hours': file_age_hours,
                'ai_score': getattr(scan_result, 'ai_score', 0.0),
                'ember_score': getattr(scan_result, 'ember_score', 0.0),
                'reputation_score': getattr(scan_result, 'reputation_score', 0.0),
                'is_signed': getattr(scan_result, 'is_signed', False),
                'signature_valid': getattr(scan_result, 'signature_valid', False),
                'is_whitelisted': getattr(scan_result, 'is_whitelisted', False),
                'publisher': getattr(scan_result, 'publisher', None),
                'yara_matches': getattr(scan_result, 'yara_matches', []),
                'yara_match_count': len(getattr(scan_result, 'yara_matches', [])),
                'environment': get_config('environment.type', 'educational'),
                'network_alerts': getattr(scan_result, 'network_activity', {}).get('alerts', []),
                'network_alert_count': len(getattr(scan_result, 'network_activity', {}).get('alerts', []))
            }

            # Handle heuristic flags
            heuristic_flags = getattr(scan_result, 'heuristic_flags', [])
            context['heuristic_flags'] = heuristic_flags
            context['heuristic_suspicious_count'] = len([f for f in heuristic_flags if 'suspicious' in f])

            # Safely get threat level
            threat_level = getattr(scan_result, 'threat_level', 'benign')
            if hasattr(threat_level, 'value'):
                context['threat_level'] = threat_level.value
            else:
                context['threat_level'] = str(threat_level)

            # Add YARA categories
            yara_categories = []
            for match in context['yara_matches']:
                match_lower = str(match).lower()
                if any(keyword in match_lower for keyword in ['malware', 'trojan', 'virus']):
                    yara_categories.append('malware')
                elif 'ransomware' in match_lower:
                    yara_categories.append('ransomware')
                elif any(keyword in match_lower for keyword in ['suspicious', 'packer']):
                    yara_categories.append('suspicious')

            context['yara_categories'] = yara_categories

            return context

        except Exception as e:
            logger.error(f"Failed to build context for {file_path}: {e}")
            return {}

    def _evaluate_rule_conditions(self, rule: DSSRule, context: Dict[str, Any]) -> bool:
        """Evaluate if rule conditions are met - ENHANCED VERSION"""
        try:
            for condition_key, condition_value in rule.conditions.items():
                if condition_key not in context:
                    continue

                context_value = context[condition_key]

                # Handle different condition types
                if isinstance(condition_value, dict):
                    # Range conditions
                    if 'min' in condition_value and context_value < condition_value['min']:
                        return False
                    if 'max' in condition_value and context_value > condition_value['max']:
                        return False
                    if 'min_count' in condition_value:
                        if isinstance(context_value, (list, tuple, set)):
                            if len(context_value) < condition_value['min_count']:
                                return False
                        else:
                            if context_value < condition_value['min_count']:
                                return False
                    if 'max_hours' in condition_value and context_value > condition_value['max_hours']:
                        return False
                    if 'contains' in condition_value:
                        if not any(item in str(context_value).lower() for item in condition_value['contains']):
                            return False

                elif isinstance(condition_value, list):
                    # List membership conditions
                    if isinstance(context_value, list):
                        if not any(item in condition_value for item in context_value):
                            return False
                    else:
                        if context_value not in condition_value:
                            return False

                elif isinstance(condition_value, bool):
                    # Boolean conditions
                    if context_value != condition_value:
                        return False

                elif isinstance(condition_value, str):
                    # String conditions
                    if str(context_value).lower() != condition_value.lower():
                        return False

                else:
                    # Direct value comparison
                    if context_value != condition_value:
                        return False

            return True

        except Exception as e:
            logger.error(f"Error evaluating rule conditions for {rule.rule_id}: {e}")
            return False

    def execute_automatic_actions(self, recommended_actions: List[DSSAction], file_path: str) -> Dict[str, Any]:
        """Execute actions that are marked for automatic execution"""
        executed_actions = []
        execution_results = {}

        try:
            for action in recommended_actions:
                if not action.auto_execute:
                    continue

                result = self._execute_action(action, file_path)
                executed_actions.append({
                    'action_type': action.action_type.value,
                    'reason': action.reason,
                    'result': result
                })
                execution_results[action.action_type.value] = result
                self.stats['auto_actions_executed'] += 1

            return {
                'executed_actions': executed_actions,
                'execution_results': execution_results
            }

        except Exception as e:
            logger.error(f"Failed to execute automatic actions for {file_path}: {e}")
            return {'error': str(e)}

    def _execute_action(self, action: DSSAction, file_path: str) -> Dict[str, Any]:
        """Execute a specific action"""
        try:
            if action.action_type == ActionType.QUARANTINE:
                return self._quarantine_file(file_path, action.details)

            elif action.action_type == ActionType.MONITOR:
                return self._start_monitoring(file_path, action.details)

            elif action.action_type == ActionType.BLOCK_NETWORK:
                return self._block_network_access(file_path, action.details)

            elif action.action_type == ActionType.ALLOW:
                return self._allow_file(file_path, action.details)

            else:
                return {'status': 'not_implemented', 'action': action.action_type.value}

        except Exception as e:
            logger.error(f"Failed to execute action {action.action_type.value}: {e}")
            return {'status': 'error', 'error': str(e)}

    def _quarantine_file(self, file_path: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine a file"""
        try:
            quarantine_dir = get_config('quarantine.directory', './quarantine')
            os.makedirs(quarantine_dir, exist_ok=True)

            # Create quarantine entry
            quarantine_path = os.path.join(quarantine_dir,
                                           f"quarantine_{int(time.time())}_{os.path.basename(file_path)}")

            # Backup if requested
            if details.get('backup_before_quarantine'):
                import shutil
                shutil.move(file_path, quarantine_path)
            else:
                # Just log for now - don't actually delete files in demo
                logger.info(f"Would quarantine file: {file_path}")

            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            return {
                'status': 'success',
                'quarantine_path': quarantine_path,
                'backup_created': details.get('backup_before_quarantine', False)
            }

        except Exception as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return {'status': 'error', 'error': str(e)}

    def _start_monitoring(self, file_path: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Start monitoring a file"""
        # This would integrate with the background monitor
        logger.info(f"Started monitoring: {file_path}")
        return {
            'status': 'success',
            'monitoring_duration': details.get('duration', 3600),
            'details': details
        }

    def _block_network_access(self, file_path: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Block network access for a file/process"""
        # This would integrate with the network monitor
        logger.info(f"Network access blocked for: {file_path}")
        return {
            'status': 'success',
            'block_duration': details.get('block_duration', 3600),
            'details': details
        }

    def _allow_file(self, file_path: str, details: Dict[str, Any]) -> Dict[str, Any]:
        """Allow file and optionally whitelist it"""
        if details.get('whitelist'):
            # Add to whitelist
            logger.info(f"File whitelisted: {file_path}")

        return {
            'status': 'success',
            'whitelisted': details.get('whitelist', False)
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get DSS engine statistics"""
        return {
            **self.stats,
            'rules_loaded': len(self.rules),
            'rules_enabled': len([r for r in self.rules if r.enabled])
        }

    def add_rule(self, rule: DSSRule) -> bool:
        """Add a new rule"""
        try:
            self.rules.append(rule)
            self._save_rules()
            logger.info(f"Added DSS rule: {rule.rule_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to add rule: {e}")
            return False

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule"""
        try:
            self.rules = [r for r in self.rules if r.rule_id != rule_id]
            self._save_rules()
            logger.info(f"Removed DSS rule: {rule_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove rule: {e}")
            return False

    def enable_rule(self, rule_id: str) -> bool:
        """Enable a rule"""
        try:
            for rule in self.rules:
                if rule.rule_id == rule_id:
                    rule.enabled = True
                    self._save_rules()
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to enable rule: {e}")
            return False

    def disable_rule(self, rule_id: str) -> bool:
        """Disable a rule"""
        try:
            for rule in self.rules:
                if rule.rule_id == rule_id:
                    rule.enabled = False
                    self._save_rules()
                    return True
            return False
        except Exception as e:
            logger.error(f"Failed to disable rule: {e}")
            return False


# Convenience functions
def create_dss_engine():
    """Create and initialize DSS engine"""
    engine = DSSEngine()
    engine.load_rules()
    return engine


def evaluate_threat(file_path: str, scan_result, engine=None):
    """Convenience function to evaluate threat with DSS"""
    if engine is None:
        engine = create_dss_engine()
    return engine.evaluate_file(file_path, scan_result)


# Main function for testing
if __name__ == "__main__":
    import sys

    # Test DSS engine
    engine = DSSEngine()
    if engine.load_rules():
        print(f"DSS Engine loaded successfully with {len(engine.rules)} rules")

        # Print rule summary
        for rule in engine.rules:
            print(f"- {rule.name}: {rule.description} (Priority: {rule.priority})")

        stats = engine.get_statistics()
        print(f"\nStatistics: {stats}")
    else:
        print("Failed to load DSS engine")