import os
import time
import hashlib
import numpy as np
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

try:
    import joblib

    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    print("Warning: joblib not installed. Install with: pip install joblib")

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatType(Enum):
    """Specific malware types"""
    TROJAN = "Trojan"
    RANSOMWARE = "Ransomware"
    WORM = "Worm"
    VIRUS = "Virus"
    ROOTKIT = "Rootkit"
    BACKDOOR = "Backdoor"
    KEYLOGGER = "Keylogger"
    SPYWARE = "Spyware"
    ADWARE = "Adware"
    CRYPTOMINER = "Cryptominer"
    DOWNLOADER = "Downloader"
    DROPPER = "Dropper"
    INFOSTEALER = "Infostealer"
    BOTNET = "Botnet"
    EXPLOIT = "Exploit"
    PUA = "Potentially Unwanted Application"
    UNKNOWN_MALWARE = "Unknown Malware"
    BENIGN = "Benign"


@dataclass
class ThreatBehavior:
    """Detailed threat behavior analysis"""
    category: str
    description: str
    severity: str
    indicators: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelligence:
    """Comprehensive threat intelligence"""
    threat_type: ThreatType
    threat_family: Optional[str] = None
    behaviors: List[ThreatBehavior] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    infection_method: Optional[str] = None
    payload_description: Optional[str] = None
    affected_files: List[str] = field(default_factory=list)
    affected_directories: List[str] = field(default_factory=list)
    network_indicators: List[Dict[str, str]] = field(default_factory=list)
    registry_modifications: List[str] = field(default_factory=list)
    persistence_mechanisms: List[str] = field(default_factory=list)
    risk_assessment: str = ""
    mitigation_steps: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result with threat intelligence"""
    file_path: str
    file_hash: str
    file_size: int
    scan_time: float
    threat_level: ThreatLevel
    confidence: float
    ai_score: float
    reputation_score: float

    # Threat intelligence
    threat_intelligence: Optional[ThreatIntelligence] = None

    # Analysis results
    heuristic_flags: List[str] = field(default_factory=list)
    signature_info: Dict[str, Any] = field(default_factory=dict)
    sandbox_result: Dict[str, Any] = field(default_factory=dict)

    # Additional context
    is_whitelisted: bool = False
    false_positive_likelihood: float = 0.0
    detailed_analysis: Dict[str, Any] = field(default_factory=dict)


class ThreatClassifier:
    """Advanced threat type classification system"""

    def __init__(self):
        # Behavior patterns for different threat types
        self.threat_signatures = {
            ThreatType.RANSOMWARE: {
                'strings': [b'encrypt', b'decrypt', b'ransom', b'bitcoin', b'wallet',
                            b'.locked', b'.encrypted', b'HOW_TO_DECRYPT', b'YOUR_FILES'],
                'behaviors': ['file_encryption', 'extension_change', 'ransom_note_creation'],
                'registry': ['HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
                'network': ['tor', 'bitcoin', 'cryptocurrency']
            },
            ThreatType.TROJAN: {
                'strings': [b'backdoor', b'remote', b'control', b'shell', b'cmd.exe'],
                'behaviors': ['remote_access', 'command_execution', 'unauthorized_access'],
                'registry': ['Run', 'RunOnce'],
                'network': ['c2', 'command_control']
            },
            ThreatType.KEYLOGGER: {
                'strings': [b'keylogger', b'keystroke', b'GetAsyncKeyState', b'SetWindowsHookEx',
                            b'keyboard', b'capture', b'log'],
                'behaviors': ['keyboard_monitoring', 'input_capture'],
                'registry': ['HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run']
            },
            ThreatType.ROOTKIT: {
                'strings': [b'rootkit', b'hide', b'stealth', b'kernel', b'driver', b'hook'],
                'behaviors': ['process_hiding', 'file_hiding', 'kernel_modification'],
                'registry': ['Services', 'Drivers']
            },
            ThreatType.WORM: {
                'strings': [b'replicate', b'propagate', b'network', b'share', b'autorun'],
                'behaviors': ['network_propagation', 'self_replication', 'removable_media_infection'],
                'network': ['scan', 'exploit', 'spread']
            },
            ThreatType.INFOSTEALER: {
                'strings': [b'password', b'credential', b'browser', b'wallet', b'steal', b'cookie'],
                'behaviors': ['credential_theft', 'browser_data_extraction', 'wallet_theft'],
                'registry': []
            },
            ThreatType.CRYPTOMINER: {
                'strings': [b'miner', b'mining', b'monero', b'xmr', b'crypto', b'pool', b'hashrate'],
                'behaviors': ['cryptocurrency_mining', 'high_cpu_usage'],
                'network': ['mining_pool', 'stratum']
            },
            ThreatType.BACKDOOR: {
                'strings': [b'backdoor', b'reverse', b'shell', b'connect', b'bind'],
                'behaviors': ['unauthorized_access', 'remote_control', 'persistence'],
                'network': ['reverse_connection', 'bind_port']
            }
        }

    def classify_threat(self, file_path: str, ai_score: float,
                        heuristic_flags: List[str],
                        file_content: bytes = None) -> ThreatIntelligence:
        """Classify threat type and generate detailed intelligence"""

        # Determine primary threat type
        threat_type = self._determine_threat_type(ai_score, heuristic_flags, file_content)

        # Generate behaviors
        behaviors = self._analyze_behaviors(threat_type, heuristic_flags, file_content)

        # Determine capabilities
        capabilities = self._extract_capabilities(threat_type, heuristic_flags)

        # Generate threat intelligence
        intel = ThreatIntelligence(
            threat_type=threat_type,
            behaviors=behaviors,
            capabilities=capabilities
        )

        # Add specific details based on threat type
        intel = self._enhance_intelligence(intel, file_path, heuristic_flags, file_content)

        return intel

    def _determine_threat_type(self, ai_score: float, heuristic_flags: List[str],
                               file_content: bytes = None) -> ThreatType:
        """Determine primary threat type"""

        if ai_score < 0.3:
            return ThreatType.BENIGN

        # Score each threat type
        scores = {}

        for threat_type, signatures in self.threat_signatures.items():
            score = 0

            # Check string patterns
            if file_content:
                for pattern in signatures['strings']:
                    if pattern in file_content[:50000]:  # Check first 50KB
                        score += 2

            # Check behavior flags
            for flag in heuristic_flags:
                flag_lower = flag.lower()
                for behavior in signatures['behaviors']:
                    if behavior.replace('_', ' ') in flag_lower:
                        score += 3

            scores[threat_type] = score

        # Get highest scoring threat type
        if scores:
            max_score = max(scores.values())
            if max_score > 0:
                return max(scores, key=scores.get)

        # Fallback based on AI score
        if ai_score >= 0.8:
            return ThreatType.UNKNOWN_MALWARE
        elif ai_score >= 0.5:
            return ThreatType.PUA

        return ThreatType.BENIGN

    def _analyze_behaviors(self, threat_type: ThreatType, heuristic_flags: List[str],
                           file_content: bytes = None) -> List[ThreatBehavior]:
        """Analyze specific behaviors"""
        behaviors = []

        # Map threat type to behaviors
        behavior_mapping = {
            ThreatType.RANSOMWARE: [
                ThreatBehavior(
                    category="File Encryption",
                    description="Encrypts user files and demands ransom",
                    severity="CRITICAL",
                    indicators=["File encryption routines", "Ransom note generation", "Bitcoin wallet references"]
                ),
                ThreatBehavior(
                    category="System Modification",
                    description="Modifies system settings to prevent recovery",
                    severity="HIGH",
                    indicators=["Disables System Restore", "Deletes Shadow Copies", "Modifies boot sector"]
                )
            ],
            ThreatType.TROJAN: [
                ThreatBehavior(
                    category="Unauthorized Access",
                    description="Provides backdoor access to attackers",
                    severity="HIGH",
                    indicators=["Remote shell creation", "Network listener", "Command execution"]
                ),
                ThreatBehavior(
                    category="Data Exfiltration",
                    description="Steals and transmits sensitive data",
                    severity="HIGH",
                    indicators=["Data collection", "Network transmission", "Encrypted communication"]
                )
            ],
            ThreatType.KEYLOGGER: [
                ThreatBehavior(
                    category="Input Monitoring",
                    description="Captures keyboard input and mouse activity",
                    severity="HIGH",
                    indicators=["Keyboard hooks", "Input capture APIs", "Log file creation"]
                )
            ],
            ThreatType.ROOTKIT: [
                ThreatBehavior(
                    category="Stealth Operations",
                    description="Hides presence from security software",
                    severity="CRITICAL",
                    indicators=["Kernel-mode operations", "Process hiding", "File hiding"]
                )
            ],
            ThreatType.WORM: [
                ThreatBehavior(
                    category="Network Propagation",
                    description="Spreads to other systems automatically",
                    severity="HIGH",
                    indicators=["Network scanning", "Exploit delivery", "Self-replication"]
                )
            ],
            ThreatType.INFOSTEALER: [
                ThreatBehavior(
                    category="Credential Theft",
                    description="Steals passwords and authentication tokens",
                    severity="HIGH",
                    indicators=["Browser data access", "Password extraction", "Token theft"]
                )
            ],
            ThreatType.CRYPTOMINER: [
                ThreatBehavior(
                    category="Resource Hijacking",
                    description="Uses system resources for cryptocurrency mining",
                    severity="MEDIUM",
                    indicators=["High CPU usage", "Mining pool connection", "GPU utilization"]
                )
            ]
        }

        # Get behaviors for this threat type
        if threat_type in behavior_mapping:
            behaviors.extend(behavior_mapping[threat_type])

        # Add behaviors based on heuristic flags
        for flag in heuristic_flags:
            if 'suspicious_network' in flag:
                behaviors.append(ThreatBehavior(
                    category="Network Activity",
                    description="Suspicious network communication detected",
                    severity="MEDIUM",
                    indicators=[flag]
                ))
            elif 'registry' in flag:
                behaviors.append(ThreatBehavior(
                    category="Registry Modification",
                    description="Modifies Windows registry for persistence",
                    severity="MEDIUM",
                    indicators=[flag]
                ))

        return behaviors

    def _extract_capabilities(self, threat_type: ThreatType,
                              heuristic_flags: List[str]) -> List[str]:
        """Extract threat capabilities"""
        capabilities = []

        capability_mapping = {
            ThreatType.RANSOMWARE: [
                "File Encryption",
                "Data Destruction",
                "Ransom Demand",
                "System Lock",
                "Network Propagation"
            ],
            ThreatType.TROJAN: [
                "Remote Access",
                "Command Execution",
                "Data Exfiltration",
                "Privilege Escalation",
                "Persistence"
            ],
            ThreatType.KEYLOGGER: [
                "Keystroke Logging",
                "Screen Capture",
                "Clipboard Monitoring",
                "Credential Theft"
            ],
            ThreatType.ROOTKIT: [
                "Kernel Modification",
                "Process Hiding",
                "File Hiding",
                "Network Hiding",
                "Anti-Detection"
            ],
            ThreatType.WORM: [
                "Self-Replication",
                "Network Scanning",
                "Exploit Delivery",
                "Rapid Propagation"
            ],
            ThreatType.INFOSTEALER: [
                "Password Theft",
                "Browser Data Extraction",
                "Cryptocurrency Wallet Theft",
                "Session Hijacking"
            ],
            ThreatType.CRYPTOMINER: [
                "CPU Hijacking",
                "GPU Hijacking",
                "Cryptocurrency Mining",
                "Resource Consumption"
            ],
            ThreatType.BACKDOOR: [
                "Remote Shell",
                "Reverse Connection",
                "Persistent Access",
                "Command & Control"
            ]
        }

        if threat_type in capability_mapping:
            capabilities = capability_mapping[threat_type]

        return capabilities

    def _enhance_intelligence(self, intel: ThreatIntelligence, file_path: str,
                              heuristic_flags: List[str], file_content: bytes = None) -> ThreatIntelligence:
        """Enhance intelligence with additional details"""

        # Set infection method
        intel.infection_method = self._determine_infection_method(intel.threat_type, heuristic_flags)

        # Set payload description
        intel.payload_description = self._describe_payload(intel.threat_type)

        # Identify affected areas
        intel.affected_files = [file_path]
        intel.affected_directories = [str(Path(file_path).parent)]

        # Risk assessment
        intel.risk_assessment = self._assess_risk(intel.threat_type, intel.behaviors)

        # Mitigation steps
        intel.mitigation_steps = self._get_mitigation_steps(intel.threat_type)

        # Persistence mechanisms
        intel.persistence_mechanisms = self._identify_persistence(heuristic_flags)

        return intel

    def _determine_infection_method(self, threat_type: ThreatType,
                                    heuristic_flags: List[str]) -> str:
        """Determine how the threat infects systems"""
        infection_methods = {
            ThreatType.RANSOMWARE: "Typically via phishing emails, exploit kits, or downloaded from compromised websites",
            ThreatType.TROJAN: "Often disguised as legitimate software or bundled with pirated applications",
            ThreatType.WORM: "Spreads automatically through network vulnerabilities or removable media",
            ThreatType.KEYLOGGER: "Usually installed by other malware or through social engineering",
            ThreatType.ROOTKIT: "Requires administrator privileges, often installed by other malware",
            ThreatType.INFOSTEALER: "Distributed through phishing, malicious downloads, or software vulnerabilities",
            ThreatType.CRYPTOMINER: "Drive-by downloads, malicious scripts, or bundled with legitimate software"
        }

        return infection_methods.get(threat_type, "Unknown infection vector")

    def _describe_payload(self, threat_type: ThreatType) -> str:
        """Describe what the malware does"""
        payload_descriptions = {
            ThreatType.RANSOMWARE: "Encrypts files with strong encryption and demands payment for decryption key",
            ThreatType.TROJAN: "Establishes backdoor access allowing remote control and data theft",
            ThreatType.KEYLOGGER: "Monitors and records all keyboard input to capture passwords and sensitive data",
            ThreatType.ROOTKIT: "Hides malicious processes and maintains persistent deep system access",
            ThreatType.WORM: "Replicates across network systems exploiting vulnerabilities automatically",
            ThreatType.INFOSTEALER: "Extracts stored credentials, browser data, and cryptocurrency wallets",
            ThreatType.CRYPTOMINER: "Utilizes system resources to mine cryptocurrency without consent"
        }

        return payload_descriptions.get(threat_type, "Malicious behavior detected")

    def _assess_risk(self, threat_type: ThreatType, behaviors: List[ThreatBehavior]) -> str:
        """Assess overall risk"""
        critical_types = [ThreatType.RANSOMWARE, ThreatType.ROOTKIT, ThreatType.WORM]
        high_types = [ThreatType.TROJAN, ThreatType.KEYLOGGER, ThreatType.INFOSTEALER, ThreatType.BACKDOOR]

        if threat_type in critical_types:
            return "CRITICAL: Immediate action required. This malware can cause severe data loss or system damage."
        elif threat_type in high_types:
            return "HIGH: Significant security risk. This malware can compromise sensitive data and system integrity."
        elif threat_type == ThreatType.CRYPTOMINER:
            return "MEDIUM: Performance impact and unauthorized resource usage. May indicate other infections."
        elif threat_type == ThreatType.PUA:
            return "LOW: Potentially unwanted but not immediately dangerous. May exhibit intrusive behavior."
        else:
            return "UNKNOWN: Unable to fully assess risk. Recommend further analysis."

    def _get_mitigation_steps(self, threat_type: ThreatType) -> List[str]:
        """Get recommended mitigation steps"""
        mitigation_mapping = {
            ThreatType.RANSOMWARE: [
                "Immediately disconnect from network to prevent spread",
                "DO NOT pay the ransom",
                "Isolate the infected system",
                "Restore files from clean backups if available",
                "Use decryption tools if available for this ransomware family",
                "Format and reinstall operating system",
                "Update all security software and apply patches"
            ],
            ThreatType.TROJAN: [
                "Disconnect from network immediately",
                "Run full system scan with updated antivirus",
                "Check for unauthorized user accounts",
                "Review and close unusual network connections",
                "Change all passwords from a clean system",
                "Consider full system wipe and reinstall"
            ],
            ThreatType.KEYLOGGER: [
                "Change all passwords from a different clean device",
                "Enable two-factor authentication on all accounts",
                "Monitor financial accounts for unauthorized access",
                "Remove malware using security software",
                "Check for additional payloads or rootkits"
            ],
            ThreatType.ROOTKIT: [
                "Boot from clean external media",
                "Use specialized rootkit removal tools",
                "Full system format and reinstall recommended",
                "Update BIOS/UEFI firmware",
                "Implement application whitelisting"
            ],
            ThreatType.WORM: [
                "Isolate infected systems immediately",
                "Block network traffic from infected hosts",
                "Patch vulnerabilities being exploited",
                "Scan entire network for additional infections",
                "Update intrusion detection systems"
            ],
            ThreatType.INFOSTEALER: [
                "Immediately change all passwords from clean system",
                "Enable MFA on all accounts",
                "Monitor accounts for suspicious activity",
                "Check browser extensions and remove suspicious ones",
                "Review recent file access and modifications",
                "Move cryptocurrency to new wallets"
            ],
            ThreatType.CRYPTOMINER: [
                "Terminate suspicious processes",
                "Remove persistence mechanisms",
                "Check scheduled tasks and startup items",
                "Monitor system resource usage",
                "Update security software"
            ]
        }

        return mitigation_mapping.get(threat_type, [
            "Quarantine the file immediately",
            "Run full system scan",
            "Update security software",
            "Monitor system for unusual activity"
        ])

    def _identify_persistence(self, heuristic_flags: List[str]) -> List[str]:
        """Identify persistence mechanisms"""
        persistence = []

        for flag in heuristic_flags:
            if 'registry' in flag.lower():
                persistence.append("Registry Run Keys")
            if 'scheduled' in flag.lower() or 'task' in flag.lower():
                persistence.append("Scheduled Tasks")
            if 'startup' in flag.lower():
                persistence.append("Startup Folder")
            if 'service' in flag.lower():
                persistence.append("Windows Service")

        return persistence if persistence else ["None detected"]


class EMBERThreatScanner:
    def __init__(self, ember_model_dir: str = "ai_models/ember_models/",
                 whitelist_manager=None, reputation_calculator=None, config=None, db=None):

        self.model_dir = Path(ember_model_dir)
        self.whitelist_manager = whitelist_manager
        self.reputation_calculator = reputation_calculator
        self.config = config
        self.db = db  # LocalDatabase instance for hash tracking

        # EMBER model components
        self.model = None
        self.scaler = None
        self.is_loaded = False

        # Threat classifier
        self.threat_classifier = ThreatClassifier()

        # Known good file patterns - EXPANDED (from your enhanced_scanner.py)
        self.known_good_patterns = {
            'system_files': [
                r'C:\\Windows\\System32\\.*',
                r'C:\\Windows\\SysWOW64\\.*',
                r'C:\\Program Files\\Windows Defender\\.*',
                r'C:\\Program Files\\Microsoft\\.*',
                r'C:\\Windows\\WinSxS\\.*',
                r'C:\\Windows\\Microsoft\.NET\\.*'
            ],
            'developer_tools': [
                r'.*\\Python\\Python\d+\\.*',
                r'.*\\nodejs\\.*',
                r'.*\\Microsoft Visual Studio\\.*',
                r'.*\\JetBrains\\.*',
                r'.*\\Git\\.*',
                r'.*\\Java\\jdk.*\\.*',
                r'.*\\Java\\jre.*\\.*',
                r'.*\\Eclipse\\.*',
                r'.*\\VSCode\\.*'
            ],
            'common_apps': [
                r'.*\\Google\\Chrome\\.*',
                r'.*\\Mozilla Firefox\\.*',
                r'.*\\Microsoft Office\\.*',
                r'.*\\Adobe\\.*',
                r'.*\\Zoom\\.*',
                r'.*\\Discord\\.*',
                r'.*\\Slack\\.*',
                r'.*\\Steam\\.*',
                r'.*\\Epic Games\\.*'
            ]
        }

        # Callbacks
        self.callbacks = {
            'on_file_scanned': None,
            'on_threat_detected': None,
            'on_scan_progress': None,
            'on_scan_complete': None
        }

        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_found': 0,
            'false_positives_prevented': 0,
            'threats_by_type': {}
        }

        # Load model
        self.load_model()

        logger.info("EMBERThreatScanner initialized")

    @property
    def ai_model_available(self) -> bool:
        """Check if AI model is loaded and available"""
        return self.is_loaded and self.model is not None

    def load_model(self) -> bool:
        """Load EMBER model and scaler"""
        if not JOBLIB_AVAILABLE:
            logger.error("joblib not available")
            return False

        try:
            # Find model file
            model_files = list(self.model_dir.rglob("ember_*.pkl"))
            model_files = [f for f in model_files if 'scaler' not in f.name.lower()]

            if not model_files:
                logger.error(f"No EMBER model found in {self.model_dir}")
                return False

            # Load model
            model_file = model_files[0]
            self.model = joblib.load(model_file)
            logger.info(f"Loaded EMBER model: {model_file.name}")

            # Load scaler
            scaler_files = list(self.model_dir.rglob("*scaler*.pkl"))
            if scaler_files:
                self.scaler = joblib.load(scaler_files[0])
                logger.info(f"Loaded scaler: {scaler_files[0].name}")

            # Test model
            test_features = np.zeros((1, 2381))
            if hasattr(self.model, 'predict_proba'):
                self.model.predict_proba(test_features)
                self.is_loaded = True
                logger.info("EMBER model test successful")
                return True

        except Exception as e:
            logger.error(f"Failed to load EMBER model: {e}")
            return False

        return False

    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """Extract EMBER features from file"""
        try:
            if not os.path.exists(file_path):
                return None

            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return None

            # Read file
            max_read = min(10 * 1024 * 1024, file_size)
            with open(file_path, 'rb') as f:
                file_bytes = f.read(max_read)

            if len(file_bytes) == 0:
                return None

            # Extract features
            features = []

            # File size
            features.append(len(file_bytes))
            features.append(len(file_bytes) / 1024)

            # Byte histogram (256 features)
            byte_hist = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
            byte_hist = byte_hist / len(file_bytes) if len(file_bytes) > 0 else byte_hist
            features.extend(byte_hist.tolist())

            # Entropy
            probabilities = byte_hist[byte_hist > 0]
            entropy = -np.sum(probabilities * np.log2(probabilities)) if len(probabilities) > 0 else 0
            features.append(entropy)

            # Printable chars ratio
            printable_count = sum(1 for b in file_bytes[:1000] if 32 <= b <= 126)
            features.append(printable_count / min(1000, len(file_bytes)))

            # Magic bytes
            magic_signatures = {
                b'MZ': 1, b'\x7fELF': 2, b'PK': 3, b'\x89PNG': 4
            }
            magic_feature = 0
            for magic, value in magic_signatures.items():
                if file_bytes.startswith(magic):
                    magic_feature = value
                    break
            features.append(magic_feature)

            # Pad to 2381 features
            target_features = 2381
            if len(features) < target_features:
                features.extend([0] * (target_features - len(features)))
            else:
                features = features[:target_features]

            return np.array(features).reshape(1, -1)

        except Exception as e:
            logger.debug(f"Feature extraction failed: {e}")
            return None

    def predict_with_ember(self, file_path: str) -> float:
        """Get EMBER malware prediction score"""
        if not self.is_loaded:
            return 0.0

        try:
            features = self.extract_features(file_path)
            if features is None:
                return 0.0

            # Scale features
            if self.scaler:
                features = self.scaler.transform(features)

            # Predict
            if hasattr(self.model, 'predict_proba'):
                prediction = self.model.predict_proba(features)[0]
                score = float(prediction[1]) if len(prediction) > 1 else float(prediction[0])
            else:
                prediction = self.model.predict(features)[0]
                score = float(prediction)

            return max(0.0, min(1.0, score))

        except Exception as e:
            logger.debug(f"EMBER prediction failed: {e}")
            return 0.0

    def perform_heuristic_analysis(self, file_path: str) -> List[str]:
        """Perform heuristic analysis for threat indicators"""
        flags = []

        try:
            # Read file sample
            with open(file_path, 'rb') as f:
                sample = f.read(50000)  # First 50KB

            # Check for suspicious strings
            suspicious_patterns = {
                'Ransomware': [b'encrypt', b'decrypt', b'ransom', b'bitcoin', b'YOUR_FILES', b'.locked'],
                'Trojan': [b'backdoor', b'remote', b'shell', b'RAT'],
                'Keylogger': [b'keylog', b'keystroke', b'GetAsyncKeyState', b'SetWindowsHookEx'],
                'Cryptominer': [b'miner', b'mining', b'monero', b'xmr', b'pool'],
                'Infostealer': [b'password', b'credential', b'wallet', b'cookie', b'token'],
                'Rootkit': [b'rootkit', b'hide', b'stealth', b'kernel'],
                'Network': [b'connect', b'socket', b'http', b'download', b'upload']
            }

            for category, patterns in suspicious_patterns.items():
                for pattern in patterns:
                    if pattern in sample:
                        flags.append(f"suspicious_{category.lower()}_{pattern.decode('utf-8', errors='ignore')}")

            # Check for high entropy (packed/encrypted)
            if len(sample) > 0:
                byte_hist = np.bincount(np.frombuffer(sample, dtype=np.uint8), minlength=256)
                probs = byte_hist[byte_hist > 0] / len(sample)
                entropy = -np.sum(probs * np.log2(probs))

                if entropy > 7.5:
                    flags.append("high_entropy_packed_or_encrypted")

        except Exception as e:
            logger.debug(f"Heuristic analysis error: {e}")

        return flags

    def scan_file(self, file_path: str) -> ScanResult:
        """Comprehensive file scan with threat intelligence"""
        start_time = time.time()

        try:
            # Basic checks
            if not os.path.exists(file_path):
                return None

            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_hash(file_path)

            # NEW: Check if file needs rescanning (hash-based skip)
            if self.db:
                try:
                    existing_hash = self.db.get_file_hash(file_path)
                    if existing_hash == file_hash:
                        # File hasn't changed, skip scanning
                        # Return cached safe result
                        return ScanResult(
                            file_path=file_path,
                            file_hash=file_hash,
                            file_size=file_size,
                            scan_time=time.time() - start_time,
                            threat_level=ThreatLevel.SAFE,
                            confidence=1.0,
                            ai_score=0.0,
                            reputation_score=1.0,
                            is_whitelisted=False,
                            threat_intelligence=ThreatIntelligence(threat_type=ThreatType.BENIGN),
                            detailed_analysis={'cached_scan': True, 'reason': 'File unchanged since last scan'}
                        )
                except Exception as e:
                    # If hash check fails, continue with normal scanning
                    pass

            # Check whitelist
            is_whitelisted = False
            if self.whitelist_manager:
                is_whitelisted, _ = self.whitelist_manager.is_whitelisted_hash(file_hash)

            if is_whitelisted:
                return ScanResult(
                    file_path=file_path,
                    file_hash=file_hash,
                    file_size=file_size,
                    scan_time=time.time() - start_time,
                    threat_level=ThreatLevel.SAFE,
                    confidence=1.0,
                    ai_score=0.0,
                    reputation_score=1.0,
                    is_whitelisted=True,
                    threat_intelligence=ThreatIntelligence(threat_type=ThreatType.BENIGN)
                )

            # EMBER AI prediction
            ai_score = self.predict_with_ember(file_path)

            # Heuristic analysis
            heuristic_flags = self.perform_heuristic_analysis(file_path)

            # Get signature info
            signature_info = self._get_signature_info(file_path)

            # Calculate reputation
            reputation_score = self._calculate_reputation(file_path, signature_info)

            # Calculate false positive likelihood with ALL factors
            fp_likelihood = self._calculate_fp_likelihood(
                ai_score, reputation_score, signature_info, file_path, heuristic_flags
            )

            # Check if should auto-whitelist (from your enhanced_scanner.py)
            if self.should_auto_whitelist(ai_score, reputation_score, signature_info,
                                          file_path, fp_likelihood):
                # Auto-whitelist this file
                if self.whitelist_manager and file_hash:
                    try:
                        self.whitelist_manager.add_to_whitelist(
                            file_hash,
                            reason=f"Auto-whitelisted (FP likelihood: {fp_likelihood:.2f})",
                            signature_info=signature_info
                        )
                        self.stats['false_positives_prevented'] += 1
                        logger.info(f"Auto-whitelisted (FP: {fp_likelihood:.2f}): {file_path}")
                    except:
                        pass

                # Return as safe
                return ScanResult(
                    file_path=file_path,
                    file_hash=file_hash,
                    file_size=file_size,
                    scan_time=time.time() - start_time,
                    threat_level=ThreatLevel.SAFE,
                    confidence=1.0,
                    ai_score=ai_score,
                    reputation_score=reputation_score,
                    is_whitelisted=True,
                    false_positive_likelihood=fp_likelihood,
                    threat_intelligence=ThreatIntelligence(threat_type=ThreatType.BENIGN),
                    detailed_analysis={
                        'auto_whitelisted': True,
                        'reason': f'False positive likelihood: {fp_likelihood:.2f}'
                    }
                )

            # Classify threat level
            threat_level = self._classify_threat_level(
                ai_score, reputation_score, heuristic_flags, signature_info, fp_likelihood
            )

            # Generate threat intelligence
            threat_intelligence = None
            if threat_level != ThreatLevel.SAFE:
                # Read file content for classification
                try:
                    with open(file_path, 'rb') as f:
                        file_content = f.read(50000)
                except:
                    file_content = None

                threat_intelligence = self.threat_classifier.classify_threat(
                    file_path, ai_score, heuristic_flags, file_content
                )
            else:
                threat_intelligence = ThreatIntelligence(threat_type=ThreatType.BENIGN)

            # Calculate confidence
            confidence = self._calculate_confidence(ai_score, reputation_score, signature_info)

            # Create result
            result = ScanResult(
                file_path=file_path,
                file_hash=file_hash,
                file_size=file_size,
                scan_time=time.time() - start_time,
                threat_level=threat_level,
                confidence=confidence,
                ai_score=ai_score,
                reputation_score=reputation_score,
                threat_intelligence=threat_intelligence,
                heuristic_flags=heuristic_flags,
                signature_info=signature_info,
                false_positive_likelihood=fp_likelihood,
                detailed_analysis={
                    'ember_analysis': {'score': ai_score, 'model': 'EMBER Advanced'},
                    'heuristic_analysis': {'flags': heuristic_flags, 'count': len(heuristic_flags)},
                    'reputation_analysis': {'score': reputation_score},
                    'false_positive_analysis': {'likelihood': fp_likelihood}
                }
            )

            # Update stats
            self.stats['files_scanned'] += 1
            if threat_level != ThreatLevel.SAFE:
                self.stats['threats_found'] += 1
                threat_type_name = threat_intelligence.threat_type.value
                self.stats['threats_by_type'][threat_type_name] = \
                    self.stats['threats_by_type'].get(threat_type_name, 0) + 1

            if fp_likelihood > 0.7:
                self.stats['false_positives_prevented'] += 1

            # Callbacks
            if self.callbacks['on_file_scanned']:
                self.callbacks['on_file_scanned'](result)

            if threat_level != ThreatLevel.SAFE and self.callbacks['on_threat_detected']:
                self.callbacks['on_threat_detected'](result)

            # NEW: Update file hash in database for future scans (only for safe files)
            if self.db and threat_level == ThreatLevel.SAFE:
                try:
                    self.db.update_file_hash(file_path, file_hash)
                except Exception as e:
                    logger.error(f"Failed to update file hash: {e}")

            return result

        except Exception as e:
            logger.error(f"Scan failed for {file_path}: {e}")
            return None

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash"""
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""

    def _get_signature_info(self, file_path: str) -> Dict[str, Any]:
        """Get digital signature info"""
        if self.whitelist_manager:
            try:
                from client.protection.whitelist_manager import SignatureVerifier
                return SignatureVerifier.verify_signature(file_path)
            except:
                pass

        return {'is_signed': False, 'signature_valid': False, 'publisher': None}

    def _calculate_reputation(self, file_path: str, signature_info: Dict) -> float:
        """Calculate file reputation"""
        if self.reputation_calculator:
            try:
                return self.reputation_calculator.calculate_reputation(file_path, signature_info)
            except:
                pass

        # Simple fallback
        score = 0.0
        if signature_info.get('signature_valid'):
            score += 0.5
        if 'windows' in file_path.lower() or 'program files' in file_path.lower():
            score += 0.3
        return min(1.0, score)

    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches pattern"""
        import re
        try:
            return bool(re.match(pattern, file_path, re.IGNORECASE))
        except:
            return False

    def should_auto_whitelist(self, ai_score: float, reputation_score: float,
                              signature_info: Dict, file_path: str,
                              fp_likelihood: float) -> bool:
        """
        Determine if file should be auto-whitelisted
        EXACTLY matches your enhanced_scanner.py logic
        """
        # Auto-whitelist if:

        # 1. High false positive likelihood (lowered threshold)
        if fp_likelihood >= 0.7:  # Lowered from 0.8
            return True

        # 2. Trusted publisher with valid signature (even with moderate threat score)
        if (signature_info.get('signature_valid') and
                signature_info.get('publisher') and
                self.whitelist_manager and
                self.whitelist_manager.is_trusted_publisher(signature_info['publisher']) and
                ai_score < 0.6):  # Increased from 0.4
            return True

        # 3. High reputation with moderate AI score (more lenient)
        if reputation_score >= 0.8 and ai_score < 0.5:  # More lenient
            return True

        # 4. Known good location with signature
        file_path_lower = file_path.lower()
        if signature_info.get('is_signed'):
            if any(loc in file_path_lower for loc in ['program files', 'windows', 'microsoft']):
                if ai_score < 0.7:  # More lenient
                    return True

        return False

    def _calculate_fp_likelihood(self, ai_score: float, reputation_score: float,
                                 signature_info: Dict, file_path: str,
                                 heuristic_flags: List[str] = None) -> float:
        """
        Calculate false positive likelihood (COMPLETE reduced FP system)
        EXACTLY matches your enhanced_scanner.py logic
        """
        fp_score = 0.0

        # 1. VERY HIGH reputation = almost certainly false positive
        if reputation_score >= 0.9:
            fp_score += 0.6  # Increased from 0.4
        elif reputation_score >= 0.7:
            fp_score += 0.4  # Increased from 0.2
        elif reputation_score >= 0.5:
            fp_score += 0.2  # New threshold

        # 2. Valid digital signature = VERY likely false positive
        if signature_info.get('signature_valid'):
            fp_score += 0.5  # Increased from 0.3

            # Trusted publisher = EXTREMELY likely false positive
            if signature_info.get('publisher') and self.whitelist_manager:
                if self.whitelist_manager.is_trusted_publisher(signature_info['publisher']):
                    fp_score += 0.6  # Increased from 0.4

        # 3. Low AI score with any reputation = likely false positive
        if ai_score < 0.7 and reputation_score > 0.5:  # More lenient threshold
            fp_score += 0.4  # Increased from 0.3

        # 4. Check against known good patterns - STRONGER bonus
        for category, patterns in self.known_good_patterns.items():
            for pattern in patterns:
                if self._matches_pattern(file_path, pattern):
                    fp_score += 0.5  # Increased from 0.3
                    break

        # 5. Heuristic-only detection with low score = very likely FP
        if heuristic_flags is not None:
            if ai_score < 0.6:  # More lenient
                if len(heuristic_flags) < 4:  # Increased from 3
                    fp_score += 0.3  # Increased from 0.2

        # 6. File age bonus - OLD files are trusted
        try:
            file_age_days = (time.time() - os.path.getctime(file_path)) / 86400
            if file_age_days > 180:  # 6 months
                fp_score += 0.4  # Increased
            elif file_age_days > 90:  # 3 months
                fp_score += 0.3  # Increased from 0.2
            elif file_age_days > 30:
                fp_score += 0.15  # Increased from 0.1
        except:
            pass

        # 7. System location bonus
        if 'program files' in file_path.lower() or 'windows' in file_path.lower():
            fp_score += 0.3

        # Cap at 1.0
        return min(1.0, fp_score)

    def _classify_threat_level(self, ai_score: float, reputation_score: float,
                               heuristic_flags: List[str], signature_info: Dict,
                               fp_likelihood: float) -> ThreatLevel:
        """Classify threat level with FP reduction"""

        # Auto-whitelist high FP likelihood
        if fp_likelihood >= 0.8:
            return ThreatLevel.SAFE

        # Adjust thresholds based on signature
        if signature_info.get('signature_valid'):
            # More lenient for signed files
            if ai_score >= 0.9:
                return ThreatLevel.HIGH
            elif ai_score >= 0.7:
                return ThreatLevel.MEDIUM
            elif ai_score >= 0.5:
                return ThreatLevel.LOW
        else:
            # Standard thresholds for unsigned files
            if ai_score >= 0.8:
                return ThreatLevel.CRITICAL
            elif ai_score >= 0.6:
                return ThreatLevel.HIGH
            elif ai_score >= 0.4:
                return ThreatLevel.MEDIUM
            elif ai_score >= 0.2:
                return ThreatLevel.LOW

        # Heuristic escalation
        suspicious_count = len([f for f in heuristic_flags if 'suspicious' in f])
        if suspicious_count >= 3:
            return ThreatLevel.MEDIUM
        elif suspicious_count >= 1:
            return ThreatLevel.LOW

        return ThreatLevel.SAFE

    def _calculate_confidence(self, ai_score: float, reputation_score: float,
                              signature_info: Dict) -> float:
        """Calculate detection confidence"""
        confidence = 0.5

        if ai_score > 0.7:
            confidence += 0.3
        elif ai_score > 0.5:
            confidence += 0.2

        if signature_info.get('is_signed'):
            confidence += 0.1

        if reputation_score > 0.7 or reputation_score < 0.3:
            confidence += 0.1

        return min(1.0, confidence)

    def get_statistics(self) -> Dict[str, Any]:
        """Get scan statistics"""
        return self.stats.copy()

    def scan(self, mode="quick", paths=None, batch_mode=False):
        """
        Main scan method that supports different scan modes

        Args:
            mode: 'quick', 'full', 'custom' as string or ScanMode enum
            paths: List of paths for custom mode
            batch_mode: If True, returns list of results

        Returns:
            List of ScanResult objects
        """
        # Normalize mode (handle both string and enum)
        if hasattr(mode, 'value'):
            mode_str = mode.value.lower()
        elif hasattr(mode, 'name'):
            mode_str = mode.name.lower()
        else:
            mode_str = str(mode).lower()

        # Build target paths based on mode
        targets = []
        if paths:
            targets = paths
        else:
            if mode_str == "quick":
                # Quick scan - common user directories and high-risk locations
                user_profile = os.environ.get("USERPROFILE") or os.path.expanduser("~")
                if user_profile:
                    downloads = os.path.join(user_profile, "Downloads")
                    desktop = os.path.join(user_profile, "Desktop")
                    documents = os.path.join(user_profile, "Documents")
                    targets.extend([downloads, desktop, documents])

                temp = os.environ.get("TEMP") or os.environ.get("TMP")
                if temp:
                    targets.append(temp)

                # Filter to only existing paths
                targets = [p for p in targets if p and os.path.exists(p)]

            elif mode_str == "full":
                # Full scan - entire system drive
                drive = os.path.splitdrive(os.path.abspath(os.sep))[0] + os.sep
                if not drive:
                    drive = os.path.abspath(os.sep)
                targets = [drive]

        # Build file list based on mode
        file_list = []

        if mode_str == "quick":
            # Quick scan - only scan executable and script files
            risky_extensions = {'.exe', '.dll', '.sys', '.scr', '.js', '.vbs',
                                '.bat', '.cmd', '.ps1', '.py', '.msi', '.jar'}

            for target in targets:
                if os.path.isfile(target):
                    if os.path.splitext(target)[1].lower() in risky_extensions:
                        file_list.append(target)
                    continue

                for root, _, files in os.walk(target):
                    for filename in files:
                        if os.path.splitext(filename)[1].lower() in risky_extensions:
                            file_list.append(os.path.join(root, filename))

        else:
            # Full or custom scan - scan all files
            exclude_dirs = {
                'System32', 'SysWOW64', 'WinSxS', '$Recycle.Bin',
                'Program Files', 'Program Files (x86)', 'Windows'
            }

            for target in targets:
                if os.path.isfile(target):
                    file_list.append(target)
                    continue

                for root, dirs, files in os.walk(target):
                    # Skip excluded directories
                    dirs[:] = [d for d in dirs if d not in exclude_dirs]

                    for filename in files:
                        file_list.append(os.path.join(root, filename))

        total_files = len(file_list)
        if total_files == 0:
            # Call completion callback
            if self.callbacks.get('on_scan_complete'):
                try:
                    self.callbacks['on_scan_complete']([])
                except Exception:
                    pass
            return []

        # Scan files
        results = []
        scanned = 0

        for file_path in file_list:
            try:
                # Calculate hash
                file_hash = self._calculate_hash(file_path)

                # Check if we should skip this file (hash-based caching)
                should_skip = False
                if self.db:
                    try:
                        existing_hash = self.db.get_file_hash(file_path)
                        if existing_hash == file_hash:
                            should_skip = True
                    except Exception:
                        pass

                if should_skip:
                    # File unchanged, skip scan
                    scanned += 1

                    # Update progress
                    if self.callbacks.get('on_scan_progress'):
                        try:
                            progress = (scanned / total_files) * 100
                            self.callbacks['on_scan_progress'](
                                progress, scanned, total_files,
                                total_files - scanned, file_path
                            )
                        except Exception:
                            pass
                    continue

                # Perform full scan
                result = self.scan_file(file_path)
                if result:
                    results.append(result)

                    # Call threat detected callback if needed
                    if result.threat_level != ThreatLevel.SAFE:
                        if self.callbacks.get('on_threat_detected'):
                            try:
                                self.callbacks['on_threat_detected'](result)
                            except Exception:
                                pass

                scanned += 1

                # Update progress
                if self.callbacks.get('on_scan_progress'):
                    try:
                        progress = (scanned / total_files) * 100
                        self.callbacks['on_scan_progress'](
                            progress, scanned, total_files,
                            total_files - scanned, file_path
                        )
                    except Exception:
                        pass

            except Exception as e:
                logger.error(f"Error scanning {file_path}: {e}")
                scanned += 1
                continue

        # Call completion callback
        if self.callbacks.get('on_scan_complete'):
            try:
                self.callbacks['on_scan_complete'](results)
            except Exception:
                pass

        return results

    def get_threat_report(self):
        """Get list of detected threats"""
        # This returns threats from the most recent scan
        # For now, return empty list (threats are stored in database)
        return []

    def scan_paths(self, paths):
        """
        Scan specified paths (wrapper method for compatibility)

        Args:
            paths: List of file or directory paths to scan

        Returns:
            List of ScanResult objects
        """
        return self.scan(mode="custom", paths=paths)
