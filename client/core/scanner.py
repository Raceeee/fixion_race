"""
scanner.py - Complete Fixed Integrated OptimizedAntivirusScanner for Fixion
All integration issues resolved, proper error handling, and path fixes
"""

import os
import time
import threading
import queue
import hashlib
import pickle
import numpy as np
from pathlib import Path
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import concurrent.futures
import logging

# Import all the integrated components with error handling
try:
    from client.config import get_config, get_logger
except ImportError:
    def get_config(key, default=None):
        return default
    def get_logger(name):
        return logging.getLogger(name)

# Import joblib at module level
try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False
    print("Warning: joblib not installed. Run: pip install joblib")

# YARA TEMPORARILY DISABLED
class YaraScanner:
    def __init__(self):
        self.rules_loaded = False
    def load_rules(self):
        return False
    def scan_file(self, file_path):
        return {'matches': [], 'error': 'YARA temporarily disabled'}
    def get_statistics(self):
        return {'status': 'disabled'}

try:
    from client.sandbox_analyzer import WindowsSandboxAnalyzer
except ImportError:
    class WindowsSandboxAnalyzer:
        def __init__(self):
            self.sandbox_available = False
        def analyze_file_in_sandbox(self, file_path):
            return {'analysis_complete': False, 'error': 'Sandbox not available'}

try:
    from client.dss_engine import DSSEngine
except ImportError:
    class DSSEngine:
        def __init__(self):
            self.rules_loaded = False
        def load_rules(self):
            return False
        def evaluate_file(self, file_path, scan_result):
            return {'matched_rules': [], 'error': 'DSS not available'}

try:
    from client.background_monitor import BackgroundFileMonitor
except ImportError:
    class BackgroundFileMonitor:
        def __init__(self):
            self.monitoring = False
        def start_monitoring(self):
            pass
        def stop_monitoring(self):
            pass

try:
    from client.network_monitor import NetworkMonitor
except ImportError:
    class NetworkMonitor:
        def __init__(self):
            self.monitoring = False
        def start_monitoring(self):
            pass
        def stop_monitoring(self):
            pass

logger = get_logger(__name__)

# Core enums and data structures
class ScanMode(Enum):
    QUICK = "quick"
    SELECTIVE = "selective"
    FULL = "full"
    BACKGROUND = "background"

class ThreatLevel(Enum):
    BENIGN = "benign"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ScanResult:
    file_path: str
    file_size: int
    file_hash: str
    scan_time: float
    threat_level: ThreatLevel
    confidence: float
    ai_score: float
    yara_matches: List[str]
    dss_rules_matched: List[str]
    heuristic_flags: List[str]
    sandbox_result: Dict[str, Any]
    threat_info: Dict[str, Any]
    publisher: Optional[str] = None
    is_signed: bool = False
    signature_valid: bool = False

    def __post_init__(self):
        if self.yara_matches is None:
            self.yara_matches = []
        if self.dss_rules_matched is None:
            self.dss_rules_matched = []
        if self.heuristic_flags is None:
            self.heuristic_flags = []
        if self.sandbox_result is None:
            self.sandbox_result = {}
        if self.threat_info is None:
            self.threat_info = {}

class ScannerCallbacks:
    """Callback interface for scanner events"""
    def __init__(self):
        self.on_file_scan_start: Optional[Callable] = None
        self.on_file_scan_complete: Optional[Callable] = None
        self.on_progress_update: Optional[Callable] = None
        self.on_threat_detected: Optional[Callable] = None
        self.on_scan_complete: Optional[Callable] = None
        self.on_scan_start: Optional[Callable] = None
        self.on_error: Optional[Callable] = None

class WhitelistManager:
    """Simple whitelist manager for trusted files"""
    def __init__(self):
        self.whitelist_file = Path("whitelist.txt")
        self.whitelisted_hashes = set()
        self.trusted_publishers = {
            'microsoft corporation', 'google llc', 'adobe inc.', 'apple inc.',
            'mozilla corporation', 'oracle corporation', 'vmware, inc.',
            'intel corporation', 'nvidia corporation', 'amd inc.'
        }
        self._load_whitelist()

    def _load_whitelist(self):
        """Load whitelist from file"""
        try:
            if self.whitelist_file.exists():
                with open(self.whitelist_file, 'r') as f:
                    self.whitelisted_hashes = set(line.strip() for line in f if line.strip())
        except Exception as e:
            logger.debug(f"Failed to load whitelist: {e}")

    def is_whitelisted(self, file_hash: str, publisher: str = None) -> bool:
        """Check if file is whitelisted"""
        if file_hash in self.whitelisted_hashes:
            return True
        if publisher and publisher.lower() in self.trusted_publishers:
            return True
        return False

    def add_to_whitelist(self, file_hash: str):
        """Add file hash to whitelist"""
        self.whitelisted_hashes.add(file_hash)
        try:
            with open(self.whitelist_file, 'a') as f:
                f.write(f"{file_hash}\n")
        except Exception as e:
            logger.debug(f"Failed to save whitelist: {e}")

class EnhancedEMBERModel:
    """Enhanced EMBER model with integrated components - FIXED VERSION"""

    def __init__(self, model_dir: str = "ai_models/ember_models"):
        # Smart path resolution
        self.model_dir = self._resolve_model_path(model_dir)
        self.model = None
        self.scaler = None
        self.is_loaded = False
        self.whitelist_manager = WhitelistManager()

        # Statistics
        self.stats = {
            'total_predictions': 0,
            'threats_detected': 0,
            'false_positives_prevented': 0,
            'files_whitelisted': 0
        }

    def _resolve_model_path(self, model_dir: str) -> Path:
        """Resolve model path using multiple strategies"""
        possible_paths = [
            Path(model_dir),  # Exact path
            Path.cwd() / model_dir,  # Relative to current directory
            Path(__file__).parent.parent / model_dir,  # Relative to project root
            Path(__file__).parent / model_dir,  # Relative to client directory
        ]

        for path in possible_paths:
            if path.exists() and path.is_dir():
                logger.info(f"Found EMBER model directory: {path}")
                return path

        # If none found, return the first one (will be created if needed)
        logger.warning(f"EMBER model directory not found, using: {possible_paths[0]}")
        return possible_paths[0]

    def load_model(self) -> bool:
        """Load EMBER model and scaler with comprehensive error handling"""
        if not JOBLIB_AVAILABLE:
            logger.error("joblib not available - cannot load EMBER model")
            return False

        try:
            logger.info(f"Looking for EMBER model in: {self.model_dir}")

            if not self.model_dir.exists():
                logger.error(f"Model directory does not exist: {self.model_dir}")
                return False

            # Search for model files with multiple patterns
            model_candidates = []

            # Specific files based on your structure
            specific_files = [
                "ember_advanced_20250914_001213.pkl",
                "ai_models/ember_models/ember_advanced_20250914_001213.pkl"
            ]

            for filename in specific_files:
                candidate = self.model_dir / filename
                if candidate.exists():
                    model_candidates.append(candidate)

            # Search recursively for any .pkl files that aren't scalers
            for pkl_file in self.model_dir.rglob("*.pkl"):
                if pkl_file.is_file() and 'scaler' not in pkl_file.name.lower():
                    model_candidates.append(pkl_file)

            if not model_candidates:
                logger.error(f"No EMBER model files found in {self.model_dir}")
                self._list_available_files()
                return False

            # Try to load the first valid model
            model_loaded = False
            for model_file in model_candidates:
                try:
                    logger.info(f"Attempting to load: {model_file}")
                    self.model = joblib.load(model_file)
                    logger.info(f"Successfully loaded model: {model_file.name}")
                    model_loaded = True
                    break
                except Exception as e:
                    logger.warning(f"Failed to load {model_file.name}: {e}")
                    continue

            if not model_loaded:
                logger.error("Failed to load any EMBER model files")
                return False

            # Load scaler
            self._load_scaler()

            # Test the model
            if not self._test_model():
                logger.error("Model test failed")
                return False

            self.is_loaded = True
            logger.info("EMBER model loaded and tested successfully")
            return True

        except Exception as e:
            logger.error(f"Error loading EMBER model: {e}")
            return False

    def _load_scaler(self):
        """Load the scaler file"""
        scaler_candidates = []

        # Specific scaler files
        specific_scalers = [
            "ember_advanced_20250914_001213_scaler.pkl",
            "trained_models/ember_advanced_20250914_001213_scaler.pkl"
        ]

        for filename in specific_scalers:
            candidate = self.model_dir / filename
            if candidate.exists():
                scaler_candidates.append(candidate)

        # Search for any scaler files
        for scaler_file in self.model_dir.rglob("*scaler*.pkl"):
            if scaler_file.is_file():
                scaler_candidates.append(scaler_file)

        for scaler_file in scaler_candidates:
            try:
                self.scaler = joblib.load(scaler_file)
                logger.info(f"Scaler loaded: {scaler_file.name}")
                return
            except Exception as e:
                logger.warning(f"Failed to load scaler {scaler_file.name}: {e}")
                continue

        logger.warning("No scaler file found - predictions may be less accurate")

    def _test_model(self) -> bool:
        """Test the loaded model"""
        try:
            test_features = np.zeros((1, 2381))  # EMBER standard

            if hasattr(self.model, 'predict_proba'):
                test_pred = self.model.predict_proba(test_features)
                logger.debug(f"Model test (predict_proba): {test_pred.shape}")
            elif hasattr(self.model, 'predict'):
                test_pred = self.model.predict(test_features)
                logger.debug(f"Model test (predict): {test_pred.shape}")
            else:
                logger.error("Model has no predict methods")
                return False

            return True
        except Exception as e:
            logger.error(f"Model test failed: {e}")
            return False

    def _list_available_files(self):
        """List available files for debugging"""
        try:
            if self.model_dir.exists():
                files = list(self.model_dir.rglob("*"))
                logger.info("Available files in model directory:")
                for file in files[:10]:  # Limit to first 10
                    if file.is_file():
                        logger.info(f"  - {file.relative_to(self.model_dir)}")
        except Exception as e:
            logger.debug(f"Could not list files: {e}")

    def extract_features(self, file_path: str) -> Optional[np.ndarray]:
        """Extract basic features from file for EMBER model"""
        try:
            if not os.path.exists(file_path):
                return None

            file_size = os.path.getsize(file_path)
            if file_size == 0:
                return None

            # Read file with size limit
            max_read_size = min(10 * 1024 * 1024, file_size)
            with open(file_path, 'rb') as f:
                file_bytes = f.read(max_read_size)

            if len(file_bytes) == 0:
                return None

            # Basic feature extraction
            features = []

            # File size features
            features.append(len(file_bytes))
            features.append(len(file_bytes) / 1024)

            # Byte histogram (256 features)
            byte_hist = np.bincount(np.frombuffer(file_bytes, dtype=np.uint8), minlength=256)
            byte_hist = byte_hist / len(file_bytes) if len(file_bytes) > 0 else byte_hist
            features.extend(byte_hist.tolist())

            # Entropy calculation
            probabilities = byte_hist[byte_hist > 0]
            entropy = -np.sum(probabilities * np.log2(probabilities)) if len(probabilities) > 0 else 0
            features.append(entropy)

            # String features
            printable_count = sum(1 for b in file_bytes[:1000] if 32 <= b <= 126)
            features.append(printable_count / min(1000, len(file_bytes)))

            # Magic bytes detection
            magic_signatures = {
                b'MZ': 1,  # PE
                b'\x7fELF': 2,  # ELF
                b'PK': 3,  # ZIP
                b'\x89PNG': 4,  # PNG
            }

            magic_feature = 0
            for magic, value in magic_signatures.items():
                if file_bytes.startswith(magic):
                    magic_feature = value
                    break
            features.append(magic_feature)

            # Pad to expected feature count
            target_features = 2381  # EMBER standard
            if len(features) < target_features:
                features.extend([0] * (target_features - len(features)))
            else:
                features = features[:target_features]

            return np.array(features).reshape(1, -1)

        except Exception as e:
            logger.debug(f"Feature extraction failed for {file_path}: {e}")
            return None

    def predict(self, file_path: str) -> float:
        """Get malware prediction score"""
        if not self.is_loaded:
            return 0.0

        try:
            # Extract features
            features = self.extract_features(file_path)
            if features is None:
                return 0.0

            # Scale features if scaler available
            if self.scaler:
                features = self.scaler.transform(features)

            # Get prediction
            if hasattr(self.model, 'predict_proba'):
                prediction = self.model.predict_proba(features)[0]
                score = float(prediction[1]) if len(prediction) > 1 else float(prediction[0])
            else:
                prediction = self.model.predict(features)[0]
                score = float(prediction)

            # Ensure score is between 0 and 1
            score = max(0.0, min(1.0, score))

            self.stats['total_predictions'] += 1
            if score > 0.5:
                self.stats['threats_detected'] += 1

            return score

        except Exception as e:
            logger.debug(f"EMBER prediction failed for {file_path}: {e}")
            return 0.0

    def predict_with_context(self, file_path: str, file_hash: str) -> Dict[str, Any]:
        """Enhanced prediction with additional context"""
        score = self.predict(file_path)

        return {
            'score': score,
            'threat_detected': score > 0.5,
            'confidence': min(score * 2, 1.0) if score > 0.5 else (1 - score) * 2,
            'reputation_score': 1 - score,
            'file_hash': file_hash,
            'prediction_method': 'ember_ai'
        }

class OptimizedAntivirusScanner:
    """Complete integrated antivirus scanner - FIXED VERSION"""

    # File extensions to skip for performance
    SKIP_EXTENSIONS = {
        '.txt', '.log', '.md', '.json', '.xml', '.csv', '.dat',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.svg',
        '.mp3', '.wav', '.mp4', '.avi', '.mkv', '.mov', '.wmv',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx'
    }

    # High priority extensions for quick scan
    HIGH_PRIORITY_EXTENSIONS = {
        '.exe', '.dll', '.sys', '.com', '.scr', '.pif', '.bat', '.cmd',
        '.msi', '.jar', '.app', '.deb', '.rpm', '.dmg', '.pkg',
        '.js', '.vbs', '.ps1', '.py', '.pl', '.sh', '.php'
    }

    def __init__(self, ember_model_dir: str = "ai_models/ember_models", max_workers: int = 4):
        # Core scanner state
        self._scanning = False
        self._paused = False
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()

        # Progress tracking
        self._total_files = 0
        self._scanned_files = 0
        self._current_file = ""
        self._scan_results = []
        self._files_remaining = 0

        # Configuration
        self.max_workers = max_workers
        self.max_file_size_mb = get_config('scanner.max_file_size_mb', 100)

        # Callback system
        self.callbacks = ScannerCallbacks()

        # Thread safety
        self._lock = threading.Lock()
        self._progress_lock = threading.Lock()

        # Initialize all integrated components
        logger.info("Initializing OptimizedAntivirusScanner...")

        # EMBER AI Model
        self.ember_model = EnhancedEMBERModel(ember_model_dir)

        # YARA Scanner - TEMPORARILY DISABLED
        self.yara_scanner = YaraScanner()

        # Sandbox Analyzer
        self.sandbox_analyzer = WindowsSandboxAnalyzer()

        # DSS Engine
        self.dss_engine = DSSEngine()

        # Background File Monitor
        self.background_monitor = BackgroundFileMonitor()

        # Network Monitor
        self.network_monitor = NetworkMonitor()

        # Load all components
        self._initialize_components()

        # Statistics
        self.stats = {
            'total_scans': 0,
            'threats_found': 0,
            'files_scanned': 0,
            'scan_time_total': 0.0,
            'cache_hits': 0,
            'cache_misses': 0
        }

        logger.info("OptimizedAntivirusScanner initialized")

    def _initialize_components(self):
        """Initialize and load all scanner components"""

        # Load EMBER model
        print("Loading EMBER AI model...")
        if self.ember_model.load_model():
            print("✓ EMBER model loaded successfully")
        else:
            print("✗ EMBER model not available - AI detection disabled")

        # YARA rules - TEMPORARILY DISABLED
        print("✗ YARA Scanner temporarily disabled")

        # Initialize DSS engine
        print("Loading DSS rules...")
        if self.dss_engine.load_rules():
            print("✓ DSS rules loaded successfully")
        else:
            print("✗ DSS rules not available")

        # Check sandbox availability
        if hasattr(self.sandbox_analyzer, 'sandbox_available') and self.sandbox_analyzer.sandbox_available:
            print("✓ Windows Sandbox available")
        else:
            print("✗ Windows Sandbox not available")

        print("Scanner initialization complete!")

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.debug(f"Failed to hash {file_path}: {e}")
            return ""

    def _get_file_signature_info(self, file_path: str) -> Dict[str, Any]:
        """Get file signature information"""
        try:
            import subprocess
            result = subprocess.run([
                'powershell', '-Command',
                f'Get-AuthenticodeSignature "{file_path}" | Select-Object Status, SignerCertificate'
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                output = result.stdout.strip()
                is_signed = 'Valid' in output
                return {
                    'is_signed': is_signed,
                    'signature_valid': is_signed,
                    'publisher': 'Unknown'
                }
        except Exception as e:
            logger.debug(f"Signature check failed for {file_path}: {e}")

        return {'is_signed': False, 'signature_valid': False, 'publisher': None}

    def _perform_heuristic_analysis(self, file_path: str) -> List[str]:
        """Perform heuristic analysis"""
        flags = []

        try:
            # File size analysis
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                flags.append("zero_byte_file")
            elif file_size > 500 * 1024 * 1024:  # 500MB
                flags.append("unusually_large_file")

            # Extension analysis
            file_ext = Path(file_path).suffix.lower()
            if file_ext in self.HIGH_PRIORITY_EXTENSIONS:
                flags.append("executable_file")

            # Content analysis
            with open(file_path, 'rb') as f:
                header = f.read(1024)

            # Check for suspicious strings
            suspicious_patterns = [
                b'CreateRemoteThread', b'WriteProcessMemory', b'VirtualAllocEx',
                b'SetWindowsHookEx', b'keylogger', b'backdoor', b'trojan'
            ]

            for pattern in suspicious_patterns:
                if pattern in header:
                    flags.append(f"suspicious_api_{pattern.decode('utf-8', errors='ignore')}")

            # PE header check
            if header.startswith(b'MZ'):
                flags.append("pe_executable")

        except Exception as e:
            logger.debug(f"Heuristic analysis failed for {file_path}: {e}")
            flags.append("analysis_error")

        return flags

    def _classify_threat_level(self, ai_score: float, yara_matches: List[str],
                             dss_matches: List[str], heuristic_flags: List[str],
                             signature_info: Dict[str, Any], file_hash: str = "") -> ThreatLevel:
        """Classify overall threat level - FIXED VERSION"""

        # Check whitelist first
        if file_hash and hasattr(self.ember_model, 'whitelist_manager'):
            if self.ember_model.whitelist_manager.is_whitelisted(file_hash, signature_info.get('publisher')):
                return ThreatLevel.BENIGN

        # DSS rule matches
        if dss_matches:
            return ThreatLevel.MEDIUM

        # AI score classification with context
        if signature_info.get('is_signed') and signature_info.get('signature_valid'):
            # Be more lenient with signed files
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

        return ThreatLevel.BENIGN

    def _scan_file_comprehensive(self, file_path: str) -> Optional[ScanResult]:
        """Comprehensive file scanning - FIXED VERSION"""
        start_time = time.time()

        try:
            # Basic file checks
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return None

            file_size = os.path.getsize(file_path)
            if file_size > self.max_file_size_mb * 1024 * 1024:
                logger.debug(f"Skipping large file: {file_path}")
                return None

            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)

            # Get signature information
            signature_info = self._get_file_signature_info(file_path)

            # AI Analysis (EMBER)
            ai_score = 0.0
            if self.ember_model.is_loaded:
                ai_score = self.ember_model.predict(file_path)

            # YARA Analysis - TEMPORARILY DISABLED
            yara_matches = []

            # DSS Analysis - FIXED METHOD CALL
            dss_matches = []
            if hasattr(self.dss_engine, 'rules_loaded') and self.dss_engine.rules_loaded:
                try:
                    # Create a mock scan result for DSS evaluation
                    mock_result = type('MockResult', (), {
                        'file_path': file_path,
                        'file_size': file_size,
                        'ai_score': ai_score,
                        'threat_level': 'unknown',
                        'yara_matches': [],
                        'file_hash': file_hash
                    })()

                    # Use evaluate_file method
                    dss_result = self.dss_engine.evaluate_file(file_path, mock_result)
                    if 'matched_rules' in dss_result:
                        dss_matches = dss_result['matched_rules']
                    elif 'recommended_actions' in dss_result:
                        dss_matches = [action.reason for action in dss_result['recommended_actions']]
                except Exception as e:
                    logger.debug(f"DSS analysis failed: {e}")
                    dss_matches = []

            # Heuristic Analysis
            heuristic_flags = self._perform_heuristic_analysis(file_path)

            # Sandbox Analysis (for suspicious files only)
            sandbox_result = {}
            threat_level_preliminary = self._classify_threat_level(
                ai_score, yara_matches, dss_matches, heuristic_flags, signature_info, file_hash
            )

            if (threat_level_preliminary in [ThreatLevel.MEDIUM, ThreatLevel.HIGH] and
                hasattr(self.sandbox_analyzer, 'sandbox_available') and
                self.sandbox_analyzer.sandbox_available):
                try:
                    sandbox_result = self.sandbox_analyzer.analyze_file_in_sandbox(file_path)
                except Exception as e:
                    logger.debug(f"Sandbox analysis failed: {e}")
                    sandbox_result = {'error': str(e)}

            # Final threat classification
            threat_level = self._classify_threat_level(
                ai_score, yara_matches, dss_matches, heuristic_flags, signature_info, file_hash
            )

            # Calculate confidence
            confidence = 0.5
            if ai_score > 0.5:
                confidence += 0.2
            if signature_info.get('is_signed'):
                confidence += 0.1
            confidence = min(confidence, 1.0)

            # Build threat info
            threat_info = {
                'ai_analysis': {'score': ai_score, 'threshold_exceeded': ai_score > 0.5},
                'yara_analysis': {'matches': yara_matches, 'rules_triggered': len(yara_matches), 'status': 'disabled'},
                'dss_analysis': {'matches': dss_matches, 'rules_triggered': len(dss_matches)},
                'heuristic_analysis': {'flags': heuristic_flags, 'suspicious_count': len(heuristic_flags)},
                'signature_analysis': signature_info
            }

            scan_time = time.time() - start_time

            # Create result
            result = ScanResult(
                file_path=file_path,
                file_size=file_size,
                file_hash=file_hash,
                scan_time=scan_time,
                threat_level=threat_level,
                confidence=confidence,
                ai_score=ai_score,
                yara_matches=yara_matches,
                dss_rules_matched=dss_matches,
                heuristic_flags=heuristic_flags,
                sandbox_result=sandbox_result,
                threat_info=threat_info,
                publisher=signature_info.get('publisher'),
                is_signed=signature_info.get('is_signed', False),
                signature_valid=signature_info.get('signature_valid', False)
            )

            # Update statistics
            self.stats['files_scanned'] += 1
            self.stats['scan_time_total'] += scan_time
            if threat_level != ThreatLevel.BENIGN:
                self.stats['threats_found'] += 1

            # Update progress
            with self._progress_lock:
                self._scanned_files += 1
                self._files_remaining = max(0, self._files_remaining - 1)
                self._current_file = file_path

            # Callbacks - FIXED PARAMETERS
            if self.callbacks.on_progress_update:
                progress_percent = (self._scanned_files / max(1, self._total_files)) * 100
                self.callbacks.on_progress_update(
                    progress_percent, self._scanned_files, self._total_files,
                    self._files_remaining, file_path
                )

            if threat_level != ThreatLevel.BENIGN and self.callbacks.on_threat_detected:
                self.callbacks.on_threat_detected(result)

            if self.callbacks.on_file_scan_complete:
                self.callbacks.on_file_scan_complete(result)

            return result

        except Exception as e:
            logger.error(f"Error scanning {file_path}: {e}")
            if self.callbacks.on_error:
                self.callbacks.on_error(f"Error scanning {file_path}: {e}")
            return None

    def _collect_files_to_scan(self, mode: ScanMode, paths: List[str] = None) -> List[str]:
        """Collect files to scan based on mode"""
        files_to_scan = []

        if paths:
            # Scan specific paths
            for path in paths:
                if os.path.isfile(path):
                    files_to_scan.append(path)
                elif os.path.isdir(path):
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            # Skip files based on extension for performance
                            if mode == ScanMode.QUICK:
                                ext = Path(file_path).suffix.lower()
                                if ext in self.SKIP_EXTENSIONS:
                                    continue
                            files_to_scan.append(file_path)
        else:
            # Default scan locations based on mode
            if mode == ScanMode.QUICK:
                scan_dirs = [
                    os.path.expanduser("~/Downloads"),
                    os.path.expanduser("~/Desktop"),
                    os.environ.get("TEMP", "C:/Windows/Temp")
                ]
            elif mode == ScanMode.FULL:
                scan_dirs = ["C:/"] if os.name == 'nt' else ["/"]
            else:  # SELECTIVE
                scan_dirs = [os.path.expanduser("~")]

            for scan_dir in scan_dirs:
                if os.path.exists(scan_dir):
                    try:
                        for root, dirs, files in os.walk(scan_dir):
                            # Skip system directories for non-full scans
                            if mode != ScanMode.FULL and os.name == 'nt':
                                skip_dirs = ['Windows', 'Program Files', 'Program Files (x86)']
                                if any(skip_dir in root for skip_dir in skip_dirs):
                                    continue

                            for file in files:
                                file_path = os.path.join(root, file)
                                if mode == ScanMode.QUICK:
                                    ext = Path(file_path).suffix.lower()
                                    if ext in self.SKIP_EXTENSIONS:
                                        continue
                                files_to_scan.append(file_path)
                    except PermissionError:
                        logger.debug(f"Permission denied: {scan_dir}")
                        continue

        return files_to_scan

    def _worker_thread(self, file_queue: queue.Queue, results_queue: queue.Queue):
        """Worker thread for file scanning"""
        while not self._stop_event.is_set():
            try:
                file_path = file_queue.get(timeout=0.1)
                if file_path is None:
                    break

                # Wait if paused
                self._pause_event.wait()

                result = self._scan_file_comprehensive(file_path)
                if result:
                    results_queue.put(result)

                file_queue.task_done()
                time.sleep(0.001)  # Prevent UI freezing

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker thread error: {e}")
                if self.callbacks.on_error:
                    self.callbacks.on_error(f"Worker thread error: {e}")

    def scan(self, mode: ScanMode = ScanMode.QUICK, paths: List[str] = None) -> List[ScanResult]:
        """Start comprehensive scanning"""
        if self._scanning:
            raise RuntimeError("Scan already in progress")

        self._scanning = True
        self._stop_event.clear()
        self._scan_results = []
        self._scanned_files = 0

        try:
            # Collect files
            files_to_scan = self._collect_files_to_scan(mode, paths)
            self._total_files = len(files_to_scan)
            self._files_remaining = self._total_files

            if self._total_files == 0:
                logger.info("No files found to scan")
                return []

            logger.info(f"Starting {mode.value} scan of {self._total_files} files")

            if self.callbacks.on_scan_start:
                self.callbacks.on_scan_start(mode, self._total_files)

            # Create queues
            file_queue = queue.Queue()
            results_queue = queue.Queue()

            # Add files to queue
            for file_path in files_to_scan:
                file_queue.put(file_path)

            # Add sentinel values for workers
            for _ in range(self.max_workers):
                file_queue.put(None)

            # Start worker threads
            workers = []
            for _ in range(min(self.max_workers, self._total_files)):
                worker = threading.Thread(
                    target=self._worker_thread,
                    args=(file_queue, results_queue)
                )
                worker.daemon = True
                worker.start()
                workers.append(worker)

            # Collect results
            while any(w.is_alive() for w in workers) or not results_queue.empty():
                try:
                    result = results_queue.get(timeout=0.1)
                    self._scan_results.append(result)
                except queue.Empty:
                    continue

                if self._stop_event.is_set():
                    break

            # Wait for workers to complete
            for worker in workers:
                worker.join(timeout=1.0)

            self.stats['total_scans'] += 1
            logger.info(f"Scan completed. {len(self._scan_results)} files processed")

            if self.callbacks.on_scan_complete:
                self.callbacks.on_scan_complete(self._scan_results)

            return self._scan_results

        except Exception as e:
            logger.error(f"Scan error: {e}")
            if self.callbacks.on_error:
                self.callbacks.on_error(f"Scan error: {e}")
            return []
        finally:
            self._scanning = False

    def stop_scan(self):
        """Stop current scan"""
        if self._scanning:
            self._stop_event.set()
            logger.info("Scan stop requested")

    def pause_scan(self):
        """Pause current scan"""
        if self._scanning:
            self._paused = True
            self._pause_event.clear()
            logger.info("Scan paused")

    def resume_scan(self):
        """Resume paused scan"""
        if self._scanning and self._paused:
            self._paused = False
            self._pause_event.set()
            logger.info("Scan resumed")

    def scan_single_file(self, file_path: str) -> Optional[ScanResult]:
        """Scan a single file"""
        return self._scan_file_comprehensive(file_path)

    def get_status(self) -> Dict[str, Any]:
        """Get current scanner status"""
        return {
            'scanning': self._scanning,
            'paused': self._paused,
            'total_files': self._total_files,
            'scanned_files': self._scanned_files,
            'files_remaining': self._files_remaining,
            'current_file': self._current_file,
            'threats_found': len([r for r in self._scan_results if r.threat_level != ThreatLevel.BENIGN]),
            'components_status': {
                'ember_loaded': self.ember_model.is_loaded,
                'yara_loaded': False,  # DISABLED
                'dss_loaded': self.dss_engine.rules_loaded,
                'sandbox_available': getattr(self.sandbox_analyzer, 'sandbox_available', False),
                'background_monitor': getattr(self.background_monitor, 'monitoring', False),
                'network_monitor': getattr(self.network_monitor, 'monitoring', False)
            },
            'statistics': self.stats
        }

    def get_scan_results(self) -> List[ScanResult]:
        """Get current scan results"""
        return self._scan_results.copy()

    def start_background_monitoring(self):
        """Start background file monitoring"""
        try:
            if hasattr(self.background_monitor, 'start_monitoring'):
                self.background_monitor.start_monitoring()
            logger.info("Background file monitoring started")
        except Exception as e:
            logger.error(f"Failed to start background monitoring: {e}")

    def stop_background_monitoring(self):
        """Stop background file monitoring"""
        try:
            if hasattr(self.background_monitor, 'stop_monitoring'):
                self.background_monitor.stop_monitoring()
            logger.info("Background file monitoring stopped")
        except Exception as e:
            logger.error(f"Failed to stop background monitoring: {e}")

    def start_network_monitoring(self):
        """Start network monitoring"""
        try:
            if hasattr(self.network_monitor, 'start_monitoring'):
                self.network_monitor.start_monitoring()
            logger.info("Network monitoring started")
        except Exception as e:
            logger.error(f"Failed to start network monitoring: {e}")

    def stop_network_monitoring(self):
        """Stop network monitoring"""
        try:
            if hasattr(self.network_monitor, 'stop_monitoring'):
                self.network_monitor.stop_monitoring()
            logger.info("Network monitoring stopped")
        except Exception as e:
            logger.error(f"Failed to stop network monitoring: {e}")

    def get_component_status(self) -> Dict[str, Any]:
        """Get status of all integrated components"""
        try:
            ember_loaded = hasattr(self.ember_model, 'is_loaded') and self.ember_model.is_loaded
            sandbox_available = hasattr(self.sandbox_analyzer, 'sandbox_available') and self.sandbox_analyzer.sandbox_available
            dss_loaded = hasattr(self.dss_engine, 'rules_loaded') and self.dss_engine.rules_loaded
            bg_monitoring = hasattr(self.background_monitor, 'monitoring') and self.background_monitor.monitoring
            net_monitoring = hasattr(self.network_monitor, 'monitoring') and self.network_monitor.monitoring

            return {
                'ember_model': {
                    'loaded': ember_loaded,
                    'model_path': str(self.ember_model.model_dir) if hasattr(self.ember_model, 'model_dir') else 'N/A',
                    'statistics': getattr(self.ember_model, 'stats', {})
                },
                'yara_scanner': {
                    'rules_loaded': False,  # DISABLED
                    'status': 'Temporarily disabled',
                    'statistics': {'status': 'disabled'}
                },
                'sandbox_analyzer': {
                    'available': sandbox_available,
                    'status': 'Available' if sandbox_available else 'Not Available'
                },
                'dss_engine': {
                    'rules_loaded': dss_loaded,
                    'status': 'Active' if dss_loaded else 'Inactive'
                },
                'background_monitor': {
                    'monitoring': bg_monitoring,
                    'status': 'Running' if bg_monitoring else 'Stopped'
                },
                'network_monitor': {
                    'monitoring': net_monitoring,
                    'status': 'Running' if net_monitoring else 'Stopped'
                }
            }
        except Exception as e:
            logger.error(f"Error getting component status: {e}")
            return {}

    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary of detected threats"""
        threats = [r for r in self._scan_results if r.threat_level != ThreatLevel.BENIGN]

        threat_by_level = {}
        for level in ThreatLevel:
            threat_by_level[level.value] = len([t for t in threats if t.threat_level == level])

        threat_by_type = {
            'yara_detections': 0,  # DISABLED
            'ai_detections': len([t for t in threats if t.ai_score > 0.5]),
            'dss_detections': len([t for t in threats if t.dss_rules_matched]),
            'sandbox_detections': len([t for t in threats if t.sandbox_result.get('malicious', False)])
        }

        return {
            'total_threats': len(threats),
            'threat_by_level': threat_by_level,
            'threat_by_detection_method': threat_by_type,
            'recent_threats': [
                {
                    'file_path': t.file_path,
                    'threat_level': t.threat_level.value,
                    'confidence': t.confidence,
                    'detection_methods': []
                }
                for t in threats[-10:]  # Last 10 threats
            ]
        }

    def export_scan_report(self, output_file: str = None) -> Dict[str, Any]:
        """Export detailed scan report"""
        if output_file is None:
            output_file = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'scan_metadata': {
                'scan_time': datetime.now().isoformat(),
                'scanner_version': '1.0.0',
                'total_files_scanned': self._scanned_files,
                'total_scan_time': self.stats['scan_time_total'],
                'avg_scan_time_per_file': self.stats['scan_time_total'] / max(1, self._scanned_files),
                'yara_status': 'disabled'
            },
            'component_status': self.get_component_status(),
            'threat_summary': self.get_threat_summary(),
            'detailed_results': [
                {
                    'file_path': r.file_path,
                    'file_size': r.file_size,
                    'file_hash': r.file_hash,
                    'threat_level': r.threat_level.value,
                    'confidence': r.confidence,
                    'ai_score': r.ai_score,
                    'yara_matches': [],  # DISABLED
                    'dss_matches': r.dss_rules_matched,
                    'heuristic_flags': r.heuristic_flags,
                    'is_signed': r.is_signed,
                    'publisher': r.publisher,
                    'scan_time': r.scan_time
                }
                for r in self._scan_results
            ],
            'statistics': self.stats
        }

        try:
            import json
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Scan report exported to: {output_file}")
        except Exception as e:
            logger.error(f"Failed to export report: {e}")

        return report


# Demo and testing functions
def demo_complete_scanner():
    """Comprehensive demo of all scanner features"""
    print("FIXION COMPLETE INTEGRATED SCANNER DEMO")
    print("=" * 70)

    # Initialize scanner
    print("\n1. Initializing Complete Scanner...")
    scanner = OptimizedAntivirusScanner()

    # Show component status
    status = scanner.get_component_status()
    print(f"\nComponent Status:")
    for component, info in status.items():
        if isinstance(info, dict):
            main_status = info.get('loaded', info.get('available', info.get('monitoring', info.get('status', 'Unknown'))))
            print(f"   {component}: {main_status}")
        else:
            print(f"   {component}: {info}")

    # Test single file scan
    print(f"\n2. Testing Single File Scan...")
    test_files = [
        r"C:\Windows\System32\notepad.exe",
        r"C:\Windows\System32\calc.exe",
        __file__  # This Python file
    ]

    for test_file in test_files:
        if os.path.exists(test_file):
            print(f"\nScanning: {test_file}")
            try:
                result = scanner.scan_single_file(test_file)

                if result:
                    print(f"   ✓ Scan completed in {result.scan_time:.3f}s")
                    print(f"   Threat Level: {result.threat_level.value}")
                    print(f"   AI Score: {result.ai_score:.3f}")
                    print(f"   DSS Matches: {result.dss_rules_matched}")
                    print(f"   Heuristic Flags: {result.heuristic_flags}")
                    print(f"   Signed: {result.is_signed}")
                    if result.publisher:
                        print(f"   Publisher: {result.publisher}")
                else:
                    print(f"   ✗ Scan failed")
            except Exception as e:
                print(f"   ✗ Scan error: {e}")
            break

    # Show final statistics
    final_status = scanner.get_status()
    print(f"\nScanner Statistics:")
    for key, value in final_status['statistics'].items():
        print(f"   - {key}: {value}")

    # Show threat summary
    threat_summary = scanner.get_threat_summary()
    print(f"\nThreat Summary:")
    print(f"   - Total threats: {threat_summary['total_threats']}")
    for level, count in threat_summary['threat_by_level'].items():
        if count > 0:
            print(f"   - {level.upper()}: {count}")

    print(f"\nComplete scanner demo finished!")
    return scanner


# Main execution
if __name__ == "__main__":
    print("FIXION COMPLETE INTEGRATED SCANNER")
    print("=" * 60)

    # Auto-run demo
    print("Running complete integrated scanner demo...")
    demo_complete_scanner()

    print("\n" + "=" * 60)
    print("Demo completed!")
    print("Available functions:")
    print("   - demo_complete_scanner()")
    print("   - OptimizedAntivirusScanner() - Main scanner class")
    print("=" * 60)