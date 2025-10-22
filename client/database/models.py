"""
models.py - Database Models for Fixion 2.0
Defines data structures for database operations
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, Optional, List
from enum import Enum


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ScanStatus(Enum):
    """Scan status types"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanRecord:
    """Represents a scan record"""
    scan_id: str
    scan_type: str
    start_time: str
    end_time: Optional[str] = None
    status: str = ScanStatus.PENDING.value
    total_files: int = 0
    scanned_files: int = 0
    threats_found: int = 0
    scan_paths: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class ThreatReport:
    """Represents a threat detection report"""
    threat_id: str
    file_path: str
    file_hash: str
    threat_level: str
    threat_type: str
    ai_score: float
    detection_time: str
    scan_id: Optional[str] = None
    reputation_score: Optional[float] = None
    sandbox_analysis: Optional[Dict[str, Any]] = None
    action_taken: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class QuarantineEntry:
    """Represents a quarantined file entry"""
    quarantine_id: str
    original_path: str
    quarantine_path: str
    file_hash: str
    quarantine_date: str
    threat_level: str
    threat_type: str
    file_size: int
    status: str = "quarantined"  # quarantined, restored, deleted
    restore_date: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class Snapshot:
    """Represents a system snapshot"""
    snapshot_id: str
    timestamp: str
    is_clean: bool
    restore_point_id: Optional[str] = None
    description: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class WhitelistEntry:
    """Represents a whitelist entry"""
    entry_id: str
    entry_type: str  # hash, publisher, path
    value: str
    reason: str
    added_date: str
    added_by: str = "user"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class ScanStatistics:
    """Represents scan statistics"""
    period: str  # daily, weekly, monthly, all_time
    total_scans: int = 0
    total_files_scanned: int = 0
    total_threats: int = 0
    threats_by_level: Dict[str, int] = field(default_factory=dict)
    threats_by_type: Dict[str, int] = field(default_factory=dict)
    last_scan_date: Optional[str] = None
    last_threat_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class FileAnalysisResult:
    """Complete file analysis result"""
    file_path: str
    file_hash: str
    file_size: int
    scan_time: str

    # AI Analysis
    ai_score: float
    threat_level: str
    threat_type: Optional[str] = None

    # Reputation
    reputation_score: Optional[float] = None
    is_signed: bool = False
    signature_valid: bool = False
    publisher: Optional[str] = None

    # Context
    location_context: Optional[str] = None
    trust_factors: List[str] = field(default_factory=list)
    risk_factors: List[str] = field(default_factory=list)

    # Decision
    final_decision: str = "SAFE"  # SAFE, SUSPICIOUS, THREAT, QUARANTINE
    recommendation: Optional[str] = None

    # Sandbox
    sandbox_analyzed: bool = False
    sandbox_result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class NetworkConnection:
    """Represents a network connection"""
    connection_id: str
    timestamp: str
    process_name: str
    process_path: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    protocol: str
    state: str
    blocked: bool = False
    threat_level: str = "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


@dataclass
class SettingsProfile:
    """User settings profile"""
    profile_name: str
    scan_settings: Dict[str, Any] = field(default_factory=dict)
    protection_settings: Dict[str, Any] = field(default_factory=dict)
    ui_settings: Dict[str, Any] = field(default_factory=dict)
    notification_settings: Dict[str, Any] = field(default_factory=dict)
    created_date: Optional[str] = None
    modified_date: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


# Helper functions
def dict_to_scan_record(data: Dict[str, Any]) -> ScanRecord:
    """Convert dictionary to ScanRecord"""
    return ScanRecord(**data)


def dict_to_threat_report(data: Dict[str, Any]) -> ThreatReport:
    """Convert dictionary to ThreatReport"""
    return ThreatReport(**data)


def dict_to_quarantine_entry(data: Dict[str, Any]) -> QuarantineEntry:
    """Convert dictionary to QuarantineEntry"""
    return QuarantineEntry(**data)


def dict_to_snapshot(data: Dict[str, Any]) -> Snapshot:
    """Convert dictionary to Snapshot"""
    return Snapshot(**data)


def dict_to_file_analysis_result(data: Dict[str, Any]) -> FileAnalysisResult:
    """Convert dictionary to FileAnalysisResult"""
    return FileAnalysisResult(**data)
