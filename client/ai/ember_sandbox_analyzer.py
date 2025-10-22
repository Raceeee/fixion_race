import os
import subprocess
import time
import json
import uuid
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SandboxReport:
    """Comprehensive sandbox analysis report"""
    file_path: str
    analysis_id: str
    timestamp: str

    # Basic info
    file_hash: str
    file_size: int
    file_type: str

    # EMBER intelligence
    ember_score: float
    threat_type: str
    threat_family: Optional[str]
    threat_behaviors: List[Dict[str, Any]]

    # Sandbox observations
    is_malicious: bool
    confidence: float
    verdict: str

    # Behavioral analysis
    processes_created: List[Dict[str, str]] = field(default_factory=list)
    files_created: List[str] = field(default_factory=list)
    files_modified: List[str] = field(default_factory=list)
    files_deleted: List[str] = field(default_factory=list)
    registry_modifications: List[Dict[str, str]] = field(default_factory=list)
    network_connections: List[Dict[str, Any]] = field(default_factory=list)

    # Threat intelligence
    capabilities_observed: List[str] = field(default_factory=list)
    persistence_mechanisms: List[str] = field(default_factory=list)
    anti_analysis_techniques: List[str] = field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    risk_level: str = "UNKNOWN"
    impact_assessment: str = ""

    # Recommendations
    recommended_action: str = ""
    mitigation_steps: List[str] = field(default_factory=list)

    # Technical details
    execution_time: float = 0.0
    sandbox_environment: str = ""
    analysis_notes: List[str] = field(default_factory=list)


class EMBERSandboxAnalyzer:
    """
    Enhanced sandbox analyzer that combines:
    - Windows Sandbox dynamic analysis
    - EMBER AI threat classification
    - Static analysis fallback
    - Comprehensive threat reporting
    """

    def __init__(self, ember_scanner=None, config=None, temp_dir=None):
        self.ember_scanner = ember_scanner
        self.config = config
        self.temp_dir = temp_dir or os.path.join(os.path.expanduser("~"), ".fixion", "sandbox")
        os.makedirs(self.temp_dir, exist_ok=True)

        # Check sandbox availability
        self.sandbox_available = self._check_sandbox()

        # Analysis history
        self.analysis_history = []

        logger.info(f"EMBERSandboxAnalyzer initialized (Sandbox: {self.sandbox_available})")

    def _check_sandbox(self) -> bool:
        """Check if Windows Sandbox is available"""
        if os.name != 'nt':
            return False

        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return 'Enabled' in result.stdout
        except:
            return False

    def analyze_file(self, file_path: str, ember_result=None) -> SandboxReport:
        """
        Comprehensive file analysis combining EMBER intelligence and sandbox execution

        Args:
            file_path: Path to file to analyze
            ember_result: Optional ScanResult from EMBER scanner

        Returns:
            Complete sandbox report with threat intelligence
        """
        analysis_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        logger.info(f"Starting sandbox analysis: {file_path}")

        # Get EMBER analysis if not provided
        if ember_result is None and self.ember_scanner:
            ember_result = self.ember_scanner.scan_file(file_path)

        # Initialize report
        report = SandboxReport(
            file_path=file_path,
            analysis_id=analysis_id,
            timestamp=datetime.now().isoformat(),
            file_hash=self._calculate_hash(file_path),
            file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
            file_type=Path(file_path).suffix,
            ember_score=ember_result.ai_score if ember_result else 0.0,
            threat_type=ember_result.threat_intelligence.threat_type.value if ember_result else "Unknown",
            threat_family=ember_result.threat_intelligence.threat_family if ember_result else None,
            threat_behaviors=[],
            is_malicious=False,
            confidence=0.0,
            verdict="Analyzing..."
        )

        # Extract EMBER intelligence
        if ember_result and ember_result.threat_intelligence:
            intel = ember_result.threat_intelligence

            # Add behaviors
            report.threat_behaviors = [
                {
                    'category': b.category,
                    'description': b.description,
                    'severity': b.severity,
                    'indicators': b.indicators
                }
                for b in intel.behaviors
            ]

            # Add capabilities
            report.capabilities_observed = intel.capabilities.copy()

            # Add persistence mechanisms
            report.persistence_mechanisms = intel.persistence_mechanisms.copy()

            # Add mitigation steps
            report.mitigation_steps = intel.mitigation_steps.copy()

            # Set risk assessment
            report.impact_assessment = intel.risk_assessment

        # Perform appropriate analysis
        if self.sandbox_available:
            logger.info("Performing dynamic sandbox analysis...")
            self._dynamic_analysis(report, file_path)
        else:
            logger.info("Performing static analysis (sandbox unavailable)...")
            self._static_analysis(report, file_path, ember_result)

        # Calculate final risk score
        report.risk_score = self._calculate_risk_score(report)
        report.risk_level = self._classify_risk_level(report.risk_score)

        # Determine verdict
        report.verdict = self._determine_verdict(report)

        # Get recommended action
        report.recommended_action = self._get_recommended_action(report)

        # Finalize
        report.execution_time = time.time() - start_time
        report.sandbox_environment = "Windows Sandbox" if self.sandbox_available else "Static Analysis"

        # Store in history
        self.analysis_history.append(report)

        logger.info(f"Analysis complete: {report.verdict} (confidence: {report.confidence:.2f})")

        return report

    def analyze_single_file(self, file_path: str, parent_window=None):
        """
        Analyze a single file and display results in sandbox report viewer

        Args:
            file_path: Path to file to analyze
            parent_window: Parent window for the report viewer dialog
        """
        import threading
        import customtkinter as ctk
        from client.gui.dialogs.sandbox_report_viewer import SandboxReportViewer

        # Show progress dialog
        progress = ctk.CTkToplevel(parent_window) if parent_window else ctk.CTk()
        progress.title("Analyzing File...")
        progress.geometry("500x200")
        if parent_window:
            progress.transient(parent_window)
            progress.grab_set()

        # Progress info
        info_label = ctk.CTkLabel(
            progress,
            text=f"Analyzing: {os.path.basename(file_path)}",
            font=ctk.CTkFont(size=14)
        )
        info_label.pack(pady=30)

        status_label = ctk.CTkLabel(
            progress,
            text="Performing sandbox analysis...",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        status_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(progress, width=400)
        progress_bar.pack(pady=20)
        progress_bar.set(0)
        progress_bar.start()

        def analyze():
            try:
                # Update status
                status_label.configure(text="Running EMBER analysis...")

                # Perform analysis
                report = self.analyze_file(file_path)

                # Update status
                status_label.configure(text="Generating report...")

                # Close progress dialog
                progress.destroy()

                # Convert SandboxReport to dict for viewer
                from dataclasses import asdict
                report_dict = asdict(report)

                # Format report data for viewer
                viewer_data = {
                    'file_info': {
                        'name': os.path.basename(file_path),
                        'size_mb': round(report.file_size / (1024 * 1024), 2) if report.file_size > 0 else 0,
                        'extension': report.file_type,
                        'sha256': report.file_hash
                    },
                    'execution_status': 'executed' if self.sandbox_available else 'sandbox_unavailable',
                    'verdict': report.verdict.lower().replace(' ', '_').replace(':', ''),
                    'confidence': int(report.confidence * 100),
                    'ai_threat_assessment': {
                        'ai_score': report.ember_score,
                        'threat_level': report.risk_level.lower(),
                        'model': 'EMBER AI Model'
                    },
                    'risk_breakdown': {},
                    'behavior_analysis': {
                        'total_suspicious': len(report.threat_behaviors),
                        'suspicious_behaviors': [
                            {
                                'category': b.get('category', 'unknown'),
                                'severity': b.get('severity', 'unknown'),
                                'description': b.get('description', '')
                            }
                            for b in report.threat_behaviors
                        ]
                    },
                    'network_activity': {
                        'total_connections': len(report.network_connections),
                        'unique_remote_ips': len(set(
                            conn.get('remote_address', '')
                            for conn in report.network_connections
                        )),
                        'connections': report.network_connections
                    },
                    'file_operations': {
                        'total': len(report.files_created) + len(report.files_modified) + len(report.files_deleted),
                        'created': len(report.files_created),
                        'modified': len(report.files_modified),
                        'deleted': len(report.files_deleted),
                        'operations': [
                                          {'action': 'created', 'path': f} for f in report.files_created
                                      ] + [
                                          {'action': 'modified', 'path': f} for f in report.files_modified
                                      ] + [
                                          {'action': 'deleted', 'path': f} for f in report.files_deleted
                                      ]
                    },
                    'timeline': [
                        {
                            'timestamp': report.timestamp,
                            'category': 'detection',
                            'event': f"File analyzed - {report.verdict}"
                        }
                    ],
                    'timestamp': report.timestamp
                }

                # Show report viewer
                viewer = SandboxReportViewer(
                    parent_window if parent_window else progress,
                    viewer_data,
                    os.path.basename(file_path)
                )

            except Exception as e:
                progress.destroy()
                if parent_window:
                    from tkinter import messagebox
                    messagebox.showerror("Analysis Error", f"Failed to analyze file:\n{str(e)}")
                else:
                    print(f"Analysis error: {e}")

        # Start analysis in thread
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()

    def analyze_batch(self, file_paths: List[str], ember_results: List[Any] = None) -> List[SandboxReport]:
        """Analyze multiple files"""
        reports = []

        for i, file_path in enumerate(file_paths):
            ember_result = ember_results[i] if ember_results and i < len(ember_results) else None

            try:
                report = self.analyze_file(file_path, ember_result)
                reports.append(report)
            except Exception as e:
                logger.error(f"Failed to analyze {file_path}: {e}")
                continue

        return reports

    def _dynamic_analysis(self, report: SandboxReport, file_path: str):
        """Perform dynamic sandbox analysis using Windows Sandbox"""
        try:
            import tempfile
            import shutil

            logger.info("Launching Windows Sandbox for dynamic analysis...")

            # Create temporary directory for sandbox files
            sandbox_temp = os.path.join(self.temp_dir, f"sandbox_{report.analysis_id}")
            os.makedirs(sandbox_temp, exist_ok=True)

            # Copy file to sandbox temp location
            sandbox_file_path = os.path.join(sandbox_temp, os.path.basename(file_path))
            shutil.copy2(file_path, sandbox_file_path)

            # Create sandbox configuration file (.wsb)
            sandbox_config_path = os.path.join(sandbox_temp, "analysis.wsb")

            # Create monitoring script
            monitor_script = os.path.join(sandbox_temp, "monitor.ps1")
            with open(monitor_script, 'w') as f:
                f.write(f"""
# Sandbox Analysis Monitor Script
$ErrorActionPreference = "SilentlyContinue"

# Log file
$logFile = "C:\\Users\\WDAGUtilityAccount\\Desktop\\sandbox_log.txt"

# Start logging
"=== Sandbox Analysis Started ===" | Out-File $logFile
"File: {os.path.basename(file_path)}" | Out-File $logFile -Append
"Time: $(Get-Date)" | Out-File $logFile -Append

# Get initial state
$initialProcesses = Get-Process | Select-Object Name, Id
$initialFiles = Get-ChildItem C:\\Users\\WDAGUtilityAccount -Recurse -ErrorAction SilentlyContinue

# Execute the file
"Executing file..." | Out-File $logFile -Append
try {{
    Start-Process "C:\\Users\\WDAGUtilityAccount\\Desktop\\{os.path.basename(file_path)}" -ErrorAction Stop
    "File executed successfully" | Out-File $logFile -Append
}} catch {{
    "Failed to execute: $_" | Out-File $logFile -Append
}}

# Wait for execution
Start-Sleep -Seconds 10

# Get new processes
$newProcesses = Get-Process | Where-Object {{ $_.Id -notin $initialProcesses.Id }}
"New processes:" | Out-File $logFile -Append
$newProcesses | ForEach-Object {{ "  - $($_.Name) (PID: $($_.Id))" | Out-File $logFile -Append }}

# Get new files
$newFiles = Get-ChildItem C:\\Users\\WDAGUtilityAccount -Recurse -ErrorAction SilentlyContinue |
            Where-Object {{ $_.FullName -notin $initialFiles.FullName }}
"New/Modified files:" | Out-File $logFile -Append
$newFiles | ForEach-Object {{ "  - $($_.FullName)" | Out-File $logFile -Append }}

# Get network connections
"Network connections:" | Out-File $logFile -Append
Get-NetTCPConnection -ErrorAction SilentlyContinue | 
    Where-Object {{ $_.State -eq 'Established' }} |
    ForEach-Object {{ "  - $($_.RemoteAddress):$($_.RemotePort)" | Out-File $logFile -Append }}

"=== Analysis Complete ===" | Out-File $logFile -Append

# Keep window open for 5 more seconds
Start-Sleep -Seconds 5
""")

            # Create WSB configuration
            with open(sandbox_config_path, 'w') as f:
                f.write(f"""<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{sandbox_temp}</HostFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File "C:\\Users\\WDAGUtilityAccount\\Desktop\\{os.path.basename(sandbox_temp)}\\monitor.ps1"</Command>
  </LogonCommand>
</Configuration>""")

            # Launch Windows Sandbox
            logger.info(f"Starting Windows Sandbox with config: {sandbox_config_path}")
            process = subprocess.Popen(
                ['start', 'WindowsSandbox', sandbox_config_path],
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Wait for sandbox to complete (timeout after 60 seconds)
            logger.info("Waiting for sandbox analysis to complete...")
            time.sleep(60)  # Give sandbox time to execute and analyze

            # Try to read results
            log_file = os.path.join(sandbox_temp, "sandbox_log.txt")
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    log_content = f.read()

                # Parse log results
                if "New processes:" in log_content:
                    processes_section = log_content.split("New processes:")[1].split("New/Modified files:")[0]
                    for line in processes_section.strip().split('\n'):
                        if line.strip() and line.strip() != '-':
                            report.processes_created.append({
                                'name': line.strip().split()[0] if line.strip() else 'Unknown',
                                'command_line': line.strip()
                            })

                if "New/Modified files:" in log_content:
                    files_section = log_content.split("New/Modified files:")[1].split("Network connections:")[0]
                    for line in files_section.strip().split('\n'):
                        if line.strip() and line.strip() != '-':
                            report.files_created.append(line.strip())

                if "Network connections:" in log_content:
                    network_section = log_content.split("Network connections:")[1].split("=== Analysis Complete ===")[0]
                    for line in network_section.strip().split('\n'):
                        if ':' in line and line.strip() != '-':
                            parts = line.strip().split(':')
                            if len(parts) >= 2:
                                report.network_connections.append({
                                    'protocol': 'TCP',
                                    'remote_address': parts[0].strip(),
                                    'remote_port': parts[1].strip(),
                                    'state': 'Established'
                                })

                report.analysis_notes.append("Windows Sandbox dynamic analysis completed")
                report.confidence = 0.9

                # Determine if malicious based on observations
                if len(report.processes_created) > 3 or len(report.network_connections) > 0:
                    report.is_malicious = True if report.ember_score > 0.5 else False

            else:
                logger.warning("Sandbox log file not found, using static analysis")
                self._static_analysis(report, file_path, None)
                report.analysis_notes.append("Sandbox log not accessible - static analysis performed")

            # Cleanup
            try:
                shutil.rmtree(sandbox_temp)
            except:
                pass

        except Exception as e:
            logger.error(f"Dynamic analysis error: {e}")
            self._static_analysis(report, file_path, None)
            report.analysis_notes.append(f"Dynamic analysis failed: {str(e)}")

    def _static_analysis(self, report: SandboxReport, file_path: str, ember_result):
        """Perform static analysis when sandbox unavailable"""
        try:
            # Read file sample
            sample_size = min(100000, report.file_size)
            with open(file_path, 'rb') as f:
                file_sample = f.read(sample_size)

            # Analyze based on EMBER score and threat type
            if report.ember_score > 0.7:
                report.is_malicious = True
                report.confidence = 0.85

                # Infer behaviors from threat type
                if 'Ransomware' in report.threat_type:
                    report.files_modified.append("User Documents (Potential)")
                    report.files_created.append("Ransom Note (Potential)")
                    report.capabilities_observed.append("File Encryption")

                elif 'Trojan' in report.threat_type:
                    report.network_connections.append({
                        'protocol': 'Unknown',
                        'remote_address': 'C2 Server (Suspected)',
                        'remote_port': 'Various',
                        'state': 'Potential'
                    })

                elif 'Keylogger' in report.threat_type:
                    report.files_created.append("Keystroke Log (Potential)")
                    report.persistence_mechanisms.append("Registry Run Key")

                elif 'Cryptominer' in report.threat_type:
                    report.processes_created.append({
                        'name': 'Mining Process',
                        'pid': 'N/A',
                        'command_line': 'CPU/GPU Intensive Operations'
                    })
                    report.network_connections.append({
                        'protocol': 'TCP',
                        'remote_address': 'Mining Pool',
                        'remote_port': 'Various',
                        'state': 'Suspected'
                    })

            elif report.ember_score > 0.4:
                report.is_malicious = False
                report.confidence = 0.65
                report.analysis_notes.append("Moderate threat score - potential PUA or false positive")

            else:
                report.is_malicious = False
                report.confidence = 0.9

            # Check for anti-analysis techniques
            anti_analysis_indicators = [
                b'IsDebuggerPresent',
                b'CheckRemoteDebuggerPresent',
                b'VirtualAlloc',
                b'CreateRemoteThread',
                b'WriteProcessMemory'
            ]

            for indicator in anti_analysis_indicators:
                if indicator in file_sample:
                    report.anti_analysis_techniques.append(
                        f"Found: {indicator.decode('utf-8', errors='ignore')}"
                    )

            report.analysis_notes.append("Static analysis completed")
            report.analysis_notes.append("Limited to heuristics and EMBER AI classification")

        except Exception as e:
            logger.error(f"Static analysis error: {e}")
            report.confidence = 0.3
            report.analysis_notes.append(f"Analysis error: {str(e)}")

    def _create_sandbox_config(self, file_path: str, analysis_id: str) -> str:
        """Create Windows Sandbox configuration"""
        file_name = Path(file_path).name

        config = f"""<Configuration>
    <MappedFolders>
        <MappedFolder>
            <HostFolder>{Path(file_path).parent}</HostFolder>
            <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop</SandboxFolder>
            <ReadOnly>true</ReadOnly>
        </MappedFolder>
    </MappedFolders>
    <LogonCommand>
        <Command>cmd.exe /c echo Analysis {analysis_id} for {file_name}</Command>
    </LogonCommand>
    <Networking>Disable</Networking>
    <MemoryInMB>4096</MemoryInMB>
</Configuration>"""

        config_path = os.path.join(self.temp_dir, f"sandbox_{analysis_id}.wsb")
        with open(config_path, 'w') as f:
            f.write(config)

        return config_path

    def _calculate_risk_score(self, report: SandboxReport) -> float:
        """Calculate comprehensive risk score"""
        risk_score = 0.0

        # EMBER score contribution (40%)
        risk_score += report.ember_score * 0.4

        # Behavioral indicators (30%)
        behavior_score = 0.0
        if report.processes_created:
            behavior_score += 0.2
        if report.files_modified:
            behavior_score += 0.2
        if report.registry_modifications:
            behavior_score += 0.3
        if report.network_connections:
            behavior_score += 0.2
        if report.persistence_mechanisms and report.persistence_mechanisms != ["None detected"]:
            behavior_score += 0.3

        risk_score += min(1.0, behavior_score) * 0.3

        # Threat type severity (20%)
        threat_severity = {
            'Ransomware': 1.0,
            'Rootkit': 1.0,
            'Trojan': 0.9,
            'Keylogger': 0.85,
            'Backdoor': 0.9,
            'Worm': 0.85,
            'Infostealer': 0.8,
            'Cryptominer': 0.6,
            'PUA': 0.3,
            'Benign': 0.0
        }

        for threat_name, severity in threat_severity.items():
            if threat_name in report.threat_type:
                risk_score += severity * 0.2
                break

        # Anti-analysis techniques (10%)
        if report.anti_analysis_techniques:
            risk_score += min(len(report.anti_analysis_techniques) * 0.1, 0.1)

        return min(1.0, risk_score)

    def _classify_risk_level(self, risk_score: float) -> str:
        """Classify risk level"""
        if risk_score >= 0.8:
            return "CRITICAL"
        elif risk_score >= 0.6:
            return "HIGH"
        elif risk_score >= 0.4:
            return "MEDIUM"
        elif risk_score >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"

    def _determine_verdict(self, report: SandboxReport) -> str:
        """Determine final verdict"""
        if report.is_malicious and report.confidence > 0.7:
            return f"MALICIOUS: {report.threat_type} detected with high confidence"
        elif report.is_malicious and report.confidence > 0.5:
            return f"LIKELY MALICIOUS: {report.threat_type} suspected"
        elif report.ember_score > 0.4:
            return "SUSPICIOUS: Requires further investigation"
        elif report.ember_score > 0.2:
            return "POTENTIALLY UNWANTED: Low threat indicators"
        else:
            return "CLEAN: No malicious behavior detected"

    def _get_recommended_action(self, report: SandboxReport) -> str:
        """Get recommended action"""
        if report.risk_level == "CRITICAL":
            return "QUARANTINE IMMEDIATELY: Isolate system, disconnect network, begin incident response"
        elif report.risk_level == "HIGH":
            return "QUARANTINE: Remove file, scan system, monitor for additional infections"
        elif report.risk_level == "MEDIUM":
            return "ISOLATE: Quarantine file, perform detailed analysis, await further instructions"
        elif report.risk_level == "LOW":
            return "REVIEW: Monitor file activity, consider whitelisting if legitimate"
        else:
            return "ALLOW: File appears safe, no action required"

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash"""
        try:
            import hashlib
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except:
            return ""

    def generate_detailed_report(self, report: SandboxReport, output_path: str = None) -> str:
        """Generate detailed HTML/text report"""
        report_text = f"""
═══════════════════════════════════════════════════════════════════════════
                        FIXION SANDBOX ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════════════

ANALYSIS INFORMATION:
────────────────────────────────────────────────────────────────────────────
Analysis ID:        {report.analysis_id}
Timestamp:          {report.timestamp}
Analysis Time:      {report.execution_time:.2f}s
Environment:        {report.sandbox_environment}

FILE INFORMATION:
────────────────────────────────────────────────────────────────────────────
File Path:          {report.file_path}
File Name:          {Path(report.file_path).name}
File Size:          {report.file_size:,} bytes
File Type:          {report.file_type}
SHA256 Hash:        {report.file_hash}

THREAT ASSESSMENT:
────────────────────────────────────────────────────────────────────────────
Verdict:            {report.verdict}
Malicious:          {'YES' if report.is_malicious else 'NO'}
Confidence:         {report.confidence:.1%}
Risk Score:         {report.risk_score:.2f}/1.00
Risk Level:         {report.risk_level}

EMBER AI ANALYSIS:
────────────────────────────────────────────────────────────────────────────
AI Score:           {report.ember_score:.3f}
Threat Type:        {report.threat_type}
Threat Family:      {report.threat_family or 'Unclassified'}

OBSERVED BEHAVIORS:
────────────────────────────────────────────────────────────────────────────
"""

        if report.threat_behaviors:
            for i, behavior in enumerate(report.threat_behaviors, 1):
                report_text += f"\n{i}. {behavior['category']} ({behavior['severity']})\n"
                report_text += f"   Description: {behavior['description']}\n"
                if behavior['indicators']:
                    report_text += f"   Indicators: {', '.join(behavior['indicators'])}\n"
        else:
            report_text += "No specific behaviors identified\n"

        report_text += f"""
CAPABILITIES:
────────────────────────────────────────────────────────────────────────────
"""
        if report.capabilities_observed:
            for cap in report.capabilities_observed:
                report_text += f"• {cap}\n"
        else:
            report_text += "None detected\n"

        if report.processes_created:
            report_text += f"""
PROCESSES CREATED:
────────────────────────────────────────────────────────────────────────────
"""
            for proc in report.processes_created:
                report_text += f"• {proc.get('name', 'Unknown')}\n"
                report_text += f"  Command: {proc.get('command_line', 'N/A')}\n"

        if report.files_created or report.files_modified:
            report_text += f"""
FILE SYSTEM CHANGES:
────────────────────────────────────────────────────────────────────────────
"""
            if report.files_created:
                report_text += "Files Created:\n"
                for f in report.files_created:
                    report_text += f"  • {f}\n"

            if report.files_modified:
                report_text += "Files Modified:\n"
                for f in report.files_modified:
                    report_text += f"  • {f}\n"

        if report.registry_modifications:
            report_text += f"""
REGISTRY MODIFICATIONS:
────────────────────────────────────────────────────────────────────────────
"""
            for reg in report.registry_modifications:
                report_text += f"• {reg.get('action', 'Modified')}: {reg.get('key', 'Unknown')}\n"

        if report.network_connections:
            report_text += f"""
NETWORK ACTIVITY:
────────────────────────────────────────────────────────────────────────────
"""
            for conn in report.network_connections:
                report_text += f"• {conn.get('protocol', 'Unknown')} -> {conn.get('remote_address', 'Unknown')}:{conn.get('remote_port', 'N/A')}\n"

        if report.persistence_mechanisms and report.persistence_mechanisms != ["None detected"]:
            report_text += f"""
PERSISTENCE MECHANISMS:
────────────────────────────────────────────────────────────────────────────
"""
            for mech in report.persistence_mechanisms:
                report_text += f"• {mech}\n"

        if report.anti_analysis_techniques:
            report_text += f"""
ANTI-ANALYSIS TECHNIQUES:
────────────────────────────────────────────────────────────────────────────
"""
            for tech in report.anti_analysis_techniques:
                report_text += f"• {tech}\n"

        report_text += f"""
IMPACT ASSESSMENT:
────────────────────────────────────────────────────────────────────────────
{report.impact_assessment}

RECOMMENDED ACTION:
────────────────────────────────────────────────────────────────────────────
{report.recommended_action}

MITIGATION STEPS:
────────────────────────────────────────────────────────────────────────────
"""
        if report.mitigation_steps:
            for i, step in enumerate(report.mitigation_steps, 1):
                report_text += f"{i}. {step}\n"
        else:
            report_text += "No specific mitigation required\n"

        if report.analysis_notes:
            report_text += f"""
ANALYSIS NOTES:
────────────────────────────────────────────────────────────────────────────
"""
            for note in report.analysis_notes:
                report_text += f"• {note}\n"

        report_text += """
═══════════════════════════════════════════════════════════════════════════
                         END OF ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════════════
"""

        # Save to file if requested
        if output_path:
            with open(output_path, 'w') as f:
                f.write(report_text)
            logger.info(f"Report saved to: {output_path}")

        return report_text

    def export_report_json(self, report: SandboxReport, output_path: str):
        """Export report as JSON"""
        import json
        from dataclasses import asdict

        report_dict = asdict(report)

        with open(output_path, 'w') as f:
            json.dump(report_dict, f, indent=2)

        logger.info(f"JSON report saved to: {output_path}")

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of all analyses"""
        if not self.analysis_history:
            return {'total_analyses': 0}

        summary = {
            'total_analyses': len(self.analysis_history),
            'malicious_files': sum(1 for r in self.analysis_history if r.is_malicious),
            'clean_files': sum(1 for r in self.analysis_history if not r.is_malicious),
            'average_risk_score': sum(r.risk_score for r in self.analysis_history) / len(self.analysis_history),
            'threat_types': {}
        }

        for report in self.analysis_history:
            threat_type = report.threat_type
            summary['threat_types'][threat_type] = summary['threat_types'].get(threat_type, 0) + 1

        return summary

    def is_sandbox_running(self):
        """Check if Windows Sandbox is currently running"""
        if os.name != 'nt':
            return False

        try:
            result = subprocess.run(
                ['powershell', '-Command',
                 'Get-Process -Name "WindowsSandbox" -ErrorAction SilentlyContinue | Select-Object -First 1'],
                capture_output=True,
                text=True,
                timeout=5
            )
            return bool(result.stdout.strip())
        except:
            return False

    def wait_for_sandbox_available(self, timeout=300):
        """Wait for Windows Sandbox to become available"""
        import time
        start_time = time.time()

        while time.time() - start_time < timeout:
            if not self.is_sandbox_running():
                return True
            time.sleep(5)

        return False

    def analyze_batch(self, threat_files, parent_window=None):
        """
        Analyze multiple threats in batch mode using Windows Sandbox

        Args:
            threat_files: List of file paths to analyze
            parent_window: Parent window for progress dialog

        Returns:
            List of SandboxReport objects
        """
        if not threat_files:
            return []

        import customtkinter as ctk
        from tkinter import messagebox

        # Show batch progress dialog
        progress_dialog = None
        if parent_window:
            progress_dialog = ctk.CTkToplevel(parent_window)
            progress_dialog.title("Batch Sandbox Analysis")
            progress_dialog.geometry("500x300")
            progress_dialog.transient(parent_window)

            ctk.CTkLabel(
                progress_dialog,
                text="Batch Sandbox Analysis",
                font=ctk.CTkFont(size=18, weight="bold")
            ).pack(pady=20)

            progress_label = ctk.CTkLabel(
                progress_dialog,
                text="Starting analysis...",
                font=ctk.CTkFont(size=12)
            )
            progress_label.pack(pady=10)

            progress_bar = ctk.CTkProgressBar(progress_dialog, width=400)
            progress_bar.pack(pady=20)
            progress_bar.set(0)

            details_text = ctk.CTkTextbox(progress_dialog, width=450, height=100)
            details_text.pack(pady=10, padx=20)

        reports = []
        total_files = len(threat_files)

        for idx, file_path in enumerate(threat_files):
            try:
                # Update progress
                if progress_dialog:
                    progress = (idx / total_files)
                    progress_bar.set(progress)
                    progress_label.configure(
                        text=f"Analyzing file {idx + 1} of {total_files}..."
                    )
                    details_text.insert("end", f"\nAnalyzing: {os.path.basename(file_path)}")
                    details_text.see("end")
                    progress_dialog.update()

                # Wait for sandbox to be available if currently running
                if self.is_sandbox_running():
                    if progress_dialog:
                        details_text.insert("end", f"\n  Waiting for sandbox to become available...")
                        details_text.see("end")
                        progress_dialog.update()

                    if not self.wait_for_sandbox_available(timeout=300):
                        logger.warning(f"Sandbox timeout for {file_path}, skipping...")
                        if progress_dialog:
                            details_text.insert("end", f"\n  Skipped (timeout)")
                            details_text.see("end")
                        continue

                # Analyze file
                report = self.analyze_file(file_path)
                reports.append(report)

                if progress_dialog:
                    verdict = report.verdict
                    details_text.insert("end", f"\n  Result: {verdict}")
                    details_text.see("end")
                    progress_dialog.update()

            except Exception as e:
                logger.error(f"Error analyzing {file_path}: {e}")
                if progress_dialog:
                    details_text.insert("end", f"\n  Error: {str(e)}")
                    details_text.see("end")

        # Complete
        if progress_dialog:
            progress_bar.set(1.0)
            progress_label.configure(text=f"Analysis complete! {len(reports)} files analyzed.")
            details_text.insert("end", f"\n\nBatch analysis complete!")
            details_text.see("end")

            # Add close button
            ctk.CTkButton(
                progress_dialog,
                text="View Reports",
                command=lambda: self.show_batch_reports(reports, parent_window)
            ).pack(pady=10)

            ctk.CTkButton(
                progress_dialog,
                text="Close",
                command=progress_dialog.destroy,
                fg_color="gray"
            ).pack(pady=5)

        return reports

    def show_batch_reports(self, reports, parent_window=None):
        """Show summary of batch analysis reports"""
        import customtkinter as ctk
        from tkinter import messagebox

        if not reports:
            messagebox.showinfo("Batch Analysis", "No reports available")
            return

        # Create summary window
        summary_window = ctk.CTkToplevel(parent_window) if parent_window else ctk.CTk()
        summary_window.title("Batch Analysis Summary")
        summary_window.geometry("700x500")

        ctk.CTkLabel(
            summary_window,
            text="Batch Analysis Summary",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=20)

        # Summary stats
        stats_frame = ctk.CTkFrame(summary_window, fg_color="#1a1c24", corner_radius=10)
        stats_frame.pack(fill="x", padx=20, pady=10)

        malicious_count = sum(1 for r in reports if r.is_malicious)
        clean_count = len(reports) - malicious_count

        stats_text = f"Total Analyzed: {len(reports)} | Malicious: {malicious_count} | Clean: {clean_count}"
        ctk.CTkLabel(
            stats_frame,
            text=stats_text,
            font=ctk.CTkFont(size=14)
        ).pack(pady=15)

        # Reports list
        scroll_frame = ctk.CTkScrollableFrame(summary_window, height=300)
        scroll_frame.pack(fill="both", expand=True, padx=20, pady=10)

        for report in reports:
            card = ctk.CTkFrame(scroll_frame, fg_color="#1a1c24", corner_radius=8)
            card.pack(fill="x", pady=5)

            # File name
            file_name = os.path.basename(report.file_path)
            ctk.CTkLabel(
                card,
                text=file_name,
                font=ctk.CTkFont(size=12, weight="bold")
            ).pack(side="left", padx=15, pady=10)

            # Verdict
            verdict_color = "#e74c3c" if report.is_malicious else "#2ecc71"
            ctk.CTkLabel(
                card,
                text=report.verdict,
                font=ctk.CTkFont(size=11),
                text_color=verdict_color
            ).pack(side="right", padx=15, pady=10)

        # Close button
        ctk.CTkButton(
            summary_window,
            text="Close",
            command=summary_window.destroy,
            width=100
        ).pack(pady=15)
