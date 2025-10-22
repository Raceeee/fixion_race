import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import os
from typing import Dict, Any
from datetime import datetime


class SandboxReportViewer(ctk.CTkToplevel):
    """Comprehensive sandbox report viewer with visualizations"""

    def __init__(self, parent, report_data: Dict[str, Any], file_name: str = "Unknown"):
        super().__init__(parent)

        self.report_data = report_data
        self.file_name = file_name

        # Window setup
        self.title(f"Sandbox Analysis Report - {file_name}")
        self.geometry("1200x800")

        # Fix for CustomTkinter scaling issue - delay initialization
        self.after(100, self._delayed_init)

    def _delayed_init(self):
        """Delayed initialization to avoid scaling issues"""
        # Center window
        self.update_idletasks()
        x = (self.winfo_screenwidth() // 2) - 600
        y = (self.winfo_screenheight() // 2) - 400
        self.geometry(f"1200x800+{x}+{y}")

        self.create_ui()
        self.populate_report()

    def create_ui(self):
        """Create UI layout"""
        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=10, pady=10)

        main_container.grid_columnconfigure(0, weight=1)
        main_container.grid_rowconfigure(1, weight=1)

        # Header
        self.create_header(main_container)

        # Content area with tabs
        self.create_content_tabs(main_container)

        # Footer with actions
        self.create_footer(main_container)

    def create_header(self, parent):
        """Create report header"""
        header_frame = ctk.CTkFrame(parent, fg_color="#1a1c24", corner_radius=10, height=120)
        header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        header_frame.grid_propagate(False)

        # File info section
        info_frame = ctk.CTkFrame(header_frame, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=20, pady=15)

        # File name
        ctk.CTkLabel(
            info_frame,
            text=self.file_name,
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(anchor="w", pady=(0, 5))

        # File details
        file_info = self.report_data.get('file_info', {})
        details = f"Size: {file_info.get('size_mb', 0)} MB  •  " \
                  f"Type: {file_info.get('extension', 'Unknown')}  •  " \
                  f"Analysis Time: {self.get_analysis_time()}"

        ctk.CTkLabel(
            info_frame,
            text=details,
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(anchor="w")

        # SHA256
        sha256 = file_info.get('sha256', 'N/A')
        ctk.CTkLabel(
            info_frame,
            text=f"SHA256: {sha256[:32]}...",
            font=ctk.CTkFont(size=10),
            text_color="gray"
        ).pack(anchor="w", pady=(5, 0))

        # Verdict section
        verdict_frame = ctk.CTkFrame(header_frame, fg_color="#2d3748", corner_radius=10)
        verdict_frame.pack(side="right", padx=20, pady=15)

        verdict = self.report_data.get('verdict', 'unknown').upper()
        confidence = self.report_data.get('confidence', 0)

        # Verdict color
        verdict_colors = {
            'BENIGN': '#2ecc71',
            'LOW_RISK': '#3498db',
            'SUSPICIOUS': '#f39c12',
            'MALICIOUS': '#e74c3c',
            'UNKNOWN': '#95a5a6'
        }
        color = verdict_colors.get(verdict, '#95a5a6')

        ctk.CTkLabel(
            verdict_frame,
            text="VERDICT",
            font=ctk.CTkFont(size=11),
            text_color="gray"
        ).pack(pady=(15, 2), padx=30)

        ctk.CTkLabel(
            verdict_frame,
            text=verdict.replace('_', ' '),
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=color
        ).pack(pady=(0, 5), padx=30)

        ctk.CTkLabel(
            verdict_frame,
            text=f"Confidence: {confidence}%",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        ).pack(pady=(0, 15), padx=30)

    def create_content_tabs(self, parent):
        """Create tabbed content area"""
        # Tab view
        self.tabview = ctk.CTkTabview(parent)
        self.tabview.grid(row=1, column=0, sticky="nsew")

        # Create tabs
        self.tabview.add("Overview")
        self.tabview.add("Behavior Analysis")
        self.tabview.add("Network Activity")
        self.tabview.add("File Operations")
        self.tabview.add("Timeline")
        self.tabview.add("AI Analysis")

        # Populate tabs
        self.create_overview_tab()
        self.create_behavior_tab()
        self.create_network_tab()
        self.create_file_ops_tab()
        self.create_timeline_tab()
        self.create_ai_analysis_tab()

    def create_overview_tab(self):
        """Create overview tab with charts"""
        tab = self.tabview.tab("Overview")
        tab.grid_columnconfigure((0, 1), weight=1)

        # Execution status card
        status_card = ctk.CTkFrame(tab, fg_color="#1a1c24", corner_radius=10)
        status_card.grid(row=0, column=0, columnspan=2, sticky="ew", padx=10, pady=10)

        ctk.CTkLabel(
            status_card,
            text="Execution Status",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 5))

        exec_status = self.report_data.get('execution_status', 'unknown')
        status_text = self.format_execution_status(exec_status)

        ctk.CTkLabel(
            status_card,
            text=status_text,
            font=ctk.CTkFont(size=14),
            text_color="gray"
        ).pack(anchor="w", padx=20, pady=(0, 15))

        # Charts area
        charts_frame = ctk.CTkFrame(tab, fg_color="#1a1c24", corner_radius=10)
        charts_frame.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=(0, 10))

        ctk.CTkLabel(
            charts_frame,
            text="Risk Breakdown",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 10))

        # Display risk breakdown chart if available
        risk_breakdown = self.report_data.get('risk_breakdown', {})
        if risk_breakdown:
            self.display_risk_breakdown_chart(charts_frame, risk_breakdown)
        else:
            ctk.CTkLabel(
                charts_frame,
                text="No risk data available",
                text_color="gray"
            ).pack(pady=30)

        # Summary statistics
        stats_frame = ctk.CTkFrame(tab, fg_color="#1a1c24", corner_radius=10)
        stats_frame.grid(row=1, column=1, sticky="nsew", padx=(5, 10), pady=(0, 10))

        ctk.CTkLabel(
            stats_frame,
            text="Analysis Summary",
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(pady=(15, 10))

        self.display_summary_stats(stats_frame)

    def create_behavior_tab(self):
        """Create behavior analysis tab"""
        tab = self.tabview.tab("Behavior Analysis")

        scroll_frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        behavior_data = self.report_data.get('behavior_analysis', {})

        if not behavior_data or behavior_data.get('total_suspicious', 0) == 0:
            ctk.CTkLabel(
                scroll_frame,
                text="No suspicious behaviors detected",
                font=ctk.CTkFont(size=14),
                text_color="gray"
            ).pack(pady=50)
            return

        # Suspicious behaviors
        ctk.CTkLabel(
            scroll_frame,
            text="Suspicious Behaviors Detected",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", pady=(0, 15))

        behaviors = behavior_data.get('suspicious_behaviors', [])

        for behavior in behaviors:
            self.create_behavior_card(scroll_frame, behavior)

    def create_network_tab(self):
        """Create network activity tab"""
        tab = self.tabview.tab("Network Activity")

        scroll_frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        network_data = self.report_data.get('network_activity', {})

        # Summary
        total_conns = network_data.get('total_connections', 0)
        unique_ips = network_data.get('unique_remote_ips', 0)

        summary_text = f"Total Connections: {total_conns}  •  Unique IPs: {unique_ips}"

        ctk.CTkLabel(
            scroll_frame,
            text=summary_text,
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 15))

        if total_conns == 0:
            ctk.CTkLabel(
                scroll_frame,
                text="No network activity detected",
                text_color="gray"
            ).pack(pady=30)
            return

        # Connection list
        connections = network_data.get('connections', [])

        for conn in connections:
            self.create_connection_card(scroll_frame, conn)

    def create_file_ops_tab(self):
        """Create file operations tab"""
        tab = self.tabview.tab("File Operations")

        scroll_frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        file_ops_data = self.report_data.get('file_operations', {})

        # Summary
        total = file_ops_data.get('total', 0)
        created = file_ops_data.get('created', 0)
        modified = file_ops_data.get('modified', 0)
        deleted = file_ops_data.get('deleted', 0)

        summary_text = f"Total: {total}  •  Created: {created}  •  Modified: {modified}  •  Deleted: {deleted}"

        ctk.CTkLabel(
            scroll_frame,
            text=summary_text,
            font=ctk.CTkFont(size=14, weight="bold")
        ).pack(anchor="w", pady=(0, 15))

        if total == 0:
            ctk.CTkLabel(
                scroll_frame,
                text="No file operations detected",
                text_color="gray"
            ).pack(pady=30)
            return

        # Operations list
        operations = file_ops_data.get('operations', [])

        for op in operations:
            self.create_file_op_card(scroll_frame, op)

    def create_timeline_tab(self):
        """Create timeline tab"""
        tab = self.tabview.tab("Timeline")

        scroll_frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        timeline = self.report_data.get('timeline', [])

        if not timeline:
            ctk.CTkLabel(
                scroll_frame,
                text="No timeline data available",
                text_color="gray"
            ).pack(pady=30)
            return

        ctk.CTkLabel(
            scroll_frame,
            text=f"Activity Timeline ({len(timeline)} events)",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", pady=(0, 15))

        for event in timeline:
            self.create_timeline_event_card(scroll_frame, event)

    def create_ai_analysis_tab(self):
        """Create AI analysis tab"""
        tab = self.tabview.tab("AI Analysis")

        scroll_frame = ctk.CTkScrollableFrame(tab, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)

        ai_data = self.report_data.get('ai_threat_assessment', {})

        if not ai_data:
            ctk.CTkLabel(
                scroll_frame,
                text="No AI analysis data available",
                text_color="gray"
            ).pack(pady=30)
            return

        # AI Model info
        model_card = ctk.CTkFrame(scroll_frame, fg_color="#1a1c24", corner_radius=10)
        model_card.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            model_card,
            text="AI Model Analysis",
            font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=20, pady=(15, 10))

        model_name = ai_data.get('model', 'Unknown')
        ctk.CTkLabel(
            model_card,
            text=f"Model: {model_name}",
            font=ctk.CTkFont(size=13)
        ).pack(anchor="w", padx=20, pady=2)

        # AI Score
        ai_score = ai_data.get('ai_score', 0)
        score_percent = int(ai_score * 100)

        score_frame = ctk.CTkFrame(model_card, fg_color="transparent")
        score_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(
            score_frame,
            text="Threat Score:",
            font=ctk.CTkFont(size=13)
        ).pack(side="left")

        # Progress bar for score
        score_bar = ctk.CTkProgressBar(score_frame, width=200, height=20)
        score_bar.pack(side="left", padx=10)
        score_bar.set(ai_score)

        # Color based on score
        if ai_score >= 0.7:
            color = "#e74c3c"
        elif ai_score >= 0.4:
            color = "#f39c12"
        else:
            color = "#2ecc71"

        score_bar.configure(progress_color=color)

        ctk.CTkLabel(
            score_frame,
            text=f"{score_percent}%",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=color
        ).pack(side="left")

        # Threat Level
        threat_level = ai_data.get('threat_level', 'unknown').upper()
        ctk.CTkLabel(
            model_card,
            text=f"Threat Level: {threat_level}",
            font=ctk.CTkFont(size=13),
            text_color=color
        ).pack(anchor="w", padx=20, pady=(5, 15))

    def create_footer(self, parent):
        """Create footer with action buttons"""
        footer_frame = ctk.CTkFrame(parent, fg_color="#1a1c24", corner_radius=10, height=70)
        footer_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        footer_frame.grid_propagate(False)

        button_frame = ctk.CTkFrame(footer_frame, fg_color="transparent")
        button_frame.pack(expand=True)

        # Export button
        ctk.CTkButton(
            button_frame,
            text="📄 Export Report",
            command=self.export_report,
            width=150,
            height=40,
            font=ctk.CTkFont(size=13)
        ).pack(side="left", padx=5)

        # Close button
        ctk.CTkButton(
            button_frame,
            text="Close",
            command=self.destroy,
            width=100,
            height=40,
            font=ctk.CTkFont(size=13),
            fg_color="#6c757d",
            hover_color="#5a6268"
        ).pack(side="left", padx=5)

    # Helper methods for displaying data

    def display_risk_breakdown_chart(self, parent, risk_data: Dict[str, float]):
        """Display risk breakdown as text (pie chart if image available)"""
        # Try to display chart image if available
        charts = self.report_data.get('charts', {})
        chart_path = charts.get('risk_breakdown')

        if chart_path and os.path.exists(chart_path):
            try:
                # Load and display image
                img = Image.open(chart_path)
                img = img.resize((400, 300), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)

                label = tk.Label(parent, image=photo, bg="#1a1c24")
                label.image = photo  # Keep reference
                label.pack(pady=10)
                return
            except Exception as e:
                print(f"Error displaying chart: {e}")

        # Fallback: Display as text
        for category, value in risk_data.items():
            if value > 0:
                item_frame = ctk.CTkFrame(parent, fg_color="#2d3748", corner_radius=8)
                item_frame.pack(fill="x", padx=20, pady=5)

                ctk.CTkLabel(
                    item_frame,
                    text=category,
                    font=ctk.CTkFont(size=12)
                ).pack(side="left", padx=15, pady=10)

                # Progress bar
                bar = ctk.CTkProgressBar(item_frame, width=150)
                bar.pack(side="left", padx=10)
                bar.set(value / 100)

                ctk.CTkLabel(
                    item_frame,
                    text=f"{value:.1f}%",
                    font=ctk.CTkFont(size=12, weight="bold")
                ).pack(side="left", padx=10)

    def display_summary_stats(self, parent):
        """Display summary statistics"""
        stats = [
            ("File Operations", self.report_data.get('file_operations', {}).get('total', 0)),
            ("Network Connections", self.report_data.get('network_activity', {}).get('total_connections', 0)),
            ("Registry Changes", self.report_data.get('registry_changes', {}).get('total', 0)),
            ("Suspicious Behaviors", self.report_data.get('behavior_analysis', {}).get('total_suspicious', 0))
        ]

        for label, value in stats:
            stat_frame = ctk.CTkFrame(parent, fg_color="#2d3748", corner_radius=8)
            stat_frame.pack(fill="x", padx=20, pady=5)

            ctk.CTkLabel(
                stat_frame,
                text=label,
                font=ctk.CTkFont(size=11),
                text_color="gray"
            ).pack(anchor="w", padx=15, pady=(8, 2))

            ctk.CTkLabel(
                stat_frame,
                text=str(value),
                font=ctk.CTkFont(size=20, weight="bold")
            ).pack(anchor="w", padx=15, pady=(0, 8))

    def create_behavior_card(self, parent, behavior: Dict[str, Any]):
        """Create card for suspicious behavior"""
        severity = behavior.get('severity', 'medium')
        severity_colors = {
            'high': '#e74c3c',
            'medium': '#f39c12',
            'low': '#3498db'
        }

        card = ctk.CTkFrame(parent, fg_color="#1a1c24", corner_radius=10)
        card.pack(fill="x", pady=5)

        # Severity indicator
        indicator = ctk.CTkFrame(card, fg_color=severity_colors.get(severity, '#95a5a6'),
                                 width=5, corner_radius=0)
        indicator.pack(side="left", fill="y")

        # Content
        content_frame = ctk.CTkFrame(card, fg_color="transparent")
        content_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)

        # Category and severity
        header_frame = ctk.CTkFrame(content_frame, fg_color="transparent")
        header_frame.pack(fill="x")

        ctk.CTkLabel(
            header_frame,
            text=behavior.get('category', 'Unknown').upper(),
            font=ctk.CTkFont(size=11, weight="bold")
        ).pack(side="left")

        ctk.CTkLabel(
            header_frame,
            text=severity.upper(),
            font=ctk.CTkFont(size=10),
            text_color=severity_colors.get(severity, '#95a5a6')
        ).pack(side="right")

        # Description
        ctk.CTkLabel(
            content_frame,
            text=behavior.get('description', ''),
            font=ctk.CTkFont(size=12),
            text_color="gray",
            wraplength=600,
            justify="left"
        ).pack(anchor="w", pady=(5, 0))

    def create_connection_card(self, parent, conn: Dict[str, Any]):
        """Create card for network connection"""
        card = ctk.CTkFrame(parent, fg_color="#1a1c24", corner_radius=8)
        card.pack(fill="x", pady=3)

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=8)

        # Remote address
        remote = f"{conn.get('remote_address', 'Unknown')}:{conn.get('remote_port', 0)}"
        ctk.CTkLabel(
            content,
            text=remote,
            font=ctk.CTkFont(size=12, weight="bold")
        ).pack(side="left")

        # State
        state = conn.get('state', 'Unknown')
        ctk.CTkLabel(
            content,
            text=state,
            font=ctk.CTkFont(size=10),
            text_color="gray"
        ).pack(side="right")

    def create_file_op_card(self, parent, op: Dict[str, Any]):
        """Create card for file operation"""
        card = ctk.CTkFrame(parent, fg_color="#1a1c24", corner_radius=8)
        card.pack(fill="x", pady=3)

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=8)

        # Action
        action = op.get('action', 'unknown').upper()
        action_colors = {
            'CREATED': '#2ecc71',
            'MODIFIED': '#3498db',
            'DELETED': '#e74c3c'
        }

        ctk.CTkLabel(
            content,
            text=action,
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=action_colors.get(action, '#95a5a6'),
            width=80
        ).pack(side="left")

        # Path
        path = op.get('path', 'Unknown')
        ctk.CTkLabel(
            content,
            text=path,
            font=ctk.CTkFont(size=11),
            text_color="gray",
            wraplength=500,
            justify="left"
        ).pack(side="left", fill="x", expand=True)

    def create_timeline_event_card(self, parent, event: Dict[str, Any]):
        """Create card for timeline event"""
        card = ctk.CTkFrame(parent, fg_color="#1a1c24", corner_radius=8)
        card.pack(fill="x", pady=3)

        content = ctk.CTkFrame(card, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=15, pady=8)

        # Timestamp
        timestamp = event.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(timestamp)
            time_str = dt.strftime("%H:%M:%S")
        except:
            time_str = timestamp[:8] if len(timestamp) > 8 else timestamp

        ctk.CTkLabel(
            content,
            text=time_str,
            font=ctk.CTkFont(size=10),
            text_color="gray",
            width=80
        ).pack(side="left")

        # Category badge
        category = event.get('category', 'other')
        category_colors = {
            'file': '#3498db',
            'network': '#e74c3c',
            'process': '#f39c12',
            'registry': '#9b59b6',
            'detection': '#e67e22'
        }

        badge = ctk.CTkLabel(
            content,
            text=category.upper(),
            font=ctk.CTkFont(size=9),
            text_color=category_colors.get(category, '#95a5a6'),
            width=70
        )
        badge.pack(side="left", padx=5)

        # Event description
        ctk.CTkLabel(
            content,
            text=event.get('event', ''),
            font=ctk.CTkFont(size=11),
            wraplength=600,
            justify="left"
        ).pack(side="left", fill="x", expand=True)

    def format_execution_status(self, status: str) -> str:
        """Format execution status text"""
        status_map = {
            'executed': '✓ File executed successfully in sandbox',
            'completed': '✓ Execution completed normally',
            'terminated': '⚠ Execution terminated (timeout or forced)',
            'failed': '✗ File failed to execute',
            'non_executable': 'ℹ Non-executable file - static analysis performed',
            'sandbox_unavailable': '⚠ Windows Sandbox unavailable - static analysis performed',
            'timeout': '⏱ Analysis timeout',
            'error': '✗ Analysis error occurred'
        }

        return status_map.get(status, f'Status: {status}')

    def get_analysis_time(self) -> str:
        """Get formatted analysis time"""
        timestamp = self.report_data.get('timestamp', '')
        try:
            dt = datetime.fromisoformat(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except:
            return "Unknown"

    def export_report(self):
        """Export report to JSON"""
        try:
            from tkinter import filedialog
            import json

            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=f"sandbox_report_{self.file_name}.json"
            )

            if filename:
                with open(filename, 'w') as f:
                    json.dump(self.report_data, f, indent=2)

                messagebox.showinfo("Export Complete", f"Report exported to:\n{filename}")

        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export report:\n{str(e)}")


# Test the viewer
if __name__ == "__main__":
    # Sample report data
    sample_report = {
        'file_info': {
            'name': 'sample.exe',
            'size_mb': 1.5,
            'extension': '.exe',
            'sha256': 'abc123def456'
        },
        'execution_status': 'executed',
        'verdict': 'suspicious',
        'confidence': 85,
        'ai_threat_assessment': {
            'ai_score': 0.65,
            'threat_level': 'medium',
            'model': 'EMBER AI Model'
        },
        'risk_breakdown': {
            'File Operations': 30,
            'Network Activity': 40,
            'Process Creation': 20,
            'Other': 10
        },
        'behavior_analysis': {
            'total_suspicious': 3,
            'suspicious_behaviors': [
                {'category': 'file', 'severity': 'high', 'description': 'Modified system files'},
                {'category': 'network', 'severity': 'medium', 'description': 'Multiple network connections'}
            ]
        },
        'network_activity': {
            'total_connections': 5,
            'unique_remote_ips': 3,
            'connections': [
                {'remote_address': '192.168.1.1', 'remote_port': 80, 'state': 'ESTABLISHED'}
            ]
        },
        'file_operations': {
            'total': 10,
            'created': 5,
            'modified': 3,
            'deleted': 2,
            'operations': [
                {'action': 'created', 'path': 'C:\\Temp\\test.txt'}
            ]
        },
        'timeline': [
            {'timestamp': datetime.now().isoformat(), 'category': 'file', 'event': 'Created test file'}
        ],
        'timestamp': datetime.now().isoformat()
    }

    root = ctk.CTk()
    root.withdraw()

    viewer = SandboxReportViewer(root, sample_report, "sample.exe")
    viewer.mainloop()
    def populate_report(self):
        """Populate the report with data"""
        # This method is called after create_ui to populate the tabs with data
        # The data is already loaded from self.report_data in each tab creation method
        # This is just a placeholder for compatibility
        pass
