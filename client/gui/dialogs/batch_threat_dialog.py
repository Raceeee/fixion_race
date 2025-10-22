
import customtkinter as ctk
from tkinter import messagebox
import os
import shutil
from datetime import datetime


class BatchThreatDialog(ctk.CTkToplevel):
    def __init__(self, parent, threats: list, database, sandbox_analyzer):
        super().__init__(parent)

        self.parent = parent
        self.threats = threats
        self.db = database
        self.sandbox_analyzer = sandbox_analyzer

        # Selection tracking
        self.threat_vars = {}
        self.select_all_var = ctk.BooleanVar(value=False)

        # Setup window
        self.title("Threats Detected")
        self.geometry("900x600")
        self.resizable(True, True)

        # Create UI
        self.create_ui()

        # Center window
        self.center_window()

    def center_window(self):
        """Center window on screen"""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def create_ui(self):
        """Create dialog UI"""
        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        self.create_header()

        # Threats list
        self.create_threats_list()

        # Action buttons
        self.create_action_buttons()

    def create_header(self):
        """Create header section"""
        header_frame = ctk.CTkFrame(self, fg_color="transparent")
        header_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 10))
        header_frame.grid_columnconfigure(0, weight=1)

        # Title
        title = ctk.CTkLabel(
            header_frame,
            text=f"⚠️ {len(self.threats)} Threat(s) Detected",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#E74C3C"
        )
        title.grid(row=0, column=0, sticky="w")

        # Subtitle
        subtitle = ctk.CTkLabel(
            header_frame,
            text="Select threats and choose an action to perform",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        subtitle.grid(row=1, column=0, sticky="w", pady=(5, 0))

        # Select all checkbox
        select_all = ctk.CTkCheckBox(
            header_frame,
            text="Select All",
            variable=self.select_all_var,
            command=self.toggle_select_all,
            font=ctk.CTkFont(size=12)
        )
        select_all.grid(row=0, column=1, rowspan=2, padx=10)

    def create_threats_list(self):
        """Create scrollable threats list"""
        list_frame = ctk.CTkScrollableFrame(self)
        list_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=10)
        list_frame.grid_columnconfigure(0, weight=1)

        # Create threat cards
        for idx, threat in enumerate(self.threats):
            card = self.create_threat_card(list_frame, threat, idx)
            card.grid(row=idx, column=0, sticky="ew", pady=5)

    def create_threat_card(self, parent, threat: dict, index: int):
        """Create individual threat card"""
        card = ctk.CTkFrame(parent)
        card.grid_columnconfigure(1, weight=1)

        # Checkbox
        var = ctk.BooleanVar(value=False)
        self.threat_vars[index] = var

        checkbox = ctk.CTkCheckBox(
            card,
            text="",
            variable=var,
            command=self.on_threat_selection_changed
        )
        checkbox.grid(row=0, column=0, rowspan=3, padx=10, pady=10)

        # Threat icon/level
        level = threat.get('threat_level', 'Unknown')
        level_colors = {
            'Critical': '#C0392B',
            'High': '#E74C3C',
            'Medium': '#E67E22',
            'Low': '#F39C12',
            'Clean': '#2ECC71',
            'Unknown': '#95A5A6'
        }

        level_label = ctk.CTkLabel(
            card,
            text=level,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=level_colors.get(level, '#95A5A6'),
            width=70
        )
        level_label.grid(row=0, column=1, sticky="w", padx=10, pady=(10, 2))

        # File name
        file_name = threat.get('file_name', 'Unknown file')
        name_label = ctk.CTkLabel(
            card,
            text=file_name,
            font=ctk.CTkFont(size=13, weight="bold"),
            anchor="w"
        )
        name_label.grid(row=1, column=1, sticky="ew", padx=10, pady=2)

        # File path
        file_path = threat.get('file_path', 'Unknown path')
        path_label = ctk.CTkLabel(
            card,
            text=file_path,
            font=ctk.CTkFont(size=10),
            text_color="gray",
            anchor="w"
        )
        path_label.grid(row=2, column=1, sticky="ew", padx=10, pady=(2, 10))

        # Details button
        details_btn = ctk.CTkButton(
            card,
            text="Details",
            command=lambda t=threat: self.show_threat_details(t),
            width=80,
            height=30
        )
        details_btn.grid(row=0, column=2, rowspan=3, padx=10, pady=10)

        return card

    def create_action_buttons(self):
        """Create action buttons"""
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=(10, 20))
        button_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        # Quarantine button
        quarantine_btn = ctk.CTkButton(
            button_frame,
            text="🔒 Quarantine Selected",
            command=self.quarantine_selected,
            height=40,
            fg_color="#E67E22",
            hover_color="#D35400",
            font=ctk.CTkFont(size=13)
        )
        quarantine_btn.grid(row=0, column=0, padx=5, sticky="ew")

        # Delete button
        delete_btn = ctk.CTkButton(
            button_frame,
            text="🗑️ Delete Selected",
            command=self.delete_selected,
            height=40,
            fg_color="#E74C3C",
            hover_color="#C0392B",
            font=ctk.CTkFont(size=13)
        )
        delete_btn.grid(row=0, column=1, padx=5, sticky="ew")

        # Analyze button
        analyze_btn = ctk.CTkButton(
            button_frame,
            text="🔍 Analyze Selected",
            command=self.analyze_selected,
            height=40,
            fg_color="#3498DB",
            hover_color="#2980B9",
            font=ctk.CTkFont(size=13)
        )
        analyze_btn.grid(row=0, column=2, padx=5, sticky="ew")

        # Ignore button
        ignore_btn = ctk.CTkButton(
            button_frame,
            text="⏭️ Ignore Selected",
            command=self.ignore_selected,
            height=40,
            fg_color="#95A5A6",
            hover_color="#7F8C8D",
            font=ctk.CTkFont(size=13)
        )
        ignore_btn.grid(row=0, column=3, padx=5, sticky="ew")

        # Close button
        close_btn = ctk.CTkButton(
            button_frame,
            text="✖️ Close",
            command=self.close_dialog,
            height=40,
            fg_color="transparent",
            border_width=2,
            font=ctk.CTkFont(size=13)
        )
        close_btn.grid(row=0, column=4, padx=5, sticky="ew")

    def toggle_select_all(self):
        """Toggle all threat selections"""
        select_all = self.select_all_var.get()

        for var in self.threat_vars.values():
            var.set(select_all)

    def on_threat_selection_changed(self):
        """Handle individual threat selection change"""
        # Check if all are selected
        all_selected = all(var.get() for var in self.threat_vars.values())
        self.select_all_var.set(all_selected)

    def get_selected_threats(self) -> list:
        """Get list of selected threats"""
        selected = []

        for idx, var in self.threat_vars.items():
            if var.get():
                selected.append(self.threats[idx])

        return selected

    def quarantine_selected(self):
        """Quarantine selected threats"""
        selected = self.get_selected_threats()

        if not selected:
            messagebox.showwarning("No Selection", "Please select threats to quarantine")
            return

        response = messagebox.askyesno(
            "Quarantine Threats",
            f"Quarantine {len(selected)} selected threat(s)?\n\n"
            "Files will be moved to secure quarantine and can be restored later."
        )

        if response:
            quarantine_dir = os.path.join(os.path.expanduser("~"), ".fixion", "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)

            success_count = 0

            for threat in selected:
                try:
                    file_path = threat.get('file_path')
                    if file_path and os.path.exists(file_path):
                        # Generate quarantine filename
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        file_name = os.path.basename(file_path)
                        quarantine_path = os.path.join(
                            quarantine_dir,
                            f"{timestamp}_{file_name}.quarantine"
                        )

                        # Move file to quarantine
                        shutil.move(file_path, quarantine_path)

                        # Add to database
                        self.db.add_to_quarantine({
                            'file_name': file_name,
                            'original_path': file_path,
                            'quarantine_path': quarantine_path,
                            'threat_level': threat.get('threat_level', 'Unknown')
                        })

                        # Update threat status
                        threat['status'] = 'quarantined'
                        self.db.add_threat_report(threat)

                        success_count += 1
                except Exception as e:
                    print(f"Error quarantining {threat.get('file_name', 'unknown')}: {e}")

            messagebox.showinfo(
                "Quarantine Complete",
                f"Successfully quarantined {success_count} of {len(selected)} threat(s)"
            )

            # Update parent dashboard
            if hasattr(self.parent, 'update_dashboard_stats'):
                self.parent.update_dashboard_stats()
                self.parent.load_quarantine_list()

            self.close_dialog()

    def delete_selected(self):
        """Delete selected threats permanently"""
        selected = self.get_selected_threats()

        if not selected:
            messagebox.showwarning("No Selection", "Please select threats to delete")
            return

        response = messagebox.askyesno(
            "Delete Threats",
            f"Permanently delete {len(selected)} selected threat(s)?\n\n"
            "⚠️ WARNING: This action cannot be undone!"
        )

        if response:
            # Double confirmation for safety
            confirm = messagebox.askyesno(
                "Confirm Deletion",
                "Are you absolutely sure you want to permanently delete these files?",
                icon='warning'
            )

            if not confirm:
                return

            success_count = 0

            for threat in selected:
                try:
                    file_path = threat.get('file_path')
                    if file_path and os.path.exists(file_path):
                        os.remove(file_path)

                        # Update threat status
                        threat['status'] = 'deleted'
                        self.db.add_threat_report(threat)

                        success_count += 1
                except Exception as e:
                    print(f"Error deleting {threat.get('file_name', 'unknown')}: {e}")

            messagebox.showinfo(
                "Deletion Complete",
                f"Successfully deleted {success_count} of {len(selected)} threat(s)"
            )

            # Update parent dashboard
            if hasattr(self.parent, 'update_dashboard_stats'):
                self.parent.update_dashboard_stats()

            self.close_dialog()

    def analyze_selected(self):
        """Analyze selected threats in sandbox"""
        selected = self.get_selected_threats()

        if not selected:
            messagebox.showwarning("No Selection", "Please select threats to analyze")
            return

        # Show progress dialog
        progress = ctk.CTkToplevel(self)
        progress.title("Analyzing Threats")
        progress.geometry("500x200")
        progress.transient(self)
        progress.grab_set()

        # Progress info
        info_label = ctk.CTkLabel(
            progress,
            text=f"Analyzing {len(selected)} threat(s) in sandbox...",
            font=ctk.CTkFont(size=14)
        )
        info_label.pack(pady=20)

        current_label = ctk.CTkLabel(
            progress,
            text="",
            font=ctk.CTkFont(size=12)
        )
        current_label.pack(pady=10)

        progress_bar = ctk.CTkProgressBar(progress, width=400)
        progress_bar.pack(pady=20)
        progress_bar.set(0)

        results_label = ctk.CTkLabel(
            progress,
            text="",
            font=ctk.CTkFont(size=12),
            text_color="gray"
        )
        results_label.pack(pady=10)

        def analyze():
            results = []  # Store SandboxReport objects
            total = len(selected)

            for idx, threat in enumerate(selected):
                try:
                    # Update progress
                    current_label.configure(
                        text=f"Analyzing: {threat.get('file_name', 'Unknown')}"
                    )
                    progress_bar.set((idx + 1) / total)

                    # Perform analysis
                    file_path = threat.get('file_path')
                    if file_path and os.path.exists(file_path):
                        # Get full SandboxReport object
                        sandbox_report = self.sandbox_analyzer.analyze_file(file_path)
                        results.append(sandbox_report)

                        # Update threat in database
                        from dataclasses import asdict
                        threat_update = {
                            'file_path': file_path,
                            'file_name': threat.get('file_name', os.path.basename(file_path)),
                            'threat_level': sandbox_report.risk_level,
                            'threat_type': sandbox_report.threat_type,
                            'verdict': sandbox_report.verdict,
                            'risk_score': sandbox_report.risk_score,
                            'ai_score': sandbox_report.ember_score
                        }
                        self.db.add_threat_report(threat_update)

                except Exception as e:
                    print(f"Analysis error for {threat.get('file_name', 'unknown')}: {e}")

            # Show results
            progress.destroy()

            if results:
                self.show_batch_analysis_results(results)
            else:
                messagebox.showinfo(
                    "Analysis Complete",
                    "Analysis completed but no results available"
                )

        # Start analysis in thread
        import threading
        thread = threading.Thread(target=analyze)
        thread.daemon = True
        thread.start()

    def show_batch_analysis_results(self, results: list):
        """Show results from batch analysis with detailed report viewer"""
        from client.gui.dialogs.sandbox_report_viewer import SandboxReportViewer
        from dataclasses import asdict

        results_dialog = ctk.CTkToplevel(self)
        results_dialog.title("Sandbox Analysis Results")
        results_dialog.geometry("800x600")
        results_dialog.transient(self)

        # Header
        header = ctk.CTkLabel(
            results_dialog,
            text=f"Sandbox Analysis Complete - {len(results)} File(s) Analyzed",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        header.pack(pady=20)

        # Results list
        results_frame = ctk.CTkScrollableFrame(results_dialog)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        for report in results:
            card = ctk.CTkFrame(results_frame, fg_color="#1a1c24")
            card.pack(fill="x", pady=8, padx=5)

            content = ctk.CTkFrame(card, fg_color="transparent")
            content.pack(fill="x", padx=15, pady=15)
            content.grid_columnconfigure(1, weight=1)

            # File name
            name_label = ctk.CTkLabel(
                content,
                text=os.path.basename(report.file_path),
                font=ctk.CTkFont(size=15, weight="bold"),
                anchor="w"
            )
            name_label.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 8))

            # Risk level with color
            risk_colors = {
                'CRITICAL': '#dc2626',
                'HIGH': '#ef4444',
                'MEDIUM': '#f59e0b',
                'LOW': '#10b981',
                'CLEAN': '#22c55e'
            }

            risk_label = ctk.CTkLabel(
                content,
                text=f"Risk: {report.risk_level}",
                font=ctk.CTkFont(size=12),
                text_color=risk_colors.get(report.risk_level, '#94a3b8')
            )
            risk_label.grid(row=1, column=0, sticky="w", pady=2)

            # Verdict
            verdict_label = ctk.CTkLabel(
                content,
                text=f"Verdict: {report.verdict}",
                font=ctk.CTkFont(size=12),
                text_color="#94a3b8"
            )
            verdict_label.grid(row=2, column=0, sticky="w", pady=2)

            # Threat type
            type_label = ctk.CTkLabel(
                content,
                text=f"Type: {report.threat_type}",
                font=ctk.CTkFont(size=12),
                text_color="#94a3b8"
            )
            type_label.grid(row=3, column=0, sticky="w", pady=2)

            # View Report button
            def show_detailed_report(sandbox_report=report):
                # Convert SandboxReport to viewer format
                viewer_data = {
                    'file_info': {
                        'name': os.path.basename(sandbox_report.file_path),
                        'size_mb': round(sandbox_report.file_size / (1024 * 1024), 2) if sandbox_report.file_size > 0 else 0,
                        'extension': sandbox_report.file_type,
                        'sha256': sandbox_report.file_hash
                    },
                    'execution_status': 'executed' if self.sandbox_analyzer.sandbox_available else 'sandbox_unavailable',
                    'verdict': sandbox_report.verdict.lower().replace(' ', '_').replace(':', ''),
                    'confidence': int(sandbox_report.confidence * 100),
                    'ai_threat_assessment': {
                        'ai_score': sandbox_report.ember_score,
                        'threat_level': sandbox_report.risk_level.lower(),
                        'model': 'EMBER AI Model'
                    },
                    'risk_breakdown': {},
                    'behavior_analysis': {
                        'total_suspicious': len(sandbox_report.threat_behaviors),
                        'suspicious_behaviors': [
                            {
                                'category': b.get('category', 'unknown'),
                                'severity': b.get('severity', 'unknown'),
                                'description': b.get('description', '')
                            }
                            for b in sandbox_report.threat_behaviors
                        ]
                    },
                    'network_activity': {
                        'total_connections': len(sandbox_report.network_connections),
                        'unique_remote_ips': len(set(
                            conn.get('remote_address', '')
                            for conn in sandbox_report.network_connections
                        )),
                        'connections': sandbox_report.network_connections
                    },
                    'file_operations': {
                        'total': len(sandbox_report.files_created) + len(sandbox_report.files_modified) + len
                            (sandbox_report.files_deleted),
                        'created': len(sandbox_report.files_created),
                        'modified': len(sandbox_report.files_modified),
                        'deleted': len(sandbox_report.files_deleted),
                        'operations': [
                                          {'action': 'created', 'path': f} for f in sandbox_report.files_created
                                      ] + [
                                          {'action': 'modified', 'path': f} for f in sandbox_report.files_modified
                                      ] + [
                                          {'action': 'deleted', 'path': f} for f in sandbox_report.files_deleted
                                      ]
                    },
                    'timeline': [
                        {
                            'timestamp': sandbox_report.timestamp,
                            'category': 'detection',
                            'event': f"File analyzed - {sandbox_report.verdict}"
                        }
                    ],
                    'timestamp': sandbox_report.timestamp
                }

                # Show detailed report viewer
                viewer = SandboxReportViewer(
                    results_dialog,
                    viewer_data,
                    os.path.basename(sandbox_report.file_path)
                )

            view_btn = ctk.CTkButton(
                content,
                text="📋 View Detailed Report",
                command=show_detailed_report,
                width=180,
                height=35,
                fg_color="#047eaf",
                hover_color="#036a91"
            )
            view_btn.grid(row=1, column=1, rowspan=3, padx=(10, 0), sticky="e")

        # Close button
        close_btn = ctk.CTkButton(
            results_dialog,
            text="Close",
            command=results_dialog.destroy,
            width=150,
            height=40
        )
        close_btn.pack(pady=20)

    def ignore_selected(self):
        """Ignore selected threats"""
        selected = self.get_selected_threats()

        if not selected:
            messagebox.showwarning("No Selection", "Please select threats to ignore")
            return

        response = messagebox.askyesno(
            "Ignore Threats",
            f"Ignore {len(selected)} selected threat(s)?\n\n"
            "These files will not be quarantined or deleted."
        )

        if response:
            for threat in selected:
                # Update threat status
                threat['status'] = 'ignored'
                self.db.add_threat_report(threat)

            messagebox.showinfo(
                "Threats Ignored",
                f"{len(selected)} threat(s) have been ignored"
            )

            self.close_dialog()

    def show_threat_details(self, threat: dict):
        """Show detailed information about a threat"""
        details_dialog = ctk.CTkToplevel(self)
        details_dialog.title("Threat Details")
        details_dialog.geometry("600x500")
        details_dialog.transient(self)

        # Header
        header = ctk.CTkLabel(
            details_dialog,
            text=threat.get('file_name', 'Unknown'),
            font=ctk.CTkFont(size=18, weight="bold")
        )
        header.pack(pady=20)

        # Details frame
        details_frame = ctk.CTkScrollableFrame(details_dialog)
        details_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Display all threat information
        info_items = [
            ("File Path", threat.get('file_path', 'Unknown')),
            ("Threat Level", threat.get('threat_level', 'Unknown')),
            ("Threat Type", threat.get('threat_type', 'Unknown')),
            ("Status", threat.get('status', 'Unknown')),
            ("Timestamp", threat.get('timestamp', 'Unknown'))
        ]

        for key, value in info_items:
            row = ctk.CTkFrame(details_frame)
            row.pack(fill="x", pady=5)

            ctk.CTkLabel(
                row,
                text=f"{key}:",
                font=ctk.CTkFont(weight="bold"),
                width=120,
                anchor="w"
            ).pack(side="left", padx=10)

            ctk.CTkLabel(
                row,
                text=str(value),
                anchor="w"
            ).pack(side="left", padx=10, fill="x", expand=True)

        # Additional details
        if threat.get('details'):
            details_label = ctk.CTkLabel(
                details_frame,
                text="Additional Details:",
                font=ctk.CTkFont(weight="bold")
            )
            details_label.pack(anchor="w", padx=10, pady=(20, 5))

            details_text = ctk.CTkTextbox(details_frame, height=150)
            details_text.pack(fill="x", padx=10, pady=5)
            details_text.insert("1.0", str(threat.get('details')))
            details_text.configure(state="disabled")

        # Close button
        close_btn = ctk.CTkButton(
            details_dialog,
            text="Close",
            command=details_dialog.destroy,
            width=150
        )
        close_btn.pack(pady=20)

    def close_dialog(self):
        """Close the dialog"""
        self.grab_release()
        self.destroy()