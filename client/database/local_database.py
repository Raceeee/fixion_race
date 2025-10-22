import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
import hashlib


class LocalDatabase:
    """Complete local database with sandbox report storage"""

    def __init__(self, db_path: str = "fixion_data.db"):
        self.db_path = db_path
        self.connection = None
        self.initialize_database()

    def get_connection(self):
        """Get database connection (thread-safe)"""
        if self.connection is None:
            self.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self.connection.row_factory = sqlite3.Row
        return self.connection

    def initialize_database(self):
        """Initialize database with all tables"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Scan history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                threats_found INTEGER DEFAULT 0,
                files_scanned INTEGER DEFAULT 0,
                status TEXT,
                duration_seconds INTEGER,
                sync_status TEXT DEFAULT 'pending',
                synced_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Threat reports table - ENHANCED with EMBER intelligence
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                threat_level TEXT,
                ai_score REAL,
                status TEXT,
                action_taken TEXT,
                timestamp TEXT NOT NULL,
                scan_id INTEGER,
                sandbox_report_id INTEGER,
                sync_status TEXT DEFAULT 'pending',
                synced_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,

                -- EMBER Intelligence Fields (NEW)
                threat_type TEXT,
                threat_family TEXT,
                confidence REAL,
                reputation_score REAL,
                threat_behaviors TEXT,
                capabilities TEXT,
                infection_method TEXT,
                affected_files TEXT,
                affected_directories TEXT,
                network_indicators TEXT,
                registry_modifications TEXT,
                persistence_mechanisms TEXT,
                risk_assessment TEXT,
                mitigation_steps TEXT,
                heuristic_flags TEXT,
                signature_info TEXT,
                false_positive_likelihood REAL,

                FOREIGN KEY (scan_id) REFERENCES scan_history(id),
                FOREIGN KEY (sandbox_report_id) REFERENCES sandbox_reports(id)
            )
        """)

        # Sandbox reports table (NEW)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sandbox_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT,
                execution_status TEXT,
                verdict TEXT,
                confidence REAL,
                ai_score REAL,
                threat_level TEXT,
                analysis_type TEXT,
                report_data TEXT,
                charts_data TEXT,
                timestamp TEXT NOT NULL,
                duration_seconds INTEGER,
                sync_status TEXT DEFAULT 'pending',
                synced_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Behavior analysis table (for sandbox)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS behavior_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sandbox_report_id INTEGER NOT NULL,
                category TEXT,
                severity TEXT,
                description TEXT,
                timestamp TEXT,
                sync_status TEXT DEFAULT 'pending',
                FOREIGN KEY (sandbox_report_id) REFERENCES sandbox_reports(id)
            )
        """)

        # Network activity table (for sandbox)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS network_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sandbox_report_id INTEGER NOT NULL,
                remote_address TEXT,
                remote_port INTEGER,
                local_address TEXT,
                local_port INTEGER,
                state TEXT,
                timestamp TEXT,
                sync_status TEXT DEFAULT 'pending',
                FOREIGN KEY (sandbox_report_id) REFERENCES sandbox_reports(id)
            )
        """)

        # File operations table (for sandbox)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_operations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sandbox_report_id INTEGER NOT NULL,
                action TEXT,
                file_path TEXT,
                timestamp TEXT,
                sync_status TEXT DEFAULT 'pending',
                FOREIGN KEY (sandbox_report_id) REFERENCES sandbox_reports(id)
            )
        """)

        # Quarantine table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_name TEXT NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL,
                file_hash TEXT,
                threat_level TEXT,
                reason TEXT,
                timestamp TEXT NOT NULL,
                restored BOOLEAN DEFAULT 0,
                sync_status TEXT DEFAULT 'pending',
                synced_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Snapshots table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                snapshot_id TEXT UNIQUE NOT NULL,
                description TEXT,
                restore_point_id TEXT,
                size_mb REAL,
                status TEXT,
                timestamp TEXT NOT NULL,
                sync_status TEXT DEFAULT 'pending',
                synced_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Sync log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sync_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_type TEXT NOT NULL,
                status TEXT NOT NULL,
                items_synced INTEGER DEFAULT 0,
                error_message TEXT,
                timestamp TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # File hashes table (NEW - for adaptive scan skipping)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_path TEXT UNIQUE NOT NULL,
                file_hash TEXT NOT NULL,
                last_scanned TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Run schema migrations for existing databases
        self._run_migrations(cursor)

        conn.commit()

    def _run_migrations(self, cursor):
        """Run database schema migrations for existing tables"""

        # Migrate scan_history table
        cursor.execute("PRAGMA table_info(scan_history)")
        scan_columns = [row[1] for row in cursor.fetchall()]

        if scan_columns:
            if 'files_scanned' not in scan_columns:
                print("Migrating scan_history table: adding 'files_scanned' column...")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN files_scanned INTEGER DEFAULT 0")

            if 'duration_seconds' not in scan_columns:
                print("Migrating scan_history table: adding 'duration_seconds' column...")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN duration_seconds INTEGER")

            if 'sync_status' not in scan_columns:
                print("Migrating scan_history table: adding 'sync_status' column...")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN sync_status TEXT DEFAULT 'pending'")

            if 'synced_at' not in scan_columns:
                print("Migrating scan_history table: adding 'synced_at' column...")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN synced_at TEXT")

            if 'created_at' not in scan_columns:
                print("Migrating scan_history table: adding 'created_at' column...")
                cursor.execute("ALTER TABLE scan_history ADD COLUMN created_at TEXT")

        # Migrate threat_reports table
        cursor.execute("PRAGMA table_info(threat_reports)")
        threat_columns = [row[1] for row in cursor.fetchall()]

        if threat_columns:
            if 'ai_score' not in threat_columns:
                print("Migrating threat_reports table: adding 'ai_score' column...")
                cursor.execute("ALTER TABLE threat_reports ADD COLUMN ai_score REAL")

            if 'sandbox_report_id' not in threat_columns:
                print("Migrating threat_reports table: adding 'sandbox_report_id' column...")
                cursor.execute("ALTER TABLE threat_reports ADD COLUMN sandbox_report_id INTEGER")

            if 'sync_status' not in threat_columns:
                print("Migrating threat_reports table: adding 'sync_status' column...")
                cursor.execute("ALTER TABLE threat_reports ADD COLUMN sync_status TEXT DEFAULT 'pending'")

            if 'synced_at' not in threat_columns:
                print("Migrating threat_reports table: adding 'synced_at' column...")
                cursor.execute("ALTER TABLE threat_reports ADD COLUMN synced_at TEXT")

            if 'created_at' not in threat_columns:
                print("Migrating threat_reports table: adding 'created_at' column...")
                cursor.execute("ALTER TABLE threat_reports ADD COLUMN created_at TEXT")

            # EMBER Intelligence Fields Migration (NEW)
            ember_fields = [
                ('threat_type', 'TEXT'),
                ('threat_family', 'TEXT'),
                ('confidence', 'REAL'),
                ('reputation_score', 'REAL'),
                ('threat_behaviors', 'TEXT'),
                ('capabilities', 'TEXT'),
                ('infection_method', 'TEXT'),
                ('affected_files', 'TEXT'),
                ('affected_directories', 'TEXT'),
                ('network_indicators', 'TEXT'),
                ('registry_modifications', 'TEXT'),
                ('persistence_mechanisms', 'TEXT'),
                ('risk_assessment', 'TEXT'),
                ('mitigation_steps', 'TEXT'),
                ('heuristic_flags', 'TEXT'),
                ('signature_info', 'TEXT'),
                ('false_positive_likelihood', 'REAL')
            ]

            for field_name, field_type in ember_fields:
                if field_name not in threat_columns:
                    print(f"Migrating threat_reports table: adding EMBER field '{field_name}'...")
                    cursor.execute(f"ALTER TABLE threat_reports ADD COLUMN {field_name} {field_type}")

        # Migrate quarantine table
        cursor.execute("PRAGMA table_info(quarantine)")
        quarantine_columns = [row[1] for row in cursor.fetchall()]

        if quarantine_columns:
            if 'restored' not in quarantine_columns:
                print("Migrating quarantine table: adding 'restored' column...")
                cursor.execute("ALTER TABLE quarantine ADD COLUMN restored BOOLEAN DEFAULT 0")

            if 'sync_status' not in quarantine_columns:
                print("Migrating quarantine table: adding 'sync_status' column...")
                cursor.execute("ALTER TABLE quarantine ADD COLUMN sync_status TEXT DEFAULT 'pending'")

            if 'synced_at' not in quarantine_columns:
                print("Migrating quarantine table: adding 'synced_at' column...")
                cursor.execute("ALTER TABLE quarantine ADD COLUMN synced_at TEXT")

            if 'created_at' not in quarantine_columns:
                print("Migrating quarantine table: adding 'created_at' column...")
                cursor.execute("ALTER TABLE quarantine ADD COLUMN created_at TEXT")

        # Migrate snapshots table
        cursor.execute("PRAGMA table_info(snapshots)")
        snapshot_columns = [row[1] for row in cursor.fetchall()]

        if snapshot_columns:
            if 'sync_status' not in snapshot_columns:
                print("Migrating snapshots table: adding 'sync_status' column...")
                cursor.execute("ALTER TABLE snapshots ADD COLUMN sync_status TEXT DEFAULT 'pending'")

            if 'synced_at' not in snapshot_columns:
                print("Migrating snapshots table: adding 'synced_at' column...")
                cursor.execute("ALTER TABLE snapshots ADD COLUMN synced_at TEXT")

            if 'created_at' not in snapshot_columns:
                print("Migrating snapshots table: adding 'created_at' column...")
                cursor.execute("ALTER TABLE snapshots ADD COLUMN created_at TEXT")

    # ==================== SANDBOX REPORTS ====================

    def add_sandbox_report(self, report_data: Dict[str, Any]) -> int:
        """
        Add sandbox analysis report to database

        Args:
            report_data: Complete sandbox report dictionary

        Returns:
            ID of inserted report
        """
        conn = self.get_connection()
        cursor = conn.cursor()

        # Extract file info
        file_info = report_data.get('file_info', {})
        ai_assessment = report_data.get('ai_threat_assessment', {})

        # Calculate duration if timestamps available
        duration = None
        if 'start_time' in report_data and 'end_time' in report_data:
            try:
                start = datetime.fromisoformat(report_data['start_time'])
                end = datetime.fromisoformat(report_data['end_time'])
                duration = int((end - start).total_seconds())
            except:
                pass

        # Insert main report
        cursor.execute("""
            INSERT INTO sandbox_reports (
                file_name, file_path, file_hash, execution_status,
                verdict, confidence, ai_score, threat_level,
                analysis_type, report_data, charts_data, timestamp,
                duration_seconds, sync_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            file_info.get('name', 'Unknown'),
            file_info.get('path', ''),
            file_info.get('sha256', ''),
            report_data.get('execution_status', 'unknown'),
            report_data.get('verdict', 'unknown'),
            report_data.get('confidence', 0),
            ai_assessment.get('ai_score', 0),
            ai_assessment.get('threat_level', 'unknown'),
            report_data.get('behavior_analysis', {}).get('analysis_type', 'dynamic'),
            json.dumps(report_data),
            json.dumps(report_data.get('charts', {})),
            report_data.get('timestamp', datetime.now().isoformat()),
            duration
        ))

        report_id = cursor.lastrowid

        # Insert behavior analysis
        behaviors = report_data.get('behavior_analysis', {}).get('suspicious_behaviors', [])
        for behavior in behaviors:
            cursor.execute("""
                INSERT INTO behavior_analysis (
                    sandbox_report_id, category, severity, description, timestamp
                ) VALUES (?, ?, ?, ?, ?)
            """, (
                report_id,
                behavior.get('category', 'unknown'),
                behavior.get('severity', 'unknown'),
                behavior.get('description', ''),
                datetime.now().isoformat()
            ))

        # Insert network activity
        connections = report_data.get('network_activity', {}).get('connections', [])
        for conn_data in connections[:50]:  # Limit to 50
            cursor.execute("""
                INSERT INTO network_activity (
                    sandbox_report_id, remote_address, remote_port,
                    local_address, local_port, state, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                conn_data.get('remote_address', ''),
                conn_data.get('remote_port', 0),
                conn_data.get('local_address', ''),
                conn_data.get('local_port', 0),
                conn_data.get('state', ''),
                conn_data.get('timestamp', datetime.now().isoformat())
            ))

        # Insert file operations
        operations = report_data.get('file_operations', {}).get('operations', [])
        for op in operations[:100]:  # Limit to 100
            cursor.execute("""
                INSERT INTO file_operations (
                    sandbox_report_id, action, file_path, timestamp
                ) VALUES (?, ?, ?, ?)
            """, (
                report_id,
                op.get('action', ''),
                op.get('path', ''),
                op.get('timestamp', datetime.now().isoformat())
            ))

        conn.commit()
        return report_id

    def get_sandbox_report(self, report_id: int) -> Optional[Dict[str, Any]]:
        """Get sandbox report by ID"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM sandbox_reports WHERE id = ?", (report_id,))
        row = cursor.fetchone()

        if row:
            report = dict(row)

            # Parse JSON data
            if report.get('report_data'):
                try:
                    report['report_data'] = json.loads(report['report_data'])
                except:
                    pass

            if report.get('charts_data'):
                try:
                    report['charts_data'] = json.loads(report['charts_data'])
                except:
                    pass

            # Get related data
            report['behaviors'] = self.get_sandbox_behaviors(report_id)
            report['network_activity'] = self.get_sandbox_network_activity(report_id)
            report['file_operations'] = self.get_sandbox_file_operations(report_id)

            return report

        return None

    def get_sandbox_behaviors(self, report_id: int) -> List[Dict[str, Any]]:
        """Get behavior analysis for sandbox report"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM behavior_analysis 
            WHERE sandbox_report_id = ?
            ORDER BY timestamp DESC
        """, (report_id,))

        return [dict(row) for row in cursor.fetchall()]

    def get_sandbox_network_activity(self, report_id: int) -> List[Dict[str, Any]]:
        """Get network activity for sandbox report"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM network_activity 
            WHERE sandbox_report_id = ?
            ORDER BY timestamp DESC
        """, (report_id,))

        return [dict(row) for row in cursor.fetchall()]

    def get_sandbox_file_operations(self, report_id: int) -> List[Dict[str, Any]]:
        """Get file operations for sandbox report"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM file_operations 
            WHERE sandbox_report_id = ?
            ORDER BY timestamp DESC
        """, (report_id,))

        return [dict(row) for row in cursor.fetchall()]

    def get_sandbox_reports(self, limit: int = 50, unsynced_only: bool = False) -> List[Dict[str, Any]]:
        """Get sandbox reports"""
        conn = self.get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM sandbox_reports"

        if unsynced_only:
            query += " WHERE sync_status = 'pending'"

        query += " ORDER BY timestamp DESC LIMIT ?"

        cursor.execute(query, (limit,))

        reports = []
        for row in cursor.fetchall():
            report = dict(row)

            # Parse JSON
            if report.get('report_data'):
                try:
                    report['report_data'] = json.loads(report['report_data'])
                except:
                    pass

            reports.append(report)

        return reports

    def mark_sandbox_report_synced(self, report_id: int):
        """Mark sandbox report as synced"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE sandbox_reports 
            SET sync_status = 'synced', synced_at = ?
            WHERE id = ?
        """, (datetime.now().isoformat(), report_id))

        # Also mark related data as synced
        cursor.execute("""
            UPDATE behavior_analysis 
            SET sync_status = 'synced'
            WHERE sandbox_report_id = ?
        """, (report_id,))

        cursor.execute("""
            UPDATE network_activity 
            SET sync_status = 'synced'
            WHERE sandbox_report_id = ?
        """, (report_id,))

        cursor.execute("""
            UPDATE file_operations 
            SET sync_status = 'synced'
            WHERE sandbox_report_id = ?
        """, (report_id,))

        conn.commit()

    # ==================== EXISTING METHODS ====================

    def add_scan_history(self, scan_data: Dict[str, Any]) -> int:
        """Add scan to history"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO scan_history (
                type, timestamp, threats_found, files_scanned, 
                status, duration_seconds, sync_status
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
        """, (
            scan_data.get('type', 'unknown'),
            scan_data.get('timestamp', datetime.now().isoformat()),
            scan_data.get('threats_found', 0),
            scan_data.get('files_scanned', 0),
            scan_data.get('status', 'completed'),
            scan_data.get('duration_seconds', 0)
        ))

        scan_id = cursor.lastrowid
        conn.commit()
        return scan_id

    def add_threat_report(self, threat_data: Dict[str, Any], sandbox_report_id: Optional[int] = None) -> int:
        """Add threat report (can link to sandbox report)"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO threat_reports (
                file_name, file_path, file_hash, threat_level, 
                ai_score, status, action_taken, timestamp, 
                sandbox_report_id, sync_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            threat_data.get('file_name', 'Unknown'),
            threat_data.get('file_path', ''),
            threat_data.get('file_hash', ''),
            threat_data.get('threat_level', 'unknown'),
            threat_data.get('ai_score', 0),
            threat_data.get('status', 'detected'),
            threat_data.get('action_taken', ''),
            threat_data.get('timestamp', datetime.now().isoformat()),
            sandbox_report_id
        ))

        threat_id = cursor.lastrowid
        conn.commit()
        return threat_id

    def get_threat_reports(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get threat reports"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM threat_reports 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (limit,))

        return [dict(row) for row in cursor.fetchall()]

    def add_quarantine_item(self, quarantine_data: Dict[str, Any]) -> int:
        """Add item to quarantine"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO quarantine (
                file_name, original_path, quarantine_path, 
                file_hash, threat_level, reason, timestamp, sync_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
        """, (
            quarantine_data.get('file_name', 'Unknown'),
            quarantine_data.get('original_path', ''),
            quarantine_data.get('quarantine_path', ''),
            quarantine_data.get('file_hash', ''),
            quarantine_data.get('threat_level', 'unknown'),
            quarantine_data.get('reason', ''),
            quarantine_data.get('timestamp', datetime.now().isoformat())
        ))

        item_id = cursor.lastrowid
        conn.commit()
        return item_id

    def get_quarantine_items(self) -> List[Dict[str, Any]]:
        """Get all quarantine items"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM quarantine 
            WHERE restored = 0 
            ORDER BY timestamp DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    def delete_quarantine_item(self, item_id: int):
        """Delete quarantine item"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM quarantine WHERE id = ?", (item_id,))
        conn.commit()

    # ==================== SNAPSHOTS ====================

    def get_snapshots(self, limit: int = None) -> List[Dict[str, Any]]:
        """Get all snapshots"""
        conn = self.get_connection()
        cursor = conn.cursor()

        query = "SELECT * FROM snapshots ORDER BY timestamp DESC"
        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query)
        return [dict(row) for row in cursor.fetchall()]

    def add_snapshot(self, snapshot_data: Dict[str, Any]) -> int:
        """Add a snapshot to the database"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO snapshots (
                snapshot_id, description, restore_point_id, 
                size_mb, status, timestamp, sync_status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            snapshot_data.get('snapshot_id'),
            snapshot_data.get('description', ''),
            snapshot_data.get('restore_point_id'),
            snapshot_data.get('size_mb', 0),
            snapshot_data.get('status', 'active'),
            snapshot_data.get('timestamp', datetime.now().isoformat()),
            'pending'
        ))

        conn.commit()
        return cursor.lastrowid

    def delete_snapshot(self, snapshot_id: str):
        """Delete a snapshot"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM snapshots WHERE snapshot_id = ?", (snapshot_id,))
        conn.commit()

    # ==================== SETTINGS ====================

    def set_setting(self, key: str, value: str):
        """Set a setting"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
        """, (key, value, datetime.now().isoformat()))

        conn.commit()

    def get_setting(self, key: str, default: Any = None) -> Any:
        """Get a setting"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()

        return row['value'] if row else default

    def get_settings(self) -> Dict[str, str]:
        """Get all settings"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT key, value FROM settings")

        return {row['key']: row['value'] for row in cursor.fetchall()}

    # ==================== SYNC METHODS ====================

    def get_unsynced_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all unsynced data for server sync"""
        return {
            'scans': self.get_unsynced_scans(),
            'threats': self.get_unsynced_threats(),
            'sandbox_reports': self.get_sandbox_reports(limit=100, unsynced_only=True),
            'quarantine': self.get_unsynced_quarantine(),
            'snapshots': self.get_unsynced_snapshots()
        }

    def get_unsynced_scans(self) -> List[Dict[str, Any]]:
        """Get unsynced scans"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM scan_history 
            WHERE sync_status = 'pending'
            ORDER BY timestamp DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    def get_unsynced_threats(self) -> List[Dict[str, Any]]:
        """Get unsynced threats"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM threat_reports 
            WHERE sync_status = 'pending'
            ORDER BY timestamp DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    def get_unsynced_quarantine(self) -> List[Dict[str, Any]]:
        """Get unsynced quarantine items"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM quarantine 
            WHERE sync_status = 'pending'
            ORDER BY timestamp DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    def get_unsynced_snapshots(self) -> List[Dict[str, Any]]:
        """Get unsynced snapshots"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM snapshots 
            WHERE sync_status = 'pending'
            ORDER BY timestamp DESC
        """)

        return [dict(row) for row in cursor.fetchall()]

    def mark_synced(self, table: str, item_ids: List[int]):
        """Mark items as synced"""
        conn = self.get_connection()
        cursor = conn.cursor()

        placeholders = ','.join('?' * len(item_ids))

        cursor.execute(f"""
            UPDATE {table}
            SET sync_status = 'synced', synced_at = ?
            WHERE id IN ({placeholders})
        """, [datetime.now().isoformat()] + item_ids)

        conn.commit()

    def log_sync(self, sync_type: str, status: str, items_synced: int = 0, error: str = None):
        """Log sync operation"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO sync_log (sync_type, status, items_synced, error_message, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (sync_type, status, items_synced, error, datetime.now().isoformat()))

        conn.commit()

    # ==================== STATISTICS ====================

    def get_threats_count(self) -> int:
        """Get total threats detected"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as count FROM threat_reports")
        row = cursor.fetchone()
        return row['count'] if row else 0

    def get_files_scanned_count(self) -> int:
        """Get total files scanned"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT SUM(files_scanned) as total FROM scan_history")
        row = cursor.fetchone()
        return row['total'] if row and row['total'] else 0

    def get_last_scan_time(self) -> Optional[str]:
        """Get last scan timestamp"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT timestamp FROM scan_history 
            ORDER BY timestamp DESC 
            LIMIT 1
        """)

        row = cursor.fetchone()
        return row['timestamp'] if row else None

    def get_sandbox_count(self) -> int:
        """Get total sandbox analyses"""
        conn = self.get_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) as count FROM sandbox_reports")
        row = cursor.fetchone()
        return row['count'] if row else 0

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive statistics for dashboard"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Total threats
        cursor.execute("SELECT COUNT(*) as count FROM threat_reports")
        total_threats = cursor.fetchone()['count']

        # Unresolved threats (not quarantined or whitelisted)
        cursor.execute("""
            SELECT COUNT(*) as count FROM threat_reports 
            WHERE status NOT IN ('quarantined', 'whitelisted', 'resolved')
        """)
        unresolved_threats = cursor.fetchone()['count']

        # Quarantined files
        cursor.execute("SELECT COUNT(*) as count FROM quarantine WHERE restored = 0")
        quarantined_files = cursor.fetchone()['count']

        # Total scans
        cursor.execute("SELECT COUNT(*) as count FROM scan_history")
        total_scans = cursor.fetchone()['count']

        # Total snapshots
        cursor.execute("SELECT COUNT(*) as count FROM snapshots")
        total_snapshots = cursor.fetchone()['count']

        # Threats in last 24 hours
        from datetime import datetime, timedelta
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute("""
            SELECT COUNT(*) as count FROM threat_reports 
            WHERE timestamp >= ?
        """, (yesterday,))
        threats_24h = cursor.fetchone()['count']

        return {
            'total_threats': total_threats,
            'unresolved_threats': unresolved_threats,
            'quarantined_files': quarantined_files,
            'total_scans': total_scans,
            'total_snapshots': total_snapshots,
            'threats_24h': threats_24h
        }

    # ==================== FILE HASH METHODS (NEW) ====================

    def get_file_hash(self, file_path: str) -> Optional[str]:
        """Get stored hash for a file path"""
        conn = self.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT file_hash FROM file_hashes WHERE file_path = ?", (file_path,))
        row = cursor.fetchone()
        return row["file_hash"] if row else None

    def update_file_hash(self, file_path: str, file_hash: str) -> None:
        """Update or insert file hash (upsert operation)"""
        conn = self.get_connection()
        cursor = conn.cursor()
        now = datetime.now().isoformat()

        try:
            # Try INSERT OR REPLACE for SQLite 3.24+
            cursor.execute(
                """
                INSERT INTO file_hashes (file_path, file_hash, last_scanned)
                VALUES (?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    file_hash=excluded.file_hash,
                    last_scanned=excluded.last_scanned
                """,
                (file_path, file_hash, now),
            )
        except Exception:
            # Fallback for older SQLite versions
            cursor.execute("SELECT id FROM file_hashes WHERE file_path = ?", (file_path,))
            if cursor.fetchone():
                cursor.execute(
                    "UPDATE file_hashes SET file_hash = ?, last_scanned = ? WHERE file_path = ?",
                    (file_hash, now, file_path),
                )
            else:
                cursor.execute(
                    "INSERT INTO file_hashes (file_path, file_hash, last_scanned) VALUES (?, ?, ?)",
                    (file_path, file_hash, now),
                )
        conn.commit()

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            self.connection = None


# ==================== EMBER INTEGRATION HELPER ====================

def create_threat_from_ember_scan(scan_result, scan_id: Optional[int] = None,
                                  sandbox_report_id: Optional[int] = None) -> Dict[str, Any]:
    """
    Create threat_data dictionary from EMBER scan result for database storage

    Args:
        scan_result: ScanResult from EMBERThreatScanner
        scan_id: Optional scan history ID
        sandbox_report_id: Optional sandbox report ID

    Returns:
        Dictionary ready for add_threat_report()
    """
    import json
    from pathlib import Path

    threat_data = {
        'file_name': Path(scan_result.file_path).name,
        'file_path': scan_result.file_path,
        'file_hash': scan_result.file_hash,
        'threat_level': scan_result.threat_level.value if hasattr(scan_result.threat_level, 'value') else str(
            scan_result.threat_level),
        'ai_score': scan_result.ai_score,
        'status': 'detected',
        'action_taken': 'pending',
        'timestamp': datetime.now().isoformat(),
    }

    # Add optional IDs
    if scan_id:
        threat_data['scan_id'] = scan_id
    if sandbox_report_id:
        threat_data['sandbox_report_id'] = sandbox_report_id

    # Add EMBER intelligence if available
    if hasattr(scan_result, 'threat_intelligence') and scan_result.threat_intelligence:
        intel = scan_result.threat_intelligence

        threat_data['threat_type'] = intel.threat_type.value if hasattr(intel.threat_type, 'value') else str(
            intel.threat_type)
        threat_data['threat_family'] = intel.threat_family
        threat_data['confidence'] = scan_result.confidence
        threat_data['reputation_score'] = scan_result.reputation_score if hasattr(scan_result,
                                                                                  'reputation_score') else 0.0

        # Serialize complex data as JSON
        threat_data['threat_behaviors'] = json.dumps([
            {
                'category': b.category,
                'description': b.description,
                'severity': b.severity,
                'indicators': b.indicators if hasattr(b, 'indicators') else []
            }
            for b in intel.behaviors
        ]) if intel.behaviors else None

        threat_data['capabilities'] = json.dumps(intel.capabilities) if intel.capabilities else None
        threat_data['infection_method'] = intel.infection_method
        threat_data['affected_files'] = json.dumps(intel.affected_files) if intel.affected_files else None
        threat_data['affected_directories'] = json.dumps(
            intel.affected_directories) if intel.affected_directories else None
        threat_data['network_indicators'] = json.dumps(intel.network_indicators) if intel.network_indicators else None
        threat_data['registry_modifications'] = json.dumps(
            intel.registry_modifications) if intel.registry_modifications else None
        threat_data['persistence_mechanisms'] = json.dumps(
            intel.persistence_mechanisms) if intel.persistence_mechanisms else None
        threat_data['risk_assessment'] = intel.risk_assessment
        threat_data['mitigation_steps'] = json.dumps(intel.mitigation_steps) if intel.mitigation_steps else None

    # Add other scan details
    if hasattr(scan_result, 'heuristic_flags'):
        threat_data['heuristic_flags'] = json.dumps(scan_result.heuristic_flags)

    if hasattr(scan_result, 'signature_info'):
        threat_data['signature_info'] = json.dumps(scan_result.signature_info)

    if hasattr(scan_result, 'false_positive_likelihood'):
        threat_data['false_positive_likelihood'] = scan_result.false_positive_likelihood

    return threat_data


if __name__ == "__main__":
    # Test database
    db = LocalDatabase("test_fixion.db")

    # Test sandbox report
    test_report = {
        'file_info': {
            'name': 'test.exe',
            'path': 'C:\\test.exe',
            'sha256': 'abc123'
        },
        'execution_status': 'executed',
        'verdict': 'malicious',
        'confidence': 85,
        'ai_threat_assessment': {
            'ai_score': 0.75,
            'threat_level': 'high'
        },
        'behavior_analysis': {
            'analysis_type': 'dynamic',
            'suspicious_behaviors': [
                {'category': 'file', 'severity': 'high', 'description': 'Modified system files'}
            ]
        },
        'network_activity': {
            'connections': [
                {'remote_address': '192.168.1.1', 'remote_port': 80, 'state': 'ESTABLISHED'}
            ]
        },
        'file_operations': {
            'operations': [
                {'action': 'created', 'path': 'C:\\malware.dll'}
            ]
        },
        'timestamp': datetime.now().isoformat()
    }

    report_id = db.add_sandbox_report(test_report)
    print(f"Added sandbox report with ID: {report_id}")

    # Get unsynced data
    unsynced = db.get_unsynced_data()
    print(f"\nUnsynced sandbox reports: {len(unsynced['sandbox_reports'])}")

    db.close()
    print("\nDatabase test complete!")