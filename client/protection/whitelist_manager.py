"""
whitelist_manager.py - Enhanced Whitelist Manager with Trust System
Manages file whitelisting, trusted publishers, and signature verification
"""

import sqlite3
import subprocess
import json
import logging
from typing import Tuple, Optional, Dict, List, Any
from pathlib import Path
import os
import time


logger = logging.getLogger(__name__)


class WhitelistManager:
    """Manages file whitelisting and trusted publishers"""

    def __init__(self, db_path: str = "whitelist.db"):
        self.db_path = db_path
        self._init_database()
        self._load_trusted_publishers()

    def _init_database(self):
        """Initialize whitelist database"""
        conn = sqlite3.connect(self.db_path)
        
        # Trusted publishers table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS trusted_publishers (
                id INTEGER PRIMARY KEY,
                publisher_name TEXT UNIQUE,
                trust_level INTEGER DEFAULT 2,
                auto_added BOOLEAN DEFAULT FALSE,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Whitelisted file hashes
        conn.execute("""
            CREATE TABLE IF NOT EXISTS whitelist_hashes (
                id INTEGER PRIMARY KEY,
                file_hash TEXT UNIQUE,
                file_path TEXT,
                reason TEXT,
                date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Scan history for learning
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                file_hash TEXT,
                file_path TEXT,
                ai_score REAL,
                reputation_score REAL,
                final_decision TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    def _load_trusted_publishers(self):
        """Load default trusted publishers"""
        trusted_publishers = [
            # Major tech companies
            ("Microsoft Corporation", 3),
            ("Microsoft Windows", 3),
            ("Apple Inc.", 3),
            ("Google LLC", 3),
            ("Adobe Inc.", 3),
            ("Adobe Systems Incorporated", 3),
            
            # Development tools
            ("Mozilla Corporation", 3),
            ("Oracle Corporation", 3),
            ("Oracle America, Inc.", 3),
            ("VMware, Inc.", 3),
            ("JetBrains s.r.o.", 3),
            ("Python Software Foundation", 3),
            ("Node.js Foundation", 3),
            ("Git Contributors", 3),
            
            # Hardware vendors
            ("Intel Corporation", 3),
            ("NVIDIA Corporation", 3),
            ("Advanced Micro Devices, Inc.", 3),
            ("AMD Inc.", 3),
            ("Realtek Semiconductor Corp.", 2),
            
            # Security companies
            ("Symantec Corporation", 3),
            ("McAfee, Inc.", 3),
            ("Kaspersky Lab", 2),
            ("ESET, spol. s r.o.", 2),
            ("Bitdefender", 2),
            
            # Common software
            ("Autodesk, Inc.", 2),
            ("Unity Technologies ApS", 2),
            ("Epic Games, Inc.", 2),
            ("Valve Corporation", 2),
            ("Electronic Arts", 2),
            ("Ubisoft", 2),
            
            # Communication tools
            ("Zoom Video Communications, Inc.", 2),
            ("Slack Technologies, Inc.", 2),
            ("Discord Inc.", 2),
            ("Skype", 2),
            
            # Utilities
            ("7-Zip", 2),
            ("VideoLAN", 2),
            ("Notepad++", 2),
            ("Foxit Software Inc.", 2)
        ]

        conn = sqlite3.connect(self.db_path)
        for publisher, trust_level in trusted_publishers:
            conn.execute(
                "INSERT OR IGNORE INTO trusted_publishers (publisher_name, trust_level, auto_added) VALUES (?, ?, ?)",
                (publisher, trust_level, True)
            )
        conn.commit()
        conn.close()

    def is_trusted_publisher(self, publisher: str) -> bool:
        """Check if publisher is trusted"""
        if not publisher:
            return False

        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT trust_level FROM trusted_publishers WHERE LOWER(publisher_name) = LOWER(?)",
            (publisher,)
        )
        result = cursor.fetchone()
        conn.close()
        
        return result is not None and result[0] >= 2

    def is_whitelisted_hash(self, file_hash: str) -> Tuple[bool, Optional[str]]:
        """Check if file hash is whitelisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute(
            "SELECT reason FROM whitelist_hashes WHERE file_hash = ?",
            (file_hash,)
        )
        result = cursor.fetchone()
        conn.close()

        if result:
            return True, result[0]
        return False, None

    def add_whitelist_hash(self, file_hash: str, file_path: str, reason: str):
        """Add file hash to whitelist"""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO whitelist_hashes (file_hash, file_path, reason) VALUES (?, ?, ?)",
            (file_hash, file_path, reason)
        )
        conn.commit()
        conn.close()
        logger.info(f"Added file to whitelist: {Path(file_path).name} - {reason}")

    def add_trusted_publisher(self, publisher_name: str, trust_level: int = 2):
        """Add a trusted publisher"""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT OR REPLACE INTO trusted_publishers (publisher_name, trust_level, auto_added) VALUES (?, ?, ?)",
            (publisher_name, trust_level, False)
        )
        conn.commit()
        conn.close()
        logger.info(f"Added trusted publisher: {publisher_name}")

    def remove_whitelist_hash(self, file_hash: str):
        """Remove file hash from whitelist"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM whitelist_hashes WHERE file_hash = ?", (file_hash,))
        conn.commit()
        conn.close()

    def remove_trusted_publisher(self, publisher_name: str):
        """Remove a trusted publisher"""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM trusted_publishers WHERE publisher_name = ?", (publisher_name,))
        conn.commit()
        conn.close()

    def log_scan_result(self, file_hash: str, file_path: str, ai_score: float,
                        reputation_score: float, final_decision: str):
        """Log scan result for analysis and learning"""
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            "INSERT INTO scan_history (file_hash, file_path, ai_score, reputation_score, final_decision) VALUES (?, ?, ?, ?, ?)",
            (file_hash, file_path, ai_score, reputation_score, final_decision)
        )
        conn.commit()
        conn.close()

    def get_whitelist_stats(self) -> Dict[str, Any]:
        """Get whitelist statistics"""
        conn = sqlite3.connect(self.db_path)

        # Count whitelisted hashes
        cursor = conn.execute("SELECT COUNT(*) FROM whitelist_hashes")
        hash_count = cursor.fetchone()[0]

        # Count trusted publishers
        cursor = conn.execute("SELECT COUNT(*) FROM trusted_publishers")
        publisher_count = cursor.fetchone()[0]

        # Get recent scan stats
        cursor = conn.execute("""
            SELECT final_decision, COUNT(*)
            FROM scan_history
            WHERE datetime(timestamp) > datetime('now', '-24 hours')
            GROUP BY final_decision
        """)
        recent_scans = dict(cursor.fetchall())

        # Get top whitelisted files
        cursor = conn.execute("""
            SELECT file_path, reason, date_added
            FROM whitelist_hashes
            ORDER BY date_added DESC
            LIMIT 10
        """)
        recent_whitelisted = cursor.fetchall()

        conn.close()

        return {
            'whitelisted_hashes': hash_count,
            'trusted_publishers': publisher_count,
            'recent_scans_24h': recent_scans,
            'recent_whitelisted': recent_whitelisted
        }

    def export_whitelist(self, export_path: str):
        """Export whitelist to JSON file"""
        conn = sqlite3.connect(self.db_path)
        
        # Get all whitelisted hashes
        cursor = conn.execute("SELECT * FROM whitelist_hashes")
        hashes = cursor.fetchall()
        
        # Get all trusted publishers
        cursor = conn.execute("SELECT * FROM trusted_publishers")
        publishers = cursor.fetchall()
        
        conn.close()
        
        export_data = {
            'export_date': time.time(),
            'whitelisted_hashes': [
                {
                    'hash': h[1],
                    'path': h[2],
                    'reason': h[3],
                    'date_added': h[4]
                }
                for h in hashes
            ],
            'trusted_publishers': [
                {
                    'name': p[1],
                    'trust_level': p[2],
                    'auto_added': p[3],
                    'date_added': p[4]
                }
                for p in publishers
            ]
        }
        
        with open(export_path, 'w') as f:
            json.dump(export_data, f, indent=2)
            
        logger.info(f"Whitelist exported to: {export_path}")

    def import_whitelist(self, import_path: str, merge: bool = True):
        """Import whitelist from JSON file"""
        with open(import_path, 'r') as f:
            import_data = json.load(f)
            
        conn = sqlite3.connect(self.db_path)
        
        if not merge:
            # Clear existing data
            conn.execute("DELETE FROM whitelist_hashes")
            conn.execute("DELETE FROM trusted_publishers")
            
        # Import hashes
        for hash_entry in import_data.get('whitelisted_hashes', []):
            conn.execute(
                "INSERT OR IGNORE INTO whitelist_hashes (file_hash, file_path, reason) VALUES (?, ?, ?)",
                (hash_entry['hash'], hash_entry['path'], hash_entry['reason'])
            )
            
        # Import publishers
        for pub_entry in import_data.get('trusted_publishers', []):
            conn.execute(
                "INSERT OR IGNORE INTO trusted_publishers (publisher_name, trust_level, auto_added) VALUES (?, ?, ?)",
                (pub_entry['name'], pub_entry['trust_level'], pub_entry['auto_added'])
            )
            
        conn.commit()
        conn.close()
        
        logger.info(f"Whitelist imported from: {import_path}")


class SignatureVerifier:
    """Verify digital signatures of files"""

    @staticmethod
    def verify_signature(file_path: str) -> Dict[str, Any]:
        """Verify digital signature using PowerShell"""
        result = {
            'is_signed': False,
            'signature_valid': False,
            'publisher': None,
            'certificate_issuer': None,
            'timestamp': None
        }

        try:
            # PowerShell command to check signature
            ps_command = f"""
            $sig = Get-AuthenticodeSignature '{file_path}'
            $result = @{{
                Status = $sig.Status.ToString()
                Publisher = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Subject }} else {{ $null }}
                Issuer = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Issuer }} else {{ $null }}
                Thumbprint = if ($sig.SignerCertificate) {{ $sig.SignerCertificate.Thumbprint }} else {{ $null }}
                TimeStamp = if ($sig.TimeStamperCertificate) {{ $sig.TimeStamperCertificate.NotBefore.ToString() }} else {{ $null }}
            }}
            $result | ConvertTo-Json -Compress
            """

            process = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=15,
                shell=True
            )

            if process.returncode == 0 and process.stdout.strip():
                try:
                    sig_info = json.loads(process.stdout.strip())

                    status = sig_info.get('Status', '')

                    if status == 'Valid':
                        result['is_signed'] = True
                        result['signature_valid'] = True
                    elif status in ['NotTrusted', 'HashMismatch', 'UnknownError']:
                        result['is_signed'] = True
                        result['signature_valid'] = False

                    # Extract publisher name from certificate subject
                    subject = sig_info.get('Publisher', '')
                    if subject and 'CN=' in subject:
                        # Extract Common Name from certificate subject
                        cn_part = subject.split('CN=')[1].split(',')[0]
                        result['publisher'] = cn_part.strip().replace('"', '')

                    result['certificate_issuer'] = sig_info.get('Issuer', '')
                    result['timestamp'] = sig_info.get('TimeStamp', '')

                except json.JSONDecodeError as e:
                    logger.debug(f"JSON decode error for {file_path}: {e}")
                except Exception as e:
                    logger.debug(f"Signature parsing error for {file_path}: {e}")

        except subprocess.TimeoutExpired:
            logger.debug(f"Signature verification timeout for {file_path}")
        except Exception as e:
            logger.debug(f"Signature verification failed for {file_path}: {e}")

        return result