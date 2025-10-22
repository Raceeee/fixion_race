"""
quarantine.py - Malware Quarantine System
Handles safe isolation and management of suspicious files
"""

import os
import shutil
import hashlib
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


class QuarantineSystem:
    """Manages quarantined files"""

    def __init__(self, quarantine_dir: str, database=None):
        """
        Initialize quarantine system

        Args:
            quarantine_dir: Directory to store quarantined files
            database: Optional database instance for logging
        """
        self.quarantine_dir = Path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.db = database

        # Create metadata directory
        self.metadata_dir = self.quarantine_dir / "metadata"
        self.metadata_dir.mkdir(exist_ok=True)

        logger.info(f"Quarantine system initialized at: {self.quarantine_dir}")

    def quarantine_file(self, file_path: str, threat_info: Dict[str, Any]) -> bool:
        """
        Quarantine a suspicious file

        Args:
            file_path: Path to file to quarantine
            threat_info: Dictionary containing threat information

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            file_path = Path(file_path)

            if not file_path.exists():
                logger.error(f"File not found for quarantine: {file_path}")
                return False

            # Generate unique ID for quarantined file
            file_hash = self._calculate_file_hash(str(file_path))
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_id = f"{timestamp}_{file_hash[:16]}"

            # Create quarantine subdirectory
            quarantine_path = self.quarantine_dir / quarantine_id
            quarantine_path.mkdir(exist_ok=True)

            # Copy file to quarantine (preserve original)
            quarantined_file = quarantine_path / file_path.name
            shutil.copy2(str(file_path), str(quarantined_file))

            # Make quarantined file read-only
            os.chmod(str(quarantined_file), 0o444)

            # Create metadata
            metadata = {
                'quarantine_id': quarantine_id,
                'original_path': str(file_path.absolute()),
                'original_name': file_path.name,
                'quarantine_path': str(quarantined_file),
                'file_hash': file_hash,
                'file_size': file_path.stat().st_size,
                'quarantine_date': datetime.now().isoformat(),
                'threat_info': threat_info,
                'status': 'quarantined'
            }

            # Save metadata
            metadata_file = self.metadata_dir / f"{quarantine_id}.json"
            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Log to database if available
            if self.db:
                try:
                    self.db.add_quarantine_entry(metadata)
                except Exception as e:
                    logger.error(f"Failed to log quarantine to database: {e}")

            logger.info(f"File quarantined successfully: {file_path.name} -> {quarantine_id}")

            # Try to delete original file
            try:
                file_path.unlink()
                logger.info(f"Original threat file deleted: {file_path}")
            except Exception as e:
                logger.warning(f"Could not delete original file {file_path}: {e}")

            return True

        except Exception as e:
            logger.error(f"Quarantine failed for {file_path}: {e}")
            return False

    def restore_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> bool:
        """
        Restore a quarantined file

        Args:
            quarantine_id: ID of quarantined file
            restore_path: Optional custom restore path

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Load metadata
            metadata_file = self.metadata_dir / f"{quarantine_id}.json"

            if not metadata_file.exists():
                logger.error(f"Metadata not found for quarantine ID: {quarantine_id}")
                return False

            with open(metadata_file, 'r') as f:
                metadata = json.load(f)

            quarantined_file = Path(metadata['quarantine_path'])

            if not quarantined_file.exists():
                logger.error(f"Quarantined file not found: {quarantined_file}")
                return False

            # Determine restore location
            if restore_path:
                target_path = Path(restore_path)
            else:
                target_path = Path(metadata['original_path'])

            # Ensure target directory exists
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Restore file
            shutil.copy2(str(quarantined_file), str(target_path))

            # Update metadata
            metadata['status'] = 'restored'
            metadata['restore_date'] = datetime.now().isoformat()
            metadata['restore_path'] = str(target_path)

            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Update database if available
            if self.db:
                try:
                    self.db.update_quarantine_status(quarantine_id, 'restored')
                except Exception as e:
                    logger.error(f"Failed to update database: {e}")

            logger.info(f"File restored successfully: {quarantine_id} -> {target_path}")
            return True

        except Exception as e:
            logger.error(f"Restore failed for {quarantine_id}: {e}")
            return False

    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """
        Permanently delete a quarantined file

        Args:
            quarantine_id: ID of quarantined file

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Load metadata
            metadata_file = self.metadata_dir / f"{quarantine_id}.json"

            if not metadata_file.exists():
                logger.error(f"Metadata not found for quarantine ID: {quarantine_id}")
                return False

            with open(metadata_file, 'r') as f:
                metadata = json.load(f)

            # Delete quarantined file directory
            quarantine_path = self.quarantine_dir / quarantine_id
            if quarantine_path.exists():
                shutil.rmtree(quarantine_path)

            # Update metadata
            metadata['status'] = 'deleted'
            metadata['delete_date'] = datetime.now().isoformat()

            with open(metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)

            # Update database if available
            if self.db:
                try:
                    self.db.update_quarantine_status(quarantine_id, 'deleted')
                except Exception as e:
                    logger.error(f"Failed to update database: {e}")

            logger.info(f"Quarantined file permanently deleted: {quarantine_id}")
            return True

        except Exception as e:
            logger.error(f"Delete failed for {quarantine_id}: {e}")
            return False

    def get_quarantined_files(self) -> List[Dict[str, Any]]:
        """
        Get list of all quarantined files

        Returns:
            List of dictionaries containing quarantine metadata
        """
        quarantined_files = []

        try:
            for metadata_file in self.metadata_dir.glob("*.json"):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        quarantined_files.append(metadata)
                except Exception as e:
                    logger.error(f"Failed to load metadata file {metadata_file}: {e}")

            # Sort by quarantine date (newest first)
            quarantined_files.sort(
                key=lambda x: x.get('quarantine_date', ''),
                reverse=True
            )

        except Exception as e:
            logger.error(f"Failed to get quarantined files: {e}")

        return quarantined_files

    def get_quarantine_info(self, quarantine_id: str) -> Optional[Dict[str, Any]]:
        """
        Get metadata for a specific quarantined file

        Args:
            quarantine_id: ID of quarantined file

        Returns:
            Dictionary containing metadata, or None if not found
        """
        try:
            metadata_file = self.metadata_dir / f"{quarantine_id}.json"

            if not metadata_file.exists():
                return None

            with open(metadata_file, 'r') as f:
                return json.load(f)

        except Exception as e:
            logger.error(f"Failed to get quarantine info for {quarantine_id}: {e}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get quarantine statistics

        Returns:
            Dictionary containing statistics
        """
        try:
            all_files = self.get_quarantined_files()

            stats = {
                'total_quarantined': len(all_files),
                'currently_quarantined': sum(1 for f in all_files if f.get('status') == 'quarantined'),
                'restored': sum(1 for f in all_files if f.get('status') == 'restored'),
                'deleted': sum(1 for f in all_files if f.get('status') == 'deleted'),
                'total_size': sum(f.get('file_size', 0) for f in all_files if f.get('status') == 'quarantined'),
                'threat_types': {}
            }

            # Count threat types
            for file_meta in all_files:
                if file_meta.get('status') == 'quarantined':
                    threat_type = file_meta.get('threat_info', {}).get('threat_type', 'Unknown')
                    stats['threat_types'][threat_type] = stats['threat_types'].get(threat_type, 0) + 1

            return stats

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}

    def cleanup_old_entries(self, days: int = 90):
        """
        Clean up old deleted entries

        Args:
            days: Number of days to keep deleted entries
        """
        try:
            cutoff_date = datetime.now().timestamp() - (days * 24 * 60 * 60)
            deleted_count = 0

            for metadata_file in self.metadata_dir.glob("*.json"):
                try:
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)

                    # Only clean up deleted entries
                    if metadata.get('status') == 'deleted':
                        delete_date = metadata.get('delete_date')
                        if delete_date:
                            delete_timestamp = datetime.fromisoformat(delete_date).timestamp()
                            if delete_timestamp < cutoff_date:
                                metadata_file.unlink()
                                deleted_count += 1

                except Exception as e:
                    logger.error(f"Failed to process {metadata_file}: {e}")

            logger.info(f"Cleaned up {deleted_count} old quarantine entries")

        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            logger.error(f"Hash calculation failed for {file_path}: {e}")
            return "unknown"
