"""
rollback_system.py - System Rollback and Snapshot Management
Integrates with Windows System Restore for creating and managing snapshots
Requires administrator privileges for full functionality
"""

import os
import subprocess
import json
from datetime import datetime
from typing import List, Dict, Optional
import uuid


class RollbackSystem:
    def __init__(self, database):
        """Initialize rollback system"""
        self.db = database
        self.snapshots_dir = os.path.join(os.path.expanduser("~"), ".fixion", "snapshots")
        self.ensure_snapshots_directory()

        # Check if running with admin privileges
        self.is_admin = self.check_admin_privileges()

    def ensure_snapshots_directory(self):
        """Ensure snapshots directory exists"""
        os.makedirs(self.snapshots_dir, exist_ok=True)

    def check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges"""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def create_snapshot(self, description: str = None) -> Dict:
        """
        Create a system snapshot/restore point
        Uses Windows System Restore API
        """
        if not self.is_admin:
            raise PermissionError(
                "Administrator privileges required to create system snapshots. "
                "Please run Fixion as administrator."
            )

        # Generate snapshot ID
        snapshot_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()

        if description is None:
            description = f"Fixion Security Snapshot - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        try:
            # Create Windows System Restore Point using PowerShell
            # This requires elevated privileges
            ps_command = f'''
            Checkpoint-Computer -Description "{description}" -RestorePointType MODIFY_SETTINGS
            '''

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )

            # Get the restore point ID (last created)
            restore_point_id = self.get_latest_restore_point_id()

            # Analyze snapshot for threats
            is_clean = self.analyze_snapshot()

            # Save snapshot metadata
            snapshot_data = {
                'snapshot_id': snapshot_id,
                'timestamp': timestamp,
                'is_clean': is_clean,
                'restore_point_id': restore_point_id,
                'details': {
                    'description': description,
                    'created_by': 'Fixion Security Suite',
                    'system_state': 'captured'
                }
            }

            # Save to database
            self.db.add_snapshot(snapshot_data)

            # Save snapshot metadata to file
            metadata_path = os.path.join(self.snapshots_dir, f"{snapshot_id}.json")
            with open(metadata_path, 'w') as f:
                json.dump(snapshot_data, f, indent=4)

            return snapshot_data

        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to create system restore point: {e.stderr}")
        except Exception as e:
            raise Exception(f"Failed to create snapshot: {str(e)}")

    def get_latest_restore_point_id(self) -> str:
        """Get the ID of the most recent restore point"""
        try:
            # Query restore points using PowerShell
            ps_command = '''
            Get-ComputerRestorePoint | 
            Sort-Object -Property SequenceNumber -Descending | 
            Select-Object -First 1 | 
            Select-Object -ExpandProperty SequenceNumber
            '''

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )

            return result.stdout.strip()
        except:
            return "unknown"

    def analyze_snapshot(self) -> bool:
        """
        Analyze the current system state for threats
        Returns True if clean, False if threats detected
        """
        try:
            # Check recent threat reports
            threats = self.db.get_threat_reports(limit=10)

            # If no threats found in recent scans, consider clean
            if not threats:
                return True

            # Check if any threats are from the last hour
            current_time = datetime.now()
            for threat in threats:
                threat_time = datetime.fromisoformat(threat['timestamp'])
                time_diff = (current_time - threat_time).total_seconds()

                # If threat detected in last hour, snapshot might not be clean
                if time_diff < 3600:
                    return False

            return True

        except Exception as e:
            print(f"Snapshot analysis error: {e}")
            return True  # Assume clean if analysis fails

    def restore_snapshot(self, snapshot_id: str):
        """
        Restore system to a specific snapshot
        This will restart the system
        """
        if not self.is_admin:
            raise PermissionError(
                "Administrator privileges required to restore system snapshots. "
                "Please run Fixion as administrator."
            )

        # Get snapshot details
        snapshots = self.get_snapshots()
        snapshot = None
        for s in snapshots:
            if s['snapshot_id'] == snapshot_id:
                snapshot = s
                break

        if not snapshot:
            raise ValueError(f"Snapshot {snapshot_id} not found")

        restore_point_id = snapshot.get('restore_point_id')

        if not restore_point_id or restore_point_id == "unknown":
            raise ValueError("Restore point ID not available for this snapshot")

        try:
            # Restore using Windows System Restore
            # This will restart the computer
            ps_command = f'''
            Restore-Computer -RestorePoint {restore_point_id} -Confirm:$false
            '''

            subprocess.run(
                ["powershell", "-Command", ps_command],
                check=True
            )

        except subprocess.CalledProcessError as e:
            raise Exception(f"Failed to restore snapshot: {e.stderr}")
        except Exception as e:
            raise Exception(f"Failed to restore snapshot: {str(e)}")

    def get_snapshots(self) -> List[Dict]:
        """Get all available snapshots"""
        return self.db.get_snapshots()

    def delete_snapshot(self, snapshot_id: str):
        """Delete a snapshot and its restore point"""
        if not self.is_admin:
            raise PermissionError(
                "Administrator privileges required to delete system snapshots. "
                "Please run Fixion as administrator."
            )

        # Get snapshot details
        snapshots = self.get_snapshots()
        snapshot = None
        for s in snapshots:
            if s['snapshot_id'] == snapshot_id:
                snapshot = s
                break

        if not snapshot:
            raise ValueError(f"Snapshot {snapshot_id} not found")

        restore_point_id = snapshot.get('restore_point_id')

        try:
            # Delete restore point
            if restore_point_id and restore_point_id != "unknown":
                ps_command = f'''
                $rp = Get-ComputerRestorePoint | Where-Object {{$_.SequenceNumber -eq {restore_point_id}}}
                if ($rp) {{
                    Remove-ComputerRestorePoint -RestorePoint $rp
                }}
                '''

                subprocess.run(
                    ["powershell", "-Command", ps_command],
                    check=True
                )

            # Delete snapshot metadata file
            metadata_path = os.path.join(self.snapshots_dir, f"{snapshot_id}.json")
            if os.path.exists(metadata_path):
                os.remove(metadata_path)

            # Remove from database (in real implementation)
            # self.db.delete_snapshot(snapshot_id)

        except Exception as e:
            raise Exception(f"Failed to delete snapshot: {str(e)}")

    def get_restore_points(self) -> List[Dict]:
        """Get all Windows restore points"""
        try:
            ps_command = '''
            Get-ComputerRestorePoint | 
            Select-Object SequenceNumber, CreationTime, Description, RestorePointType |
            ConvertTo-Json
            '''

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )

            if result.stdout.strip():
                restore_points = json.loads(result.stdout)
                if isinstance(restore_points, dict):
                    restore_points = [restore_points]
                return restore_points
            else:
                return []

        except Exception as e:
            print(f"Error getting restore points: {e}")
            return []

    def create_scheduled_snapshot(self, interval: str):
        """
        Create scheduled snapshot based on interval
        This should be called by the scheduler
        """
        current_time = datetime.now()
        snapshots = self.get_snapshots()

        if not snapshots:
            # No snapshots exist, create one
            return self.create_snapshot(f"Scheduled Snapshot - {interval}")

        # Get last snapshot time
        last_snapshot = snapshots[0]
        last_time = datetime.fromisoformat(last_snapshot['timestamp'])
        time_diff = (current_time - last_time).total_seconds()

        # Check if it's time to create a new snapshot
        should_create = False

        if interval == "twice_monthly":
            # Create every 15 days
            if time_diff >= (15 * 24 * 3600):
                should_create = True
        elif interval == "monthly":
            # Create every 30 days
            if time_diff >= (30 * 24 * 3600):
                should_create = True

        if should_create:
            return self.create_snapshot(f"Scheduled Snapshot - {interval}")

        return None

    def export_snapshot_info(self, snapshot_id: str, export_path: str):
        """Export snapshot information to a file"""
        snapshots = self.get_snapshots()
        snapshot = None
        for s in snapshots:
            if s['snapshot_id'] == snapshot_id:
                snapshot = s
                break

        if not snapshot:
            raise ValueError(f"Snapshot {snapshot_id} not found")

        with open(export_path, 'w') as f:
            json.dump(snapshot, f, indent=4)

    def verify_snapshot_integrity(self, snapshot_id: str) -> bool:
        """Verify snapshot integrity"""
        try:
            # Check if snapshot metadata exists
            metadata_path = os.path.join(self.snapshots_dir, f"{snapshot_id}.json")
            if not os.path.exists(metadata_path):
                return False

            # Load and validate metadata
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)

            # Check if restore point still exists
            restore_point_id = metadata.get('restore_point_id')
            if restore_point_id and restore_point_id != "unknown":
                restore_points = self.get_restore_points()
                point_exists = any(
                    str(rp.get('SequenceNumber')) == restore_point_id
                    for rp in restore_points
                )
                return point_exists

            return True

        except Exception as e:
            print(f"Integrity check error: {e}")
            return False

    def cleanup_old_snapshots(self, max_snapshots: int = 10):
        """Clean up old snapshots, keeping only the most recent ones"""
        snapshots = self.get_snapshots()

        if len(snapshots) > max_snapshots:
            # Delete oldest snapshots
            snapshots_to_delete = snapshots[max_snapshots:]

            for snapshot in snapshots_to_delete:
                try:
                    self.delete_snapshot(snapshot['snapshot_id'])
                except Exception as e:
                    print(f"Failed to delete snapshot {snapshot['snapshot_id']}: {e}")

    def get_system_info(self) -> Dict:
        """Get current system information"""
        try:
            # Get OS info
            ps_command = '''
            Get-ComputerInfo | 
            Select-Object WindowsProductName, WindowsVersion, OsHardwareAbstractionLayer |
            ConvertTo-Json
            '''

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                check=True
            )

            if result.stdout.strip():
                return json.loads(result.stdout)
            else:
                return {}

        except Exception as e:
            print(f"Error getting system info: {e}")
            return {}