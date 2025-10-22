"""
snapshot_manager.py - Windows System Restore & Rollback Manager
Uses Windows System Restore API to create restore points and trigger rollbacks
"""

import os
import subprocess
import time
import json
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path
import threading

logger = logging.getLogger(__name__)


class WindowsSnapshotManager:
    """Manager for Windows System Restore Points (Snapshots)"""
    
    def __init__(self):
        self.snapshots_config_file = "snapshots_config.json"
        self.scheduled_snapshots = []
        self.scheduler_thread = None
        self.running = False
        
        # Load configuration
        self.load_config()
        
    def load_config(self):
        """Load snapshot configuration"""
        try:
            if os.path.exists(self.snapshots_config_file):
                with open(self.snapshots_config_file, 'r') as f:
                    config = json.load(f)
                    self.scheduled_snapshots = config.get('scheduled_snapshots', [])
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            self.scheduled_snapshots = []
    
    def save_config(self):
        """Save snapshot configuration"""
        try:
            config = {
                'scheduled_snapshots': self.scheduled_snapshots
            }
            with open(self.snapshots_config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
    
    def is_system_restore_enabled(self) -> bool:
        """Check if System Restore is enabled"""
        try:
            # PowerShell command to check System Restore status
            ps_command = """
            $status = Get-ComputerRestorePoint -ErrorAction SilentlyContinue
            if ($status) { "ENABLED" } else { "DISABLED" }
            """
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            return "ENABLED" in result.stdout
            
        except Exception as e:
            logger.error(f"Error checking System Restore status: {e}")
            return False
    
    def enable_system_restore(self, drive: str = "C:\\") -> bool:
        """Enable System Restore on specified drive"""
        try:
            # PowerShell command to enable System Restore
            ps_command = f"""
            Enable-ComputerRestore -Drive "{drive}"
            """
            
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                logger.info(f"System Restore enabled on {drive}")
                return True
            else:
                logger.error(f"Failed to enable System Restore: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error enabling System Restore: {e}")
            return False
    
    def create_snapshot(self, description: str = None, snapshot_type: str = "APPLICATION_INSTALL") -> Dict[str, Any]:
        """
        Create a Windows System Restore Point (Snapshot)
        
        Args:
            description: Description for the restore point
            snapshot_type: Type of restore point (APPLICATION_INSTALL, MODIFY_SETTINGS, etc.)
        
        Returns:
            Dict with status and restore point info
        """
        if description is None:
            description = f"Fixion Security Snapshot - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        
        try:
            logger.info(f"Creating system restore point: {description}")
            
            # PowerShell command to create restore point
            ps_command = f"""
            $description = "{description}"
            
            # Create restore point
            try {{
                Checkpoint-Computer -Description $description -RestorePointType APPLICATION_INSTALL
                
                # Get the most recent restore point
                Start-Sleep -Seconds 2
                $restorePoint = Get-ComputerRestorePoint | Select-Object -First 1
                
                $result = @{{
                    Status = "Success"
                    Description = $restorePoint.Description
                    CreationTime = $restorePoint.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                    SequenceNumber = $restorePoint.SequenceNumber
                }}
                
                $result | ConvertTo-Json -Compress
                
            }} catch {{
                $error = @{{
                    Status = "Failed"
                    Error = $_.Exception.Message
                }}
                $error | ConvertTo-Json -Compress
            }}
            """
            
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    result_data = json.loads(result.stdout.strip())
                    if result_data.get('Status') == 'Success':
                        logger.info(f"Snapshot created successfully: {result_data.get('Description')}")
                        return {
                            'success': True,
                            'description': result_data.get('Description'),
                            'creation_time': result_data.get('CreationTime'),
                            'sequence_number': result_data.get('SequenceNumber'),
                            'message': 'System restore point created successfully'
                        }
                    else:
                        logger.error(f"Failed to create snapshot: {result_data.get('Error')}")
                        return {
                            'success': False,
                            'error': result_data.get('Error'),
                            'message': 'Failed to create system restore point'
                        }
                except json.JSONDecodeError:
                    logger.error("Failed to parse PowerShell output")
                    return {
                        'success': False,
                        'error': 'Failed to parse result',
                        'message': 'Error creating restore point'
                    }
            else:
                logger.error(f"PowerShell command failed: {result.stderr}")
                return {
                    'success': False,
                    'error': result.stderr,
                    'message': 'System Restore may not be enabled'
                }
                
        except Exception as e:
            logger.error(f"Error creating snapshot: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Exception occurred while creating restore point'
            }
    
    def list_snapshots(self) -> List[Dict[str, Any]]:
        """List all available System Restore Points"""
        try:
            ps_command = """
            Get-ComputerRestorePoint | ForEach-Object {
                @{
                    SequenceNumber = $_.SequenceNumber
                    Description = $_.Description
                    CreationTime = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                    RestorePointType = $_.RestorePointType
                }
            } | ConvertTo-Json
            """
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    snapshots_data = json.loads(result.stdout.strip())
                    
                    # Handle single result (not a list)
                    if isinstance(snapshots_data, dict):
                        snapshots_data = [snapshots_data]
                    
                    snapshots = []
                    for snapshot in snapshots_data:
                        snapshots.append({
                            'sequence_number': snapshot.get('SequenceNumber'),
                            'description': snapshot.get('Description'),
                            'creation_time': snapshot.get('CreationTime'),
                            'type': snapshot.get('RestorePointType', 'Unknown')
                        })
                    
                    return snapshots
                    
                except json.JSONDecodeError:
                    logger.error("Failed to parse snapshots list")
                    return []
            else:
                logger.warning("No restore points found or System Restore not enabled")
                return []
                
        except Exception as e:
            logger.error(f"Error listing snapshots: {e}")
            return []
    
    def trigger_rollback(self, sequence_number: int = None, emergency: bool = False) -> Dict[str, Any]:
        """
        Trigger Windows System Restore (Rollback)
        
        Args:
            sequence_number: Specific restore point to restore to. If None, uses most recent.
            emergency: If True, initiates immediate restore
        
        Returns:
            Dict with rollback status
        """
        try:
            # Get restore point info
            snapshots = self.list_snapshots()
            
            if not snapshots:
                return {
                    'success': False,
                    'error': 'No restore points available',
                    'message': 'Cannot perform rollback - no restore points found'
                }
            
            # Determine which restore point to use
            if sequence_number is None:
                # Use most recent
                target_snapshot = snapshots[0]
            else:
                # Find specific restore point
                target_snapshot = None
                for snapshot in snapshots:
                    if snapshot['sequence_number'] == sequence_number:
                        target_snapshot = snapshot
                        break
                
                if not target_snapshot:
                    return {
                        'success': False,
                        'error': f'Restore point {sequence_number} not found',
                        'message': 'Specified restore point does not exist'
                    }
            
            logger.info(f"Triggering rollback to: {target_snapshot['description']}")
            
            # Create PowerShell script to initiate System Restore
            ps_script = f"""
            # Windows System Restore Initiation
            $restorePoint = {target_snapshot['sequence_number']}
            
            # Launch System Restore UI with pre-selected restore point
            # Note: This requires user confirmation for safety
            
            rstrui.exe /offline:$restorePoint
            """
            
            # For emergency mode, create a more direct approach
            if emergency:
                ps_script = f"""
                # Emergency System Restore
                $restorePoint = {target_snapshot['sequence_number']}
                
                # Create VBScript to show confirmation and restore
                $vbsScript = @"
Set objShell = CreateObject("WScript.Shell")
result = MsgBox("EMERGENCY ROLLBACK`n`nThis will restore your system to:`n{target_snapshot['description']}`n`nCreated: {target_snapshot['creation_time']}`n`nYour computer will restart. Continue?", vbYesNo + vbCritical, "Fixion Emergency Rollback")
if result = vbYes then
    objShell.Run "rstrui.exe /offline:$restorePoint", 1, False
end if
"@
                
                $vbsPath = "$env:TEMP\\emergency_restore.vbs"
                $vbsScript | Out-File -FilePath $vbsPath -Encoding ASCII
                
                Start-Process "wscript.exe" -ArgumentList $vbsPath
                """
            
            # Execute the rollback script
            result = subprocess.run(
                ['powershell', '-ExecutionPolicy', 'Bypass', '-Command', ps_script],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            logger.info("System Restore initiated")
            
            return {
                'success': True,
                'restore_point': target_snapshot,
                'message': 'System Restore has been initiated. Follow the on-screen prompts.',
                'emergency': emergency
            }
            
        except Exception as e:
            logger.error(f"Error triggering rollback: {e}")
            return {
                'success': False,
                'error': str(e),
                'message': 'Failed to initiate System Restore'
            }
    
    def schedule_snapshot(self, interval_hours: int, description_prefix: str = "Scheduled") -> bool:
        """
        Schedule automatic snapshots
        
        Args:
            interval_hours: Hours between snapshots
            description_prefix: Prefix for snapshot descriptions
        """
        try:
            schedule_config = {
                'interval_hours': interval_hours,
                'description_prefix': description_prefix,
                'enabled': True,
                'last_snapshot': None
            }
            
            self.scheduled_snapshots.append(schedule_config)
            self.save_config()
            
            # Start scheduler if not running
            if not self.running:
                self.start_scheduler()
            
            logger.info(f"Scheduled snapshot every {interval_hours} hours")
            return True
            
        except Exception as e:
            logger.error(f"Error scheduling snapshot: {e}")
            return False
    
    def start_scheduler(self):
        """Start the snapshot scheduler"""
        if self.running:
            return
        
        self.running = True
        self.scheduler_thread = threading.Thread(target=self._scheduler_worker, daemon=True)
        self.scheduler_thread.start()
        logger.info("Snapshot scheduler started")
    
    def stop_scheduler(self):
        """Stop the snapshot scheduler"""
        self.running = False
        if self.scheduler_thread:
            self.scheduler_thread.join(timeout=5)
        logger.info("Snapshot scheduler stopped")
    
    def _scheduler_worker(self):
        """Background worker for scheduled snapshots"""
        while self.running:
            try:
                current_time = datetime.now()
                
                for schedule in self.scheduled_snapshots:
                    if not schedule.get('enabled'):
                        continue
                    
                    last_snapshot = schedule.get('last_snapshot')
                    interval_hours = schedule.get('interval_hours', 24)
                    
                    # Check if snapshot is due
                    if last_snapshot is None:
                        should_create = True
                    else:
                        last_time = datetime.fromisoformat(last_snapshot)
                        hours_since = (current_time - last_time).total_seconds() / 3600
                        should_create = hours_since >= interval_hours
                    
                    if should_create:
                        description = f"{schedule['description_prefix']} - {current_time.strftime('%Y-%m-%d %H:%M')}"
                        result = self.create_snapshot(description)
                        
                        if result.get('success'):
                            schedule['last_snapshot'] = current_time.isoformat()
                            self.save_config()
                            logger.info(f"Scheduled snapshot created: {description}")
                
                # Sleep for 1 hour before checking again
                time.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in scheduler worker: {e}")
                time.sleep(300)  # Sleep 5 minutes on error
    
    def delete_snapshot(self, sequence_number: int) -> bool:
        """
        Delete a specific restore point
        Note: Windows doesn't easily allow deleting individual restore points
        This will disable and re-enable System Restore to clear all old points
        """
        try:
            # This is a limitation of Windows - can't easily delete specific restore points
            logger.warning("Windows does not support deleting individual restore points easily")
            return False
        except Exception as e:
            logger.error(f"Error deleting snapshot: {e}")
            return False
    
    def get_disk_usage(self) -> Dict[str, Any]:
        """Get disk space used by System Restore"""
        try:
            ps_command = """
            $volume = Get-CimInstance -ClassName Win32_ShadowStorage | Select-Object -First 1
            @{
                UsedSpace = [math]::Round($volume.UsedSpace / 1GB, 2)
                AllocatedSpace = [math]::Round($volume.AllocatedSpace / 1GB, 2)
                MaxSpace = [math]::Round($volume.MaxSpace / 1GB, 2)
            } | ConvertTo-Json
            """
            
            result = subprocess.run(
                ['powershell', '-Command', ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and result.stdout.strip():
                usage_data = json.loads(result.stdout.strip())
                return {
                    'used_gb': usage_data.get('UsedSpace', 0),
                    'allocated_gb': usage_data.get('AllocatedSpace', 0),
                    'max_gb': usage_data.get('MaxSpace', 0)
                }
            
            return {'used_gb': 0, 'allocated_gb': 0, 'max_gb': 0}
            
        except Exception as e:
            logger.error(f"Error getting disk usage: {e}")
            return {'used_gb': 0, 'allocated_gb': 0, 'max_gb': 0}
    
    def get_status(self) -> Dict[str, Any]:
        """Get overall snapshot manager status"""
        try:
            snapshots = self.list_snapshots()
            disk_usage = self.get_disk_usage()
            
            return {
                'system_restore_enabled': self.is_system_restore_enabled(),
                'total_snapshots': len(snapshots),
                'latest_snapshot': snapshots[0] if snapshots else None,
                'disk_usage': disk_usage,
                'scheduled_snapshots': len([s for s in self.scheduled_snapshots if s.get('enabled')]),
                'scheduler_running': self.running
            }
        except Exception as e:
            logger.error(f"Error getting status: {e}")
            return {
                'system_restore_enabled': False,
                'total_snapshots': 0,
                'error': str(e)
            }


# Convenience functions
def create_emergency_snapshot(description: str = "Emergency Snapshot Before Security Action"):
    """Quick function to create emergency snapshot"""
    manager = WindowsSnapshotManager()
    return manager.create_snapshot(description)


def trigger_emergency_rollback():
    """Quick function to trigger emergency rollback to most recent restore point"""
    manager = WindowsSnapshotManager()
    return manager.trigger_rollback(emergency=True)


# Main function for testing
if __name__ == "__main__":
    print("=" * 60)
    print("WINDOWS SNAPSHOT & ROLLBACK MANAGER - TEST")
    print("=" * 60)
    
    manager = WindowsSnapshotManager()
    
    # Check status
    print("\n1. Checking System Restore Status...")
    status = manager.get_status()
    print(f"   System Restore Enabled: {status['system_restore_enabled']}")
    print(f"   Total Restore Points: {status['total_snapshots']}")
    print(f"   Disk Usage: {status['disk_usage']['used_gb']:.2f} GB")
    
    # List snapshots
    print("\n2. Available Restore Points:")
    snapshots = manager.list_snapshots()
    if snapshots:
        for i, snapshot in enumerate(snapshots[:5], 1):
            print(f"   {i}. {snapshot['description']}")
            print(f"      Created: {snapshot['creation_time']}")
            print(f"      Sequence: {snapshot['sequence_number']}")
    else:
        print("   No restore points found")
    
    # Test create snapshot
    print("\n3. Testing Snapshot Creation...")
    choice = input("   Create a test snapshot? (y/n): ")
    if choice.lower() == 'y':
        result = manager.create_snapshot("Fixion Test Snapshot")
        if result['success']:
            print(f"   ✓ Snapshot created successfully!")
            print(f"     Description: {result['description']}")
        else:
            print(f"   ✗ Failed: {result['message']}")
    
    print("\n" + "=" * 60)
    print("Test complete!")
