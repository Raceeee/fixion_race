"""
reputation_calculator.py - Enhanced Reputation Calculator
Calculates file reputation scores based on multiple factors
"""

import os
import time
import winreg
import logging
from typing import Set, Optional, Dict, List, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class ReputationCalculator:
    """Calculate file reputation scores based on context"""

    def __init__(self, whitelist_manager):
        self.whitelist_manager = whitelist_manager
        self.system_paths = self._get_system_paths()
        self.installed_programs = self._get_installed_programs()
        
        # Cache for performance
        self._cache = {}
        self._cache_timeout = 3600  # 1 hour

    def _get_system_paths(self) -> Set[str]:
        """Get known system paths"""
        paths = set()
        
        # Windows system paths
        if os.name == 'nt':
            paths.update({
                os.environ.get('SYSTEMROOT', 'C:\\Windows').lower(),
                os.environ.get('PROGRAMFILES', 'C:\\Program Files').lower(),
                os.environ.get('PROGRAMFILES(X86)', 'C:\\Program Files (x86)').lower(),
                os.environ.get('PROGRAMDATA', 'C:\\ProgramData').lower(),
                os.environ.get('COMMONPROGRAMFILES', 'C:\\Program Files\\Common Files').lower(),
            })

            # Add common system subdirectories
            system_root = os.environ.get('SYSTEMROOT', 'C:\\Windows').lower()
            paths.update({
                os.path.join(system_root, 'system32').lower(),
                os.path.join(system_root, 'syswow64').lower(),
                os.path.join(system_root, 'winsxs').lower(),
                os.path.join(system_root, 'microsoft.net').lower(),
            })
        else:
            # Unix-like system paths
            paths.update({
                '/usr/bin',
                '/usr/sbin',
                '/bin',
                '/sbin',
                '/usr/lib',
                '/lib',
                '/usr/local/bin',
                '/usr/local/lib',
                '/opt'
            })

        return paths

    def _get_installed_programs(self) -> Set[str]:
        """Get list of installed programs from registry"""
        installed = set()

        if os.name != 'nt':
            return installed  # Only for Windows

        try:
            # Registry paths to check for installed programs
            reg_paths = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            ]

            for reg_path in reg_paths:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                    i = 0

                    while True:
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            subkey = winreg.OpenKey(key, subkey_name)

                            try:
                                # Get installation location
                                install_location = winreg.QueryValueEx(subkey, "InstallLocation")[0]
                                if install_location and os.path.exists(install_location):
                                    installed.add(install_location.lower())
                            except FileNotFoundError:
                                pass

                            try:
                                # Also get DisplayIcon path as potential program location
                                display_icon = winreg.QueryValueEx(subkey, "DisplayIcon")[0]
                                if display_icon and ',' in display_icon:
                                    icon_path = display_icon.split(',')[0].strip('"')
                                    if os.path.exists(icon_path):
                                        installed.add(os.path.dirname(icon_path).lower())
                            except FileNotFoundError:
                                pass

                            winreg.CloseKey(subkey)
                            i += 1

                        except OSError:  # No more subkeys
                            break

                    winreg.CloseKey(key)

                except Exception as e:
                    logger.debug(f"Error reading registry path {reg_path}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Error reading installed programs: {e}")

        return installed

    def calculate_reputation(self, file_path: str, signature_info: Dict[str, Any]) -> float:
        """Calculate file reputation score (0.0 to 1.0)"""
        
        # Check cache first
        cache_key = f"{file_path}_{signature_info.get('publisher', '')}"
        if cache_key in self._cache:
            cached_time, cached_score = self._cache[cache_key]
            if time.time() - cached_time < self._cache_timeout:
                return cached_score
        
        score = 0.0
        file_path_lower = file_path.lower()

        # 1. Digital signature bonus (40% of total possible score)
        if signature_info.get('signature_valid'):
            score += 0.4

            # Extra bonus for trusted publisher (50% of total possible score)
            publisher = signature_info.get('publisher')
            if publisher and self.whitelist_manager.is_trusted_publisher(publisher):
                score += 0.5

        elif signature_info.get('is_signed'):
            # Signed but not validated - still some bonus
            score += 0.15

        # 2. System location bonus (25% of total possible score)
        if self._is_system_location(file_path_lower):
            score += 0.25

        # 3. Installed program bonus (20% of total possible score)
        if self._is_installed_program(file_path_lower):
            score += 0.2

        # 4. File age bonus (15% of total possible score)
        age_bonus = self._calculate_age_bonus(file_path, file_path_lower)
        score += age_bonus

        # 5. File extension bonus (10% of total possible score)
        extension_bonus = self._calculate_extension_bonus(file_path_lower)
        score += extension_bonus

        # 6. Path depth penalty (files in very deep or unusual paths are more suspicious)
        depth_penalty = self._calculate_depth_penalty(file_path_lower)
        score -= depth_penalty

        # 7. Known good patterns bonus
        if self._matches_known_good_pattern(file_path_lower):
            score += 0.15

        # Ensure score is between 0.0 and 1.0
        final_score = max(0.0, min(1.0, score))
        
        # Cache the result
        self._cache[cache_key] = (time.time(), final_score)
        
        return final_score

    def _is_system_location(self, file_path_lower: str) -> bool:
        """Check if file is in a system location"""
        return any(file_path_lower.startswith(sys_path) for sys_path in self.system_paths)

    def _is_installed_program(self, file_path_lower: str) -> bool:
        """Check if file is part of an installed program"""
        return any(file_path_lower.startswith(install_path) for install_path in self.installed_programs)

    def _calculate_age_bonus(self, file_path: str, file_path_lower: str) -> float:
        """Calculate age-based reputation bonus"""
        try:
            # Get file creation time
            creation_time = os.path.getctime(file_path)
            age_days = (time.time() - creation_time) / 86400

            # Files older than 30 days in system locations get bonus
            if age_days > 30 and self._is_system_location(file_path_lower):
                return 0.15
            elif age_days > 90:  # Very old files anywhere get some bonus
                return 0.1
            elif age_days > 7:  # Week-old files get small bonus
                return 0.05

        except Exception:
            pass

        return 0.0

    def _calculate_extension_bonus(self, file_path_lower: str) -> float:
        """Calculate extension-based reputation bonus"""
        # Common legitimate executable extensions
        safe_extensions = {'.exe', '.dll', '.msi', '.com'}

        # Get file extension
        extension = Path(file_path_lower).suffix

        if extension in safe_extensions:
            return 0.05

        # System files
        if extension in {'.sys', '.drv', '.ocx'}:
            return 0.1

        return 0.0

    def _calculate_depth_penalty(self, file_path_lower: str) -> float:
        """Calculate penalty for suspicious path depths or locations"""
        path_parts = file_path_lower.split(os.sep)

        # Very deep paths (more than 8 levels) are suspicious
        if len(path_parts) > 8:
            return 0.1

        # Files in temp directories are more suspicious
        suspicious_dirs = {'temp', 'tmp', 'appdata\\local\\temp', 'users\\public', 'downloads'}
        if any(suspicious_dir in file_path_lower for suspicious_dir in suspicious_dirs):
            return 0.15

        # Files in user profile folders (but not standard locations) are somewhat suspicious
        if 'users\\' in file_path_lower and 'program files' not in file_path_lower:
            return 0.05

        return 0.0

    def _matches_known_good_pattern(self, file_path_lower: str) -> bool:
        """Check if file matches known good patterns"""
        good_patterns = [
            'microsoft visual studio',
            'windows defender',
            'windows security',
            'microsoft office',
            'google\\chrome',
            'mozilla firefox',
            'python\\python',
            'nodejs',
            'git\\',
            'jetbrains'
        ]
        
        return any(pattern in file_path_lower for pattern in good_patterns)

    def get_location_context(self, file_path: str) -> str:
        """Get human-readable location context"""
        file_path_lower = file_path.lower()

        if self._is_system_location(file_path_lower):
            return "System Location"
        elif self._is_installed_program(file_path_lower):
            return "Installed Program"
        elif 'program files' in file_path_lower:
            return "Program Files"
        elif 'users\\' in file_path_lower:
            if 'downloads' in file_path_lower:
                return "Downloads Folder"
            elif 'desktop' in file_path_lower:
                return "Desktop"
            elif 'documents' in file_path_lower:
                return "Documents Folder"
            elif 'appdata' in file_path_lower:
                return "Application Data"
            else:
                return "User Directory"
        elif any(temp_dir in file_path_lower for temp_dir in ['temp', 'tmp']):
            return "Temporary Directory"
        else:
            return "Unknown Location"

    def analyze_file_context(self, file_path: str, signature_info: Dict[str, Any]) -> Dict[str, Any]:
        """Provide detailed context analysis"""
        reputation_score = self.calculate_reputation(file_path, signature_info)
        location_context = self.get_location_context(file_path)

        # Determine risk factors
        risk_factors = []
        trust_factors = []

        # Signature analysis
        if signature_info.get('signature_valid'):
            trust_factors.append("Digitally signed with valid signature")

            publisher = signature_info.get('publisher')
            if publisher and self.whitelist_manager.is_trusted_publisher(publisher):
                trust_factors.append(f"Published by trusted company: {publisher}")

        elif signature_info.get('is_signed'):
            risk_factors.append("Digitally signed but signature not validated")
        else:
            risk_factors.append("Not digitally signed")

        # Location analysis
        if location_context == "System Location":
            trust_factors.append("Located in system directory")
        elif location_context == "Installed Program":
            trust_factors.append("Part of installed program")
        elif location_context == "Temporary Directory":
            risk_factors.append("Located in temporary directory")
        elif location_context == "Downloads Folder":
            risk_factors.append("Recently downloaded file")

        file_path_lower = file_path.lower()
        
        # Path analysis
        if any(temp_dir in file_path_lower for temp_dir in ['temp', 'tmp']):
            if "Located in temporary directory" not in risk_factors:
                risk_factors.append("In temporary directory")

        # Check file age
        try:
            age_days = (time.time() - os.path.getctime(file_path)) / 86400
            if age_days > 30:
                trust_factors.append(f"File age: {int(age_days)} days (established)")
            elif age_days < 1:
                risk_factors.append("Very recently created file")
            elif age_days < 7:
                risk_factors.append(f"Recently created: {int(age_days)} days ago")
        except:
            pass

        # Extension analysis
        ext = Path(file_path).suffix.lower()
        if ext in ['.exe', '.dll', '.sys', '.drv']:
            if location_context not in ["System Location", "Installed Program", "Program Files"]:
                risk_factors.append(f"Executable file in {location_context}")

        return {
            'reputation_score': reputation_score,
            'location_context': location_context,
            'trust_factors': trust_factors,
            'risk_factors': risk_factors,
            'recommendation': self._get_recommendation(reputation_score, risk_factors),
            'details': {
                'is_system_location': self._is_system_location(file_path_lower),
                'is_installed_program': self._is_installed_program(file_path_lower),
                'publisher': signature_info.get('publisher'),
                'signature_valid': signature_info.get('signature_valid', False)
            }
        }

    def _get_recommendation(self, reputation_score: float, risk_factors: List[str]) -> str:
        """Get recommendation based on reputation analysis"""
        if reputation_score >= 0.8:
            return "HIGH_TRUST"
        elif reputation_score >= 0.6:
            return "MODERATE_TRUST"
        elif reputation_score >= 0.3:
            return "LOW_TRUST"
        elif len(risk_factors) > 2:
            return "HIGH_SUSPICION"
        else:
            return "MODERATE_SUSPICION"

    def clear_cache(self):
        """Clear the reputation cache"""
        self._cache = {}
        logger.info("Reputation cache cleared")