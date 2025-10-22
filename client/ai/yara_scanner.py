"""
yara_scanner.py - Fixed YARA Rules Scanner for Fixion
Provides malware signature detection using YARA rules with proper error handling
"""

import os
import time
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import with error handling
try:
    from client.config import get_config, get_logger
except ImportError:
    def get_config(key, default=None):
        return default
    def get_logger(name):
        import logging
        return logging.getLogger(name)

logger = get_logger(__name__)

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA not installed. Run: pip install yara-python")

    # Create dummy yara module
    class DummyYara:
        def compile(self, *args, **kwargs):
            return DummyRules()

    class DummyRules:
        def match(self, *args, **kwargs):
            return []

    yara = DummyYara()


class YaraScanner:
    """YARA-based malware signature scanner"""

    def __init__(self, rules_dir: str = "yara_rules"):
        # Handle relative paths from project structure
        if not os.path.isabs(rules_dir):
            # Look for yara_rules in client directory
            client_dir = Path(__file__).parent
            rules_dir = client_dir / rules_dir

        self.rules_dir = Path(rules_dir)
        self.compiled_rules = None
        self.rules_loaded = False
        self.stats = {
            'files_scanned': 0,
            'matches_found': 0,
            'rules_loaded': 0,
            'scan_errors': 0
        }

    def load_rules(self) -> bool:
        """Load and compile YARA rules"""
        if not YARA_AVAILABLE:
            logger.error("YARA not available - cannot load rules")
            return False

        try:
            # Create rules directory if it doesn't exist
            self.rules_dir.mkdir(parents=True, exist_ok=True)

            # Check if we have any rule files
            rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))

            if not rule_files:
                logger.info("No YARA rule files found, creating default rules")
                self._create_default_rules()
                rule_files = list(self.rules_dir.glob("*.yar"))

            # Compile rules
            if rule_files:
                rules_dict = {}
                for rule_file in rule_files:
                    try:
                        rule_name = rule_file.stem
                        rules_dict[rule_name] = str(rule_file)
                        logger.debug(f"Loading YARA rule: {rule_file}")
                    except Exception as e:
                        logger.error(f"Failed to load rule {rule_file}: {e}")

                if rules_dict:
                    self.compiled_rules = yara.compile(filepaths=rules_dict)
                    self.rules_loaded = True
                    self.stats['rules_loaded'] = len(rules_dict)
                    logger.info(f"YARA scanner loaded {len(rules_dict)} rule files")
                    return True

            logger.warning("No valid YARA rules could be loaded")
            return False

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            return False

    def _create_default_rules(self):
        """Create default YARA rules for common malware patterns"""
        default_rules = {
            "common_malware.yar": '''
rule Suspicious_PE_Characteristics
{
    meta:
        description = "Detects suspicious PE file characteristics"
        author = "Fixion"
        date = "2025-01-01"
        category = "suspicious"

    condition:
        uint16(0) == 0x5A4D and
        (
            pe.number_of_sections > 10 or
            pe.number_of_sections < 2
        )
}

rule Suspicious_Imports
{
    meta:
        description = "Detects suspicious API imports"
        author = "Fixion"
        category = "suspicious"

    strings:
        $api1 = "CreateRemoteThread"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $api4 = "SetWindowsHookEx"
        $api5 = "GetProcAddress"
        $api6 = "LoadLibrary"

    condition:
        uint16(0) == 0x5A4D and 3 of ($api*)
}

rule Ransomware_Keywords
{
    meta:
        description = "Detects ransomware-related keywords"
        author = "Fixion"
        category = "ransomware"

    strings:
        $s1 = "encrypted" nocase
        $s2 = "decrypt" nocase
        $s3 = "ransom" nocase
        $s4 = "bitcoin" nocase
        $s5 = "payment" nocase
        $s6 = "restore" nocase
        $s7 = "locked" nocase

    condition:
        3 of ($s*)
}

rule Keylogger_Indicators
{
    meta:
        description = "Detects keylogger indicators"
        author = "Fixion"
        category = "keylogger"

    strings:
        $api1 = "GetAsyncKeyState"
        $api2 = "SetWindowsHookEx"
        $api3 = "CallNextHookEx"
        $api4 = "GetKeyState"
        $s1 = "keylog" nocase
        $s2 = "keystroke" nocase

    condition:
        uint16(0) == 0x5A4D and (2 of ($api*) or any of ($s*))
}
''',
            "suspicious_scripts.yar": '''
rule Suspicious_PowerShell
{
    meta:
        description = "Detects suspicious PowerShell commands"
        author = "Fixion"
        category = "script"

    strings:
        $ps1 = "Invoke-Expression" nocase
        $ps2 = "DownloadString" nocase
        $ps3 = "DownloadFile" nocase
        $ps4 = "FromBase64String" nocase
        $ps5 = "EncodedCommand" nocase
        $ps6 = "WebClient" nocase
        $ps7 = "Start-Process" nocase

    condition:
        2 of ($ps*)
}

rule Suspicious_Batch_Commands
{
    meta:
        description = "Detects suspicious batch file commands"
        author = "Fixion"
        category = "script"

    strings:
        $cmd1 = "echo off"
        $cmd2 = "del /f /q"
        $cmd3 = "shutdown"
        $cmd4 = "taskkill"
        $cmd5 = "reg add"
        $cmd6 = "schtasks"
        $cmd7 = "netsh"

    condition:
        3 of ($cmd*)
}

rule VBA_Macro_Suspicious
{
    meta:
        description = "Detects suspicious VBA macro content"
        author = "Fixion"
        category = "macro"

    strings:
        $vba1 = "Auto_Open"
        $vba2 = "Document_Open"
        $vba3 = "Shell"
        $vba4 = "CreateObject"
        $vba5 = "WScript.Shell"
        $vba6 = "URLDownloadToFile"

    condition:
        2 of ($vba*)
}
''',
            "network_indicators.yar": '''
rule Suspicious_URLs
{
    meta:
        description = "Detects suspicious URLs in files"
        author = "Fixion"
        category = "network"

    strings:
        $url1 = /https?:\/\/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/
        $url2 = ".tk/" nocase
        $url3 = ".ml/" nocase
        $url4 = ".ga/" nocase
        $url5 = ".bit/" nocase
        $url6 = ".onion/" nocase

    condition:
        any of them
}

rule IRC_Bot_Indicators
{
    meta:
        description = "Detects IRC bot indicators"
        author = "Fixion"
        category = "botnet"

    strings:
        $irc1 = "PRIVMSG"
        $irc2 = "JOIN #"
        $irc3 = "NICK "
        $irc4 = "USER "
        $irc5 = "MODE "

    condition:
        3 of ($irc*)
}
''',
            "file_operations.yar": '''
rule Mass_File_Operations
{
    meta:
        description = "Detects potential mass file operations (ransomware behavior)"
        author = "Fixion"
        category = "file_operations"

    strings:
        $op1 = "FindFirstFile"
        $op2 = "FindNextFile"
        $op3 = "CreateFile"
        $op4 = "WriteFile"
        $op5 = "DeleteFile"

    condition:
        uint16(0) == 0x5A4D and 3 of ($op*)
}

rule Anti_Analysis_Techniques
{
    meta:
        description = "Detects anti-analysis techniques"
        author = "Fixion"
        category = "anti_analysis"

    strings:
        $aa1 = "IsDebuggerPresent"
        $aa2 = "CheckRemoteDebuggerPresent"
        $aa3 = "OutputDebugString"
        $aa4 = "GetTickCount"
        $aa5 = "Sleep"
        $aa6 = "VirtualProtect"

    condition:
        uint16(0) == 0x5A4D and 3 of ($aa*)
}

rule Packed_Executable
{
    meta:
        description = "Detects potentially packed executables based on section characteristics"
        author = "Fixion"
        category = "packer"

    condition:
        uint16(0) == 0x5A4D and
        for any section in pe.sections : (
            section.characteristics & 0x20000000  // IMAGE_SCN_MEM_EXECUTE
        ) and
        pe.number_of_sections < 5
}
'''
        }

        # Create rule files
        for filename, content in default_rules.items():
            rule_file = self.rules_dir / filename
            try:
                with open(rule_file, 'w') as f:
                    f.write(content)
                logger.info(f"Created default YARA rule: {filename}")
            except Exception as e:
                logger.error(f"Failed to create rule {filename}: {e}")

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """Scan a file with YARA rules"""
        if not self.rules_loaded or not YARA_AVAILABLE:
            return {
                'matches': [],
                'error': 'YARA rules not loaded or YARA not available',
                'scan_time': 0
            }

        self.stats['files_scanned'] += 1
        start_time = time.time()

        try:
            # Check file size limit (default 100MB)
            max_size = get_config('yara.max_file_size_mb', 100) * 1024 * 1024
            if os.path.getsize(file_path) > max_size:
                return {
                    'matches': [],
                    'error': f'File too large for YARA scanning (>{max_size} bytes)',
                    'scan_time': time.time() - start_time
                }

            # Scan the file
            matches = self.compiled_rules.match(file_path)

            # Process matches
            match_info = []
            for match in matches:
                match_detail = {
                    'rule': match.rule,
                    'namespace': getattr(match, 'namespace', 'default'),
                    'tags': list(getattr(match, 'tags', [])),
                    'meta': dict(getattr(match, 'meta', {})),
                    'strings': []
                }

                # Add string matches if available
                if hasattr(match, 'strings'):
                    for string_match in match.strings:
                        string_detail = {
                            'identifier': getattr(string_match, 'identifier', 'unknown'),
                            'offset': 0,
                            'matched_data': ''
                        }

                        if hasattr(string_match, 'instances') and string_match.instances:
                            instance = string_match.instances[0]
                            string_detail['offset'] = getattr(instance, 'offset', 0)
                            matched_data = getattr(instance, 'matched_data', b'')
                            if isinstance(matched_data, bytes):
                                string_detail['matched_data'] = matched_data.decode('utf-8', errors='ignore')[:100]
                            else:
                                string_detail['matched_data'] = str(matched_data)[:100]

                        match_detail['strings'].append(string_detail)

                match_info.append(match_detail)

            if matches:
                self.stats['matches_found'] += len(matches)

            scan_time = time.time() - start_time

            return {
                'matches': [match.rule for match in matches],
                'detailed_matches': match_info,
                'match_count': len(matches),
                'scan_time': scan_time,
                'file_path': file_path,
                'categories': list(set(match.meta.get('category', 'unknown')
                                     for match in matches
                                     if hasattr(match, 'meta') and hasattr(match.meta, 'get')))
            }

        except Exception as e:
            self.stats['scan_errors'] += 1
            logger.error(f"YARA scan failed for {file_path}: {e}")
            return {
                'matches': [],
                'error': str(e),
                'scan_time': time.time() - start_time
            }

    def scan_memory(self, pid: int) -> Dict[str, Any]:
        """Scan process memory with YARA rules"""
        if not self.rules_loaded or not YARA_AVAILABLE:
            return {
                'matches': [],
                'error': 'YARA rules not loaded or YARA not available'
            }

        try:
            matches = self.compiled_rules.match(pid=pid)

            match_info = []
            for match in matches:
                match_detail = {
                    'rule': match.rule,
                    'namespace': getattr(match, 'namespace', 'default'),
                    'tags': list(getattr(match, 'tags', [])),
                    'meta': dict(getattr(match, 'meta', {}))
                }
                match_info.append(match_detail)

            return {
                'matches': [match.rule for match in matches],
                'detailed_matches': match_info,
                'match_count': len(matches),
                'pid': pid
            }

        except Exception as e:
            logger.error(f"YARA memory scan failed for PID {pid}: {e}")
            return {
                'matches': [],
                'error': str(e)
            }

    def add_custom_rule(self, rule_name: str, rule_content: str) -> bool:
        """Add a custom YARA rule"""
        try:
            rule_file = self.rules_dir / f"{rule_name}.yar"
            with open(rule_file, 'w') as f:
                f.write(rule_content)

            # Reload rules
            self.load_rules()
            logger.info(f"Added custom YARA rule: {rule_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to add custom rule {rule_name}: {e}")
            return False

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a YARA rule file"""
        try:
            rule_file = self.rules_dir / f"{rule_name}.yar"
            if rule_file.exists():
                rule_file.unlink()
                self.load_rules()  # Reload rules
                logger.info(f"Removed YARA rule: {rule_name}")
                return True
            return False

        except Exception as e:
            logger.error(f"Failed to remove rule {rule_name}: {e}")
            return False

    def get_rule_info(self) -> Dict[str, Any]:
        """Get information about loaded rules"""
        if not self.rules_loaded:
            return {'error': 'No rules loaded'}

        rule_files = list(self.rules_dir.glob("*.yar")) + list(self.rules_dir.glob("*.yara"))

        return {
            'rules_loaded': self.stats['rules_loaded'],
            'rule_files': [f.name for f in rule_files],
            'rules_directory': str(self.rules_dir),
            'yara_available': YARA_AVAILABLE
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return {
            **self.stats,
            'rules_loaded': self.rules_loaded,
            'yara_available': YARA_AVAILABLE
        }

    def update_rules_from_online(self, sources: List[str] = None) -> Dict[str, Any]:
        """Update rules from online sources (placeholder for future implementation)"""
        logger.info("Online rule updates not implemented yet")
        return {
            'status': 'not_implemented',
            'message': 'Online rule updates will be implemented in future version'
        }

    def validate_rule_syntax(self, rule_content: str) -> Dict[str, Any]:
        """Validate YARA rule syntax"""
        if not YARA_AVAILABLE:
            return {'valid': False, 'error': 'YARA not available'}

        try:
            # Try to compile the rule
            yara.compile(source=rule_content)
            return {'valid': True}

        except Exception as e:
            return {'valid': False, 'error': str(e)}


# Convenience functions
def create_yara_scanner():
    """Create and initialize YARA scanner"""
    scanner = YaraScanner()
    scanner.load_rules()
    return scanner


def scan_file_with_yara(file_path: str, scanner=None):
    """Convenience function to scan file with YARA"""
    if scanner is None:
        scanner = create_yara_scanner()
    return scanner.scan_file(file_path)


# PyCharm-friendly testing and demo functions
def demo_yara_scanner():
    """Demo function that works well in PyCharm"""
    print("=" * 60)
    print("FIXION YARA SCANNER DEMO")
    print("=" * 60)

    # Initialize scanner
    print("\n1. Initializing YARA Scanner...")
    scanner = YaraScanner()

    # Load rules
    print("2. Loading YARA rules...")
    if scanner.load_rules():
        print("✅ YARA scanner loaded successfully!")

        # Show rule info
        rule_info = scanner.get_rule_info()
        print(f"\n📋 Rules Information:")
        print(f"   - Rules loaded: {rule_info.get('rules_loaded', 0)}")
        print(f"   - Rule files: {rule_info.get('rule_files', [])}")
        print(f"   - Rules directory: {rule_info.get('rules_directory', 'N/A')}")
        print(f"   - YARA available: {rule_info.get('yara_available', False)}")

        # Test with a sample file (PyCharm executable as example)
        print(f"\n3. Testing with sample files...")

        # Try to find some common Windows files to test
        test_files = [
            r"C:\Windows\System32\notepad.exe",
            r"C:\Windows\System32\calc.exe",
            r"C:\Windows\System32\cmd.exe"
        ]

        for test_file in test_files:
            if os.path.exists(test_file):
                print(f"\n🔍 Scanning: {test_file}")
                result = scanner.scan_file(test_file)

                if result.get('error'):
                    print(f"   ❌ Error: {result['error']}")
                else:
                    matches = result.get('matches', [])
                    print(f"   ✅ Scan completed in {result.get('scan_time', 0):.3f}s")
                    if matches:
                        print(f"   🚨 Matches found: {matches}")
                        # Show detailed match info
                        for match in result.get('detailed_matches', []):
                            print(f"      - Rule: {match['rule']}")
                            print(f"        Category: {match['meta'].get('category', 'unknown')}")
                            print(f"        Description: {match['meta'].get('description', 'No description')}")
                    else:
                        print(f"   ✅ No threats detected")
                break
        else:
            print("   ⚠️  No test files found. You can test with any file by calling:")
            print("     scanner.scan_file('path/to/your/file.exe')")

        # Show statistics
        print(f"\n📊 Scanner Statistics:")
        stats = scanner.get_statistics()
        for key, value in stats.items():
            print(f"   - {key}: {value}")

        print(f"\n✅ Demo completed successfully!")
        return scanner

    else:
        print("❌ Failed to load YARA scanner")
        print("   This might be because:")
        print("   1. YARA is not installed (pip install yara-python)")
        print("   2. Rule compilation failed")
        print("   3. Permission issues with rules directory")
        return None


def test_custom_rule():
    """Test adding a custom rule - PyCharm friendly"""
    print("\n" + "=" * 60)
    print("TESTING CUSTOM RULE FUNCTIONALITY")
    print("=" * 60)

    scanner = YaraScanner()
    if not scanner.load_rules():
        print("❌ Cannot test custom rules - scanner failed to load")
        return

    # Create a simple test rule
    custom_rule = '''
rule Test_Custom_Rule
{
    meta:
        description = "Simple test rule for demonstration"
        author = "Fixion Demo"
        category = "test"

    strings:
        $test1 = "This is a test string"
        $test2 = "PyCharm"
        $test3 = "YARA"

    condition:
        any of ($test*)
}
'''

    print("🔧 Adding custom rule...")
    if scanner.add_custom_rule("demo_test", custom_rule):
        print("✅ Custom rule added successfully!")

        # Test the rule syntax validation
        print("🔍 Validating rule syntax...")
        validation = scanner.validate_rule_syntax(custom_rule)
        if validation.get('valid'):
            print("✅ Rule syntax is valid!")
        else:
            print(f"❌ Rule syntax error: {validation.get('error')}")
    else:
        print("❌ Failed to add custom rule")


def interactive_file_scanner():
    """Interactive file scanner for PyCharm console"""
    print("\n" + "=" * 60)
    print("INTERACTIVE FILE SCANNER")
    print("=" * 60)

    scanner = YaraScanner()
    if not scanner.load_rules():
        print("❌ Scanner initialization failed")
        return

    print("✅ Scanner ready!")
    print("Enter file paths to scan (or 'quit' to exit):")
    print("Example: C:\\Windows\\System32\\notepad.exe")

    while True:
        try:
            file_path = input("\n📁 File path: ").strip()

            if file_path.lower() in ['quit', 'exit', 'q']:
                print("👋 Goodbye!")
                break

            if not file_path:
                continue

            if not os.path.exists(file_path):
                print(f"❌ File not found: {file_path}")
                continue

            print(f"🔍 Scanning: {file_path}")
            result = scanner.scan_file(file_path)

            if result.get('error'):
                print(f"❌ Error: {result['error']}")
            else:
                matches = result.get('matches', [])
                scan_time = result.get('scan_time', 0)
                print(f"✅ Scan completed in {scan_time:.3f}s")

                if matches:
                    print(f"🚨 {len(matches)} threats detected:")
                    for match in result.get('detailed_matches', []):
                        print(f"   - {match['rule']} ({match['meta'].get('category', 'unknown')})")
                        print(f"     {match['meta'].get('description', 'No description')}")
                else:
                    print("✅ No threats detected")

        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")


# Main function for PyCharm execution
if __name__ == "__main__":
    print("🔥 FIXION YARA SCANNER")
    print("=" * 50)

    # Auto-run demo for PyCharm (you can change this behavior)
    print("🚀 Auto-running demo (perfect for PyCharm)...")
    print("💡 To change behavior, modify the __main__ section")

    # Run the demo automatically
    demo_yara_scanner()

    print("\n" + "=" * 50)
    print("🏁 Demo completed!")
    print("💡 Available functions you can call:")
    print("   - demo_yara_scanner()")
    print("   - test_custom_rule()")
    print("   - interactive_file_scanner()")
    print("=" * 50)

    # Uncomment below if you want interactive mode instead:
    """
    try:
        choice = input("\nChoose option (1=Demo, 2=Custom Rules, 3=Interactive, 4=Quick Test): ").strip()
        
        if choice == "2":
            test_custom_rule()
        elif choice == "3":
            interactive_file_scanner()
        elif choice == "4":
            scanner = YaraScanner()
            if scanner.load_rules():
                print("✅ YARA scanner working correctly!")
                print(f"📊 Statistics: {scanner.get_statistics()}")
            else:
                print("❌ YARA scanner failed to load")
        else:
            demo_yara_scanner()
            
    except (EOFError, KeyboardInterrupt):
        print("\n🚀 Running automated demo...")
        demo_yara_scanner()
    """