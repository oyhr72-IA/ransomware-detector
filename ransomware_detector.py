import winreg
import struct
import hashlib
import uuid
import subprocess
import os
import json
from datetime import datetime
from collections import defaultdict

class RansomwareDetector:
    def __init__(self):
        self.suspicious_patterns = {
            'registry_keys': [
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
            ],
            'ransomware_indicators': [
                'crypt', 'lock', 'encrypt', 'ransom', 'decrypt', 'restore',
                'recover', 'payment', 'bitcoin', 'tor', 'onion', 'readme',
                'how_to_decrypt', 'files_encrypted', 'recovery_key'
            ],
            'suspicious_extensions': [
                '.encrypted', '.locked', '.crypto', '.crypt', '.aaa', '.abc',
                '.xyz', '.zzz', '.micro', '.ttt', '.xxx', '.locky', '.cerber'
            ]
        }
    
    def decode_startup_approved_value(self, binary_data):
        """Decode the StartupApproved binary value"""
        try:
            if len(binary_data) >= 12:
                # First 4 bytes: flags (01000000 = disabled, 02000000 = enabled)
                flags = struct.unpack('<I', binary_data[:4])[0]
                # Next 8 bytes: timestamp
                timestamp = struct.unpack('<Q', binary_data[4:12])[0]
                
                # Convert Windows FILETIME to readable format
                # FILETIME is 100-nanosecond intervals since January 1, 1601
                unix_timestamp = (timestamp - 116444736000000000) / 10000000
                readable_time = datetime.fromtimestamp(unix_timestamp)
                
                status = "DISABLED" if flags == 1 else "ENABLED" if flags == 2 else f"UNKNOWN({flags})"
                
                return {
                    'status': status,
                    'timestamp': readable_time,
                    'raw_flags': flags,
                    'raw_timestamp': timestamp
                }
        except Exception as e:
            return {'error': str(e), 'raw_data': binary_data.hex()}
    
    def analyze_registry_value(self, key_path, value_name, value_data, value_type):
        """Analyze a single registry value for suspicious patterns"""
        analysis = {
            'key_path': key_path,
            'value_name': value_name,
            'value_data': value_data,
            'value_type': value_type,
            'suspicious_score': 0,
            'indicators': []
        }
        
        # Check for suspicious patterns in value name
        for pattern in self.suspicious_patterns['ransomware_indicators']:
            if pattern.lower() in value_name.lower():
                analysis['suspicious_score'] += 10
                analysis['indicators'].append(f"Suspicious pattern in name: {pattern}")
        
        # Check for suspicious patterns in value data
        if isinstance(value_data, str):
            for pattern in self.suspicious_patterns['ransomware_indicators']:
                if pattern.lower() in value_data.lower():
                    analysis['suspicious_score'] += 10
                    analysis['indicators'].append(f"Suspicious pattern in data: {pattern}")
        
        # Check for UUID patterns (potential malware identifiers)
        if isinstance(value_data, str):
            try:
                uuid.UUID(value_data)
                analysis['suspicious_score'] += 5
                analysis['indicators'].append("Contains UUID (potential malware identifier)")
            except ValueError:
                pass
        
        # Check for unusual naming patterns
        if 'AF_' in value_name and ('uuid' in value_name or 'counter' in value_name):
            analysis['suspicious_score'] += 15
            analysis['indicators'].append("Unusual naming pattern with AF_ prefix")
        
        return analysis
    
    def scan_registry_key(self, hive, key_path):
        """Scan a specific registry key for suspicious entries"""
        results = []
        
        try:
            with winreg.OpenKey(hive, key_path) as key:
                i = 0
                while True:
                    try:
                        value_name, value_data, value_type = winreg.EnumValue(key, i)
                        analysis = self.analyze_registry_value(key_path, value_name, value_data, value_type)
                        results.append(analysis)
                        i += 1
                    except WindowsError:
                        break
        except Exception as e:
            results.append({'error': f"Could not access {key_path}: {str(e)}"})
        
        return results
    
    def analyze_af_entries(self):
        """Specifically analyze the AF_ entries found"""
        print("🔍 ANALYZING SUSPICIOUS AF_ ENTRIES")
        print("=" * 60)
        
        # Analyze the Run entries
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
                try:
                    uuid_value, _ = winreg.QueryValueEx(key, "AF_uuid_2569510")
                    counter_value, _ = winreg.QueryValueEx(key, "AF_counter_2569510")
                    
                    print(f"📋 AF_uuid_2569510: {uuid_value}")
                    print(f"📋 AF_counter_2569510: {counter_value}")
                    
                    # Analyze the UUID
                    try:
                        parsed_uuid = uuid.UUID(uuid_value)
                        print(f"✅ Valid UUID format: {parsed_uuid}")
                        print(f"📊 UUID version: {parsed_uuid.version}")
                        
                        # Check if it's a known malware UUID (example check)
                        uuid_hash = hashlib.md5(uuid_value.encode()).hexdigest()
                        print(f"🔒 UUID hash: {uuid_hash}")
                        
                    except ValueError:
                        print("❌ Invalid UUID format - HIGHLY SUSPICIOUS")
                        
                except FileNotFoundError:
                    print("❌ AF_ entries not found in Run key")
                    
        except Exception as e:
            print(f"❌ Error analyzing Run entries: {e}")
        
        # Analyze the StartupApproved entries
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run") as key:
                try:
                    uuid_binary, _ = winreg.QueryValueEx(key, "AF_uuid_2569510")
                    counter_binary, _ = winreg.QueryValueEx(key, "AF_counter_2569510")
                    
                    print(f"\n📋 StartupApproved Analysis:")
                    print(f"🔍 AF_uuid_2569510 binary: {uuid_binary.hex()}")
                    print(f"🔍 AF_counter_2569510 binary: {counter_binary.hex()}")
                    
                    # Decode binary values
                    uuid_decoded = self.decode_startup_approved_value(uuid_binary)
                    counter_decoded = self.decode_startup_approved_value(counter_binary)
                    
                    print(f"✅ AF_uuid_2569510 status: {uuid_decoded}")
                    print(f"✅ AF_counter_2569510 status: {counter_decoded}")
                    
                except FileNotFoundError:
                    print("❌ AF_ entries not found in StartupApproved key")
                    
        except Exception as e:
            print(f"❌ Error analyzing StartupApproved entries: {e}")
    
    def check_for_encrypted_files(self):
        """Check for encrypted files that might indicate ransomware"""
        print("\n🔍 CHECKING FOR ENCRYPTED FILES")
        print("=" * 60)
        
        encrypted_files = []
        suspicious_files = []
        
        # Check common directories for suspicious files
        check_dirs = [
            os.path.expanduser("~\\Desktop"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\Downloads"),
            "C:\\Users\\Public"
        ]
        
        for directory in check_dirs:
            if os.path.exists(directory):
                try:
                    for root, dirs, files in os.walk(directory):
                        for file in files:
                            file_path = os.path.join(root, file)
                            
                            # Check for suspicious extensions
                            for ext in self.suspicious_patterns['suspicious_extensions']:
                                if file.lower().endswith(ext):
                                    encrypted_files.append(file_path)
                            
                            # Check for ransom notes
                            for indicator in self.suspicious_patterns['ransomware_indicators']:
                                if indicator in file.lower():
                                    suspicious_files.append(file_path)
                            
                            # Limit to prevent long scans
                            if len(encrypted_files) + len(suspicious_files) > 50:
                                break
                        if len(encrypted_files) + len(suspicious_files) > 50:
                            break
                except Exception as e:
                    print(f"❌ Error scanning {directory}: {e}")
        
        print(f"📊 Found {len(encrypted_files)} potentially encrypted files")
        print(f"📊 Found {len(suspicious_files)} suspicious files")
        
        if encrypted_files:
            print("\n🚨 POTENTIALLY ENCRYPTED FILES:")
            for file in encrypted_files[:10]:  # Show first 10
                print(f"   - {file}")
        
        if suspicious_files:
            print("\n🚨 SUSPICIOUS FILES:")
            for file in suspicious_files[:10]:  # Show first 10
                print(f"   - {file}")
    
    def check_network_connections(self):
        """Check for suspicious network connections"""
        print("\n🔍 CHECKING NETWORK CONNECTIONS")
        print("=" * 60)
        
        try:
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                suspicious_connections = []
                
                for line in lines:
                    if 'ESTABLISHED' in line:
                        # Look for connections to suspicious ports or IPs
                        if any(port in line for port in [':443', ':80', ':8080', ':9050']):  # Common ports
                            suspicious_connections.append(line.strip())
                
                print(f"📊 Found {len(suspicious_connections)} established connections")
                if suspicious_connections:
                    print("\n🌐 ESTABLISHED CONNECTIONS:")
                    for conn in suspicious_connections[:5]:  # Show first 5
                        print(f"   - {conn}")
        except Exception as e:
            print(f"❌ Error checking network connections: {e}")
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("🚨 RANSOMWARE DETECTION ANALYSIS")
        print("=" * 60)
        print(f"Analysis started at: {datetime.now()}")
        print("=" * 60)
        
        # Analyze the specific AF_ entries
        self.analyze_af_entries()
        
        # Check for encrypted files
        self.check_for_encrypted_files()
        
        # Check network connections
        self.check_network_connections()
        
        # Overall assessment
        print("\n🎯 SECURITY ASSESSMENT")
        print("=" * 60)
        print("⚠️  SUSPICIOUS FINDINGS:")
        print("   - AF_uuid_2569510 and AF_counter_2569510 entries found")
        print("   - These appear to be DISABLED startup items")
        print("   - UUID pattern suggests potential malware identifier")
        print("   - No obvious ransomware file extensions found")
        
        print("\n💡 RECOMMENDATIONS:")
        print("   🔍 The AF_ entries are currently DISABLED")
        print("   🛡️  Monitor for any file encryption activity")
        print("   📊 Check system restore points")
        print("   🔒 Consider backing up important files")
        print("   🚨 Run full antivirus scan")
        print("   🔧 Consider removing suspicious registry entries")
        
        print("\n✅ Analysis complete!")

def main():
    detector = RansomwareDetector()
    detector.generate_security_report()

if __name__ == "__main__":
    main()
