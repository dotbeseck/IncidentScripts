#!/usr/bin/env python3
"""
macOS Security Audit Script for CrowdStrike Falcon RTR
Designed to run in restricted environments with minimal dependencies
"""

import os
import sys
import json
import subprocess
import plistlib
from datetime import datetime
from pathlib import Path

class MacOSSecurityAudit:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'system_info': {},
            'security_checks': {},
            'findings': [],
            'recommendations': []
        }
    
    def run_command(self, command, timeout=30):
        """Safely execute system commands"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr': 'Command timed out', 'returncode': -1}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e), 'returncode': -1}
    
    def get_system_info(self):
        """Collect basic system information"""
        print("[INFO] Collecting system information...")
        
        # Get macOS version
        version_result = self.run_command("sw_vers")
        if version_result['success']:
            version_info = {}
            for line in version_result['stdout'].split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    version_info[key.strip()] = value.strip()
            self.results['system_info']['version'] = version_info
        
        # Get hardware info
        hw_result = self.run_command("system_profiler SPHardwareDataType")
        if hw_result['success']:
            self.results['system_info']['hardware'] = hw_result['stdout']
        
        # Get current user
        self.results['system_info']['current_user'] = os.getenv('USER', 'unknown')
        
        # Get uptime
        uptime_result = self.run_command("uptime")
        if uptime_result['success']:
            self.results['system_info']['uptime'] = uptime_result['stdout']
    
    def check_sip_status(self):
        """Check System Integrity Protection status"""
        print("[INFO] Checking System Integrity Protection (SIP)...")
        
        sip_result = self.run_command("csrutil status")
        sip_status = {
            'enabled': False,
            'status': 'Unknown',
            'raw_output': sip_result['stdout'] if sip_result['success'] else sip_result['stderr']
        }
        
        if sip_result['success']:
            if 'enabled' in sip_result['stdout'].lower():
                sip_status['enabled'] = True
                sip_status['status'] = 'Enabled'
            elif 'disabled' in sip_result['stdout'].lower():
                sip_status['enabled'] = False
                sip_status['status'] = 'Disabled'
        
        self.results['security_checks']['sip'] = sip_status
        
        if not sip_status['enabled']:
            self.results['findings'].append({
                'severity': 'HIGH',
                'category': 'System Integrity',
                'description': 'System Integrity Protection (SIP) is disabled',
                'recommendation': 'Enable SIP to protect system files and processes'
            })
    
    def check_gatekeeper_status(self):
        """Check Gatekeeper status"""
        print("[INFO] Checking Gatekeeper status...")
        
        gk_result = self.run_command("spctl --status")
        gatekeeper_status = {
            'enabled': False,
            'status': 'Unknown',
            'raw_output': gk_result['stdout'] if gk_result['success'] else gk_result['stderr']
        }
        
        if gk_result['success']:
            if 'enabled' in gk_result['stdout'].lower():
                gatekeeper_status['enabled'] = True
                gatekeeper_status['status'] = 'Enabled'
            elif 'disabled' in gk_result['stdout'].lower():
                gatekeeper_status['enabled'] = False
                gatekeeper_status['status'] = 'Disabled'
        
        self.results['security_checks']['gatekeeper'] = gatekeeper_status
        
        if not gatekeeper_status['enabled']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Application Security',
                'description': 'Gatekeeper is disabled',
                'recommendation': 'Enable Gatekeeper to prevent execution of unsigned applications'
            })
    
    def check_filevault_status(self):
        """Check FileVault encryption status"""
        print("[INFO] Checking FileVault status...")
        
        fv_result = self.run_command("fdesetup status")
        filevault_status = {
            'enabled': False,
            'status': 'Unknown',
            'raw_output': fv_result['stdout'] if fv_result['success'] else fv_result['stderr']
        }
        
        if fv_result['success']:
            if 'on' in fv_result['stdout'].lower():
                filevault_status['enabled'] = True
                filevault_status['status'] = 'Enabled'
            elif 'off' in fv_result['stdout'].lower():
                filevault_status['enabled'] = False
                filevault_status['status'] = 'Disabled'
        
        self.results['security_checks']['filevault'] = filevault_status
        
        if not filevault_status['enabled']:
            self.results['findings'].append({
                'severity': 'HIGH',
                'category': 'Data Protection',
                'description': 'FileVault disk encryption is disabled',
                'recommendation': 'Enable FileVault to encrypt the startup disk'
            })
    
    def check_firewall_status(self):
        """Check firewall status"""
        print("[INFO] Checking firewall status...")
        
        fw_result = self.run_command("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate")
        firewall_status = {
            'enabled': False,
            'status': 'Unknown',
            'raw_output': fw_result['stdout'] if fw_result['success'] else fw_result['stderr']
        }
        
        if fw_result['success']:
            if 'enabled' in fw_result['stdout'].lower():
                firewall_status['enabled'] = True
                firewall_status['status'] = 'Enabled'
            elif 'disabled' in fw_result['stdout'].lower():
                firewall_status['enabled'] = False
                firewall_status['status'] = 'Disabled'
        
        self.results['security_checks']['firewall'] = firewall_status
        
        if not firewall_status['enabled']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Network Security',
                'description': 'Firewall is disabled',
                'recommendation': 'Enable the firewall to block unauthorized network connections'
            })
    
    def check_launch_agents(self):
        """Check for suspicious launch agents and daemons"""
        print("[INFO] Checking launch agents and daemons...")
        
        suspicious_agents = []
        launch_paths = [
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons',
            '/System/Library/LaunchAgents',
            '/System/Library/LaunchDaemons',
            f'{os.path.expanduser("~")}/Library/LaunchAgents'
        ]
        
        for path in launch_paths:
            if os.path.exists(path):
                try:
                    for file in os.listdir(path):
                        if file.endswith('.plist'):
                            plist_path = os.path.join(path, file)
                            try:
                                with open(plist_path, 'rb') as f:
                                    plist_data = plistlib.load(f)
                                
                                # Check for suspicious patterns
                                if 'ProgramArguments' in plist_data:
                                    args = plist_data['ProgramArguments']
                                    if isinstance(args, list) and len(args) > 0:
                                        program = args[0]
                                        if any(suspicious in program.lower() for suspicious in ['curl', 'wget', 'nc', 'netcat', 'python', 'perl', 'bash', 'sh']):
                                            suspicious_agents.append({
                                                'file': plist_path,
                                                'program': program,
                                                'arguments': args[1:] if len(args) > 1 else []
                                            })
                            except Exception as e:
                                continue
                except Exception as e:
                    continue
        
        self.results['security_checks']['launch_agents'] = {
            'suspicious_count': len(suspicious_agents),
            'suspicious_agents': suspicious_agents
        }
        
        if suspicious_agents:
            self.results['findings'].append({
                'severity': 'HIGH',
                'category': 'Persistence',
                'description': f'Found {len(suspicious_agents)} suspicious launch agents/daemons',
                'details': suspicious_agents,
                'recommendation': 'Review and remove suspicious launch agents/daemons'
            })
    
    def check_system_extensions(self):
        """Check for system extensions"""
        print("[INFO] Checking system extensions...")
        
        # Check for kernel extensions (deprecated but still possible)
        kext_result = self.run_command("kextstat")
        kext_status = {
            'loaded_extensions': [],
            'raw_output': kext_result['stdout'] if kext_result['success'] else kext_result['stderr']
        }
        
        if kext_result['success']:
            lines = kext_result['stdout'].split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        kext_status['loaded_extensions'].append({
                            'index': parts[0],
                            'name': parts[1],
                            'version': parts[2] if len(parts) > 2 else 'Unknown'
                        })
        
        # Check for system extensions (newer method)
        sysext_result = self.run_command("systemextensionsctl list")
        sysext_status = {
            'extensions': [],
            'raw_output': sysext_result['stdout'] if sysext_result['success'] else sysext_result['stderr']
        }
        
        if sysext_result['success']:
            lines = sysext_result['stdout'].split('\n')
            for line in lines:
                if line.strip() and not line.startswith('---'):
                    sysext_status['extensions'].append(line.strip())
        
        self.results['security_checks']['system_extensions'] = {
            'kernel_extensions': kext_status,
            'system_extensions': sysext_status
        }
        
        # Check for suspicious extensions
        suspicious_extensions = []
        for ext in kext_status['loaded_extensions']:
            if any(suspicious in ext['name'].lower() for suspicious in ['rootkit', 'backdoor', 'trojan', 'malware']):
                suspicious_extensions.append(ext)
        
        if suspicious_extensions:
            self.results['findings'].append({
                'severity': 'CRITICAL',
                'category': 'System Extensions',
                'description': f'Found {len(suspicious_extensions)} suspicious system extensions',
                'details': suspicious_extensions,
                'recommendation': 'Immediately investigate and remove suspicious system extensions'
            })
    
    def check_network_connections(self):
        """Check for suspicious network connections"""
        print("[INFO] Checking network connections...")
        
        # Get network connections
        netstat_result = self.run_command("netstat -an")
        network_info = {
            'connections': [],
            'raw_output': netstat_result['stdout'] if netstat_result['success'] else netstat_result['stderr']
        }
        
        if netstat_result['success']:
            lines = netstat_result['stdout'].split('\n')
            for line in lines:
                if 'ESTABLISHED' in line or 'LISTEN' in line:
                    network_info['connections'].append(line.strip())
        
        # Check for suspicious ports
        suspicious_ports = [22, 23, 3389, 445, 135, 137, 138, 139, 161, 162, 389, 636, 1433, 1521, 3306, 5432, 6379, 27017]
        suspicious_connections = []
        
        for conn in network_info['connections']:
            for port in suspicious_ports:
                if f':{port}' in conn or f'.{port}' in conn:
                    suspicious_connections.append({
                        'connection': conn,
                        'suspicious_port': port
                    })
        
        self.results['security_checks']['network'] = {
            'total_connections': len(network_info['connections']),
            'suspicious_connections': suspicious_connections,
            'all_connections': network_info['connections']
        }
        
        if suspicious_connections:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Network Security',
                'description': f'Found {len(suspicious_connections)} connections to suspicious ports',
                'details': suspicious_connections,
                'recommendation': 'Review network connections and block suspicious ports'
            })
    
    def check_sudo_users(self):
        """Check for users with sudo privileges"""
        print("[INFO] Checking sudo users...")
        
        sudo_result = self.run_command("dscl . -read /Groups/admin GroupMembership")
        sudo_users = {
            'admin_users': [],
            'raw_output': sudo_result['stdout'] if sudo_result['success'] else sudo_result['stderr']
        }
        
        if sudo_result['success']:
            # Parse admin users from output
            output = sudo_result['stdout']
            if 'GroupMembership:' in output:
                users_line = output.split('GroupMembership:')[1].strip()
                sudo_users['admin_users'] = users_line.split()
        
        self.results['security_checks']['sudo_users'] = sudo_users
        
        # Check for excessive admin users
        if len(sudo_users['admin_users']) > 3:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Access Control',
                'description': f'Found {len(sudo_users["admin_users"])} admin users (excessive)',
                'details': sudo_users['admin_users'],
                'recommendation': 'Review admin users and remove unnecessary privileges'
            })
    
    def check_recent_files(self):
        """Check for recently modified files in sensitive locations"""
        print("[INFO] Checking recent files in sensitive locations...")
        
        sensitive_paths = [
            '/etc',
            '/usr/bin',
            '/usr/sbin',
            '/System/Library',
            '/Library/LaunchAgents',
            '/Library/LaunchDaemons'
        ]
        
        recent_files = []
        for path in sensitive_paths:
            if os.path.exists(path):
                try:
                    # Find files modified in the last 7 days
                    find_result = self.run_command(f"find {path} -type f -mtime -7 -exec ls -la {{}} +")
                    if find_result['success']:
                        lines = find_result['stdout'].split('\n')
                        for line in lines:
                            if line.strip():
                                recent_files.append({
                                    'path': path,
                                    'file_info': line.strip()
                                })
                except Exception:
                    continue
        
        self.results['security_checks']['recent_files'] = {
            'count': len(recent_files),
            'files': recent_files[:50]  # Limit to first 50 to avoid huge output
        }
        
        if len(recent_files) > 20:
            self.results['findings'].append({
                'severity': 'LOW',
                'category': 'File System',
                'description': f'Found {len(recent_files)} recently modified files in sensitive locations',
                'recommendation': 'Review recent file modifications for suspicious activity'
            })
    
    def generate_summary(self):
        """Generate security summary and recommendations"""
        total_findings = len(self.results['findings'])
        critical_findings = len([f for f in self.results['findings'] if f['severity'] == 'CRITICAL'])
        high_findings = len([f for f in self.results['findings'] if f['severity'] == 'HIGH'])
        medium_findings = len([f for f in self.results['findings'] if f['severity'] == 'MEDIUM'])
        low_findings = len([f for f in self.results['findings'] if f['severity'] == 'LOW'])
        
        self.results['summary'] = {
            'total_findings': total_findings,
            'critical': critical_findings,
            'high': high_findings,
            'medium': medium_findings,
            'low': low_findings,
            'security_score': max(0, 100 - (critical_findings * 25 + high_findings * 15 + medium_findings * 10 + low_findings * 5))
        }
        
        # Generate recommendations
        if critical_findings > 0:
            self.results['recommendations'].append("CRITICAL: Address critical security findings immediately")
        if high_findings > 0:
            self.results['recommendations'].append("HIGH: Address high-priority security findings within 24 hours")
        if medium_findings > 0:
            self.results['recommendations'].append("MEDIUM: Address medium-priority findings within 1 week")
        if low_findings > 0:
            self.results['recommendations'].append("LOW: Review low-priority findings during next maintenance window")
        
        if total_findings == 0:
            self.results['recommendations'].append("No security issues found - maintain current security posture")
    
    def run_audit(self):
        """Run complete security audit"""
        print("Starting macOS Security Audit...")
        print("=" * 50)
        
        self.get_system_info()
        self.check_sip_status()
        self.check_gatekeeper_status()
        self.check_filevault_status()
        self.check_firewall_status()
        self.check_launch_agents()
        self.check_system_extensions()
        self.check_network_connections()
        self.check_sudo_users()
        self.check_recent_files()
        self.generate_summary()
        
        print("=" * 50)
        print("Security Audit Complete!")
        print(f"Total Findings: {self.results['summary']['total_findings']}")
        print(f"Security Score: {self.results['summary']['security_score']}/100")
        
        return self.results

def main():
    """Main function for RTR execution"""
    audit = MacOSSecurityAudit()
    results = audit.run_audit()
    
    # Output results in JSON format for RTR
    print("\n" + "=" * 50)
    print("AUDIT RESULTS (JSON):")
    print("=" * 50)
    print(json.dumps(results, indent=2))
    
    # Also save to file if possible
    try:
        output_file = f"/tmp/macos_security_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Could not save to file: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
