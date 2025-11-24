#!/usr/bin/env python3
"""
macOS Process Forensics Script for CrowdStrike Falcon RTR
Deep process analysis and anomaly detection
"""

import os
import sys
import json
import subprocess
import re
from datetime import datetime
from collections import defaultdict

class MacOSProcessForensics:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': os.uname().nodename,
            'process_analysis': {},
            'anomalies': [],
            'suspicious_processes': [],
            'network_connections': {},
            'findings': []
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
    
    def get_process_list(self):
        """Get detailed process list"""
        print("[INFO] Collecting process information...")
        
        # Get process list with detailed information
        ps_result = self.run_command("ps -axo pid,ppid,user,command,pcpu,pmem,time,state")
        processes = []
        
        if ps_result['success']:
            lines = ps_result['stdout'].split('\n')
            headers = lines[0].split()
            
            for line in lines[1:]:
                if line.strip():
                    parts = line.split(None, 7)  # Split into max 8 parts
                    if len(parts) >= 8:
                        process = {
                            'pid': parts[0],
                            'ppid': parts[1],
                            'user': parts[2],
                            'command': parts[7] if len(parts) > 7 else '',
                            'cpu_percent': parts[4],
                            'mem_percent': parts[5],
                            'time': parts[6],
                            'state': parts[3]
                        }
                        processes.append(process)
        
        self.results['process_analysis']['all_processes'] = processes
        self.results['process_analysis']['total_processes'] = len(processes)
        
        return processes
    
    def analyze_process_tree(self, processes):
        """Analyze process parent-child relationships"""
        print("[INFO] Analyzing process tree...")
        
        # Build process tree
        process_tree = defaultdict(list)
        process_info = {}
        
        for proc in processes:
            pid = proc['pid']
            ppid = proc['ppid']
            process_info[pid] = proc
            process_tree[ppid].append(pid)
        
        # Find orphaned processes (parent doesn't exist)
        orphaned_processes = []
        for proc in processes:
            if proc['ppid'] != '0' and proc['ppid'] not in process_info:
                orphaned_processes.append(proc)
        
        # Find processes with unusual parent-child relationships
        suspicious_relationships = []
        for proc in processes:
            # Check for processes with system PIDs as parents but running as non-system users
            if proc['ppid'] in ['1', '0'] and proc['user'] not in ['root', '_windowserver', '_securityd']:
                suspicious_relationships.append({
                    'process': proc,
                    'reason': 'Non-system process with system parent',
                    'severity': 'MEDIUM'
                })
            
            # Check for processes with high CPU usage
            try:
                cpu_usage = float(proc['cpu_percent'])
                if cpu_usage > 50.0:  # More than 50% CPU
                    suspicious_relationships.append({
                        'process': proc,
                        'reason': f'High CPU usage: {cpu_usage}%',
                        'severity': 'LOW'
                    })
            except ValueError:
                pass
        
        self.results['process_analysis']['orphaned_processes'] = orphaned_processes
        self.results['process_analysis']['suspicious_relationships'] = suspicious_relationships
        
        if orphaned_processes:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Process Anomaly',
                'description': f'Found {len(orphaned_processes)} orphaned processes',
                'details': orphaned_processes,
                'recommendation': 'Investigate orphaned processes for potential malware'
            })
    
    def detect_suspicious_processes(self, processes):
        """Detect suspicious process patterns"""
        print("[INFO] Detecting suspicious processes...")
        
        suspicious_patterns = [
            # Network tools
            r'(curl|wget|nc|netcat|ncat|nmap|telnet|ssh)',
            # Scripting languages
            r'(python|perl|ruby|php|bash|sh|zsh|ksh)',
            # System utilities
            r'(dd|cat|base64|openssl|gpg)',
            # Suspicious names
            r'(backdoor|trojan|malware|virus|rootkit)',
            # Common malware indicators
            r'(\.tmp|\.temp|\.exe|\.bat|\.cmd)',
            # Process name obfuscation
            r'^[a-zA-Z0-9]{1,3}$',  # Very short names
            r'^[0-9]+$'  # Numeric names
        ]
        
        suspicious_processes = []
        
        for proc in processes:
            command = proc['command'].lower()
            pid = proc['pid']
            user = proc['user']
            
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, command):
                    suspicious_processes.append({
                        'process': proc,
                        'matched_pattern': pattern,
                        'reason': f'Matches suspicious pattern: {pattern}',
                        'severity': 'HIGH' if 'backdoor' in pattern or 'trojan' in pattern else 'MEDIUM'
                    })
                    break
            
            # Check for processes running from suspicious locations
            if any(suspicious_path in command for suspicious_path in ['/tmp/', '/var/tmp/', '/dev/shm/', '/tmp/']):
                suspicious_processes.append({
                    'process': proc,
                    'reason': 'Running from temporary directory',
                    'severity': 'MEDIUM'
                })
            
            # Check for processes with no command line (potential code injection)
            if not command or command.strip() == '':
                suspicious_processes.append({
                    'process': proc,
                    'reason': 'No command line visible (potential code injection)',
                    'severity': 'HIGH'
                })
        
        self.results['suspicious_processes'] = suspicious_processes
        
        if suspicious_processes:
            high_severity = [p for p in suspicious_processes if p['severity'] == 'HIGH']
            medium_severity = [p for p in suspicious_processes if p['severity'] == 'MEDIUM']
            
            if high_severity:
                self.results['findings'].append({
                    'severity': 'HIGH',
                    'category': 'Suspicious Process',
                    'description': f'Found {len(high_severity)} high-severity suspicious processes',
                    'details': high_severity,
                    'recommendation': 'Immediately investigate and terminate suspicious processes'
                })
            
            if medium_severity:
                self.results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'Suspicious Process',
                    'description': f'Found {len(medium_severity)} medium-severity suspicious processes',
                    'details': medium_severity,
                    'recommendation': 'Review and investigate suspicious processes'
                })
    
    def analyze_network_connections(self):
        """Analyze network connections by process"""
        print("[INFO] Analyzing network connections...")
        
        # Get network connections with process information
        lsof_result = self.run_command("lsof -i -P -n")
        network_connections = []
        
        if lsof_result['success']:
            lines = lsof_result['stdout'].split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 9:
                        connection = {
                            'command': parts[0],
                            'pid': parts[1],
                            'user': parts[2],
                            'fd': parts[3],
                            'type': parts[4],
                            'device': parts[5],
                            'size_off': parts[6],
                            'node': parts[7],
                            'name': parts[8] if len(parts) > 8 else ''
                        }
                        network_connections.append(connection)
        
        # Group connections by process
        connections_by_process = defaultdict(list)
        for conn in network_connections:
            connections_by_process[conn['pid']].append(conn)
        
        # Find suspicious network activity
        suspicious_network = []
        for pid, connections in connections_by_process.items():
            # Check for processes with many connections
            if len(connections) > 10:
                suspicious_network.append({
                    'pid': pid,
                    'connection_count': len(connections),
                    'reason': 'High number of network connections',
                    'connections': connections[:5],  # Show first 5
                    'severity': 'MEDIUM'
                })
            
            # Check for connections to suspicious ports
            for conn in connections:
                if ':' in conn['name']:
                    port = conn['name'].split(':')[-1]
                    try:
                        port_num = int(port)
                        if port_num in [22, 23, 3389, 445, 135, 137, 138, 139, 161, 162, 389, 636, 1433, 1521, 3306, 5432, 6379, 27017]:
                            suspicious_network.append({
                                'pid': pid,
                                'connection': conn,
                                'reason': f'Connection to suspicious port {port_num}',
                                'severity': 'HIGH'
                            })
                    except ValueError:
                        pass
        
        self.results['network_connections'] = {
            'total_connections': len(network_connections),
            'connections_by_process': dict(connections_by_process),
            'suspicious_network': suspicious_network
        }
        
        if suspicious_network:
            high_severity = [n for n in suspicious_network if n['severity'] == 'HIGH']
            if high_severity:
                self.results['findings'].append({
                    'severity': 'HIGH',
                    'category': 'Network Security',
                    'description': f'Found {len(high_severity)} high-severity network anomalies',
                    'details': high_severity,
                    'recommendation': 'Investigate suspicious network connections immediately'
                })
    
    def check_memory_anomalies(self):
        """Check for memory-related anomalies"""
        print("[INFO] Checking memory anomalies...")
        
        # Get memory usage by process
        ps_result = self.run_command("ps -axo pid,pmem,rss,vsz,command")
        memory_anomalies = []
        
        if ps_result['success']:
            lines = ps_result['stdout'].split('\n')
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split(None, 4)
                    if len(parts) >= 5:
                        try:
                            pid = parts[0]
                            pmem = float(parts[1])
                            rss = int(parts[2])
                            vsz = int(parts[3])
                            command = parts[4]
                            
                            # Check for high memory usage
                            if pmem > 10.0:  # More than 10% memory
                                memory_anomalies.append({
                                    'pid': pid,
                                    'command': command,
                                    'memory_percent': pmem,
                                    'rss_mb': rss / 1024,
                                    'vsz_mb': vsz / 1024,
                                    'reason': f'High memory usage: {pmem}%',
                                    'severity': 'MEDIUM'
                                })
                            
                            # Check for unusually large virtual memory
                            if vsz > 1024 * 1024 * 1024:  # More than 1GB virtual memory
                                memory_anomalies.append({
                                    'pid': pid,
                                    'command': command,
                                    'memory_percent': pmem,
                                    'rss_mb': rss / 1024,
                                    'vsz_mb': vsz / 1024,
                                    'reason': f'Large virtual memory: {vsz / (1024*1024):.1f}MB',
                                    'severity': 'LOW'
                                })
                        except (ValueError, IndexError):
                            continue
        
        self.results['process_analysis']['memory_anomalies'] = memory_anomalies
        
        if memory_anomalies:
            high_memory = [m for m in memory_anomalies if m['memory_percent'] > 20.0]
            if high_memory:
                self.results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'Memory Anomaly',
                    'description': f'Found {len(high_memory)} processes with high memory usage',
                    'details': high_memory,
                    'recommendation': 'Investigate processes with high memory usage'
                })
    
    def check_system_calls(self):
        """Check for suspicious system call patterns"""
        print("[INFO] Checking system call patterns...")
        
        # Get processes with their system call information
        # Note: This is limited in RTR environment, but we can check what's available
        syscall_result = self.run_command("ps -axo pid,command | grep -E '(ptrace|exec|fork|clone)'")
        
        suspicious_syscalls = []
        if syscall_result['success'] and syscall_result['stdout']:
            lines = syscall_result['stdout'].split('\n')
            for line in lines:
                if line.strip():
                    parts = line.split(None, 1)
                    if len(parts) >= 2:
                        suspicious_syscalls.append({
                            'pid': parts[0],
                            'command': parts[1],
                            'reason': 'Process using system calls (ptrace/exec/fork/clone)',
                            'severity': 'LOW'
                        })
        
        self.results['process_analysis']['suspicious_syscalls'] = suspicious_syscalls
        
        if suspicious_syscalls:
            self.results['findings'].append({
                'severity': 'LOW',
                'category': 'System Calls',
                'description': f'Found {len(suspicious_syscalls)} processes using system calls',
                'details': suspicious_syscalls,
                'recommendation': 'Review processes using system calls for potential debugging or injection'
            })
    
    def generate_summary(self):
        """Generate process forensics summary"""
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
            'total_processes': self.results['process_analysis'].get('total_processes', 0),
            'suspicious_processes': len(self.results['suspicious_processes']),
            'network_connections': self.results['network_connections'].get('total_connections', 0)
        }
    
    def run_forensics(self):
        """Run complete process forensics analysis"""
        print("Starting macOS Process Forensics Analysis...")
        print("=" * 60)
        
        processes = self.get_process_list()
        self.analyze_process_tree(processes)
        self.detect_suspicious_processes(processes)
        self.analyze_network_connections()
        self.check_memory_anomalies()
        self.check_system_calls()
        self.generate_summary()
        
        print("=" * 60)
        print("Process Forensics Analysis Complete!")
        print(f"Total Processes: {self.results['summary']['total_processes']}")
        print(f"Total Findings: {self.results['summary']['total_findings']}")
        print(f"Suspicious Processes: {self.results['summary']['suspicious_processes']}")
        
        return self.results

def main():
    """Main function for RTR execution"""
    forensics = MacOSProcessForensics()
    results = forensics.run_forensics()
    
    # Output results in JSON format for RTR
    print("\n" + "=" * 60)
    print("FORENSICS RESULTS (JSON):")
    print("=" * 60)
    print(json.dumps(results, indent=2))
    
    # Also save to file if possible
    try:
        output_file = f"/tmp/macos_process_forensics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Could not save to file: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
