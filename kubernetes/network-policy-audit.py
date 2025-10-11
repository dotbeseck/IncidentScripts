#!/usr/bin/env python3
"""
Kubernetes Network Policy Auditor
Comprehensive analysis of network security policies and configurations
"""

import os
import sys
import json
import subprocess
import yaml
import re
from datetime import datetime
from collections import defaultdict

class KubernetesNetworkPolicyAuditor:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'cluster_info': {},
            'network_analysis': {},
            'findings': [],
            'recommendations': []
        }
        self.namespace = os.getenv('KUBECTL_NAMESPACE', 'default')
    
    def run_kubectl(self, command, timeout=30):
        """Safely execute kubectl commands"""
        try:
            full_command = f"kubectl {command}"
            result = subprocess.run(
                full_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout.strip(),
                'stderr': result.stderr.strip(),
                'returncode': result.returncode,
                'command': full_command
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr': 'Command timed out', 'returncode': -1}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr': str(e), 'returncode': -1}
    
    def get_cluster_info(self):
        """Get basic cluster information"""
        print("[INFO] Collecting cluster information...")
        
        # Get cluster version
        version_result = self.run_kubectl("version --output=yaml")
        if version_result['success']:
            try:
                version_data = yaml.safe_load(version_result['stdout'])
                self.results['cluster_info']['version'] = version_data
            except yaml.YAMLError:
                self.results['cluster_info']['version'] = version_result['stdout']
        
        # Get current context
        context_result = self.run_kubectl("config current-context")
        if context_result['success']:
            self.results['cluster_info']['current_context'] = context_result['stdout']
        
        # Get namespaces
        ns_result = self.run_kubectl("get namespaces -o name")
        if ns_result['success']:
            namespaces = [ns.replace('namespace/', '') for ns in ns_result['stdout'].split('\n') if ns.strip()]
            self.results['cluster_info']['namespaces'] = namespaces
    
    def analyze_network_policies(self):
        """Analyze network policies across all namespaces"""
        print("[INFO] Analyzing network policies...")
        
        network_analysis = {
            'policies': [],
            'namespaces_with_policies': set(),
            'namespaces_without_policies': set(),
            'policy_issues': [],
            'coverage_analysis': {}
        }
        
        # Get all network policies
        netpol_result = self.run_kubectl("get networkpolicies --all-namespaces -o yaml")
        if netpol_result['success']:
            try:
                netpol_data = yaml.safe_load(netpol_result['stdout'])
                if 'items' in netpol_data:
                    for policy in netpol_data['items']:
                        policy_analysis = self._analyze_single_policy(policy)
                        network_analysis['policies'].append(policy_analysis)
                        network_analysis['namespaces_with_policies'].add(policy['metadata']['namespace'])
                        
                        if policy_analysis['issues']:
                            network_analysis['policy_issues'].extend(policy_analysis['issues'])
            except yaml.YAMLError:
                pass
        
        # Find namespaces without network policies
        all_namespaces = set(self.results['cluster_info'].get('namespaces', []))
        system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'}
        user_namespaces = all_namespaces - system_namespaces
        
        network_analysis['namespaces_without_policies'] = user_namespaces - network_analysis['namespaces_with_policies']
        
        # Calculate coverage
        total_user_namespaces = len(user_namespaces)
        namespaces_with_policies = len(network_analysis['namespaces_with_policies'])
        coverage_percentage = (namespaces_with_policies / total_user_namespaces * 100) if total_user_namespaces > 0 else 0
        
        network_analysis['coverage_analysis'] = {
            'total_user_namespaces': total_user_namespaces,
            'namespaces_with_policies': namespaces_with_policies,
            'namespaces_without_policies': len(network_analysis['namespaces_without_policies']),
            'coverage_percentage': coverage_percentage
        }
        
        self.results['network_analysis']['policies'] = network_analysis
        
        # Add findings
        if network_analysis['namespaces_without_policies']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Network Policy Coverage',
                'description': f'Found {len(network_analysis["namespaces_without_policies"])} namespaces without network policies',
                'details': list(network_analysis['namespaces_without_policies']),
                'recommendation': 'Implement network policies for namespace isolation'
            })
        
        if network_analysis['policy_issues']:
            critical_issues = [i for i in network_analysis['policy_issues'] if i['severity'] == 'CRITICAL']
            high_issues = [i for i in network_analysis['policy_issues'] if i['severity'] == 'HIGH']
            medium_issues = [i for i in network_analysis['policy_issues'] if i['severity'] == 'MEDIUM']
            
            if critical_issues:
                self.results['findings'].append({
                    'severity': 'CRITICAL',
                    'category': 'Network Policy Configuration',
                    'description': f'Found {len(critical_issues)} critical network policy issues',
                    'details': critical_issues,
                    'recommendation': 'Immediately fix critical network policy configurations'
                })
            
            if high_issues:
                self.results['findings'].append({
                    'severity': 'HIGH',
                    'category': 'Network Policy Configuration',
                    'description': f'Found {len(high_issues)} high-severity network policy issues',
                    'details': high_issues,
                    'recommendation': 'Review and fix network policy configurations'
                })
            
            if medium_issues:
                self.results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'Network Policy Configuration',
                    'description': f'Found {len(medium_issues)} medium-severity network policy issues',
                    'details': medium_issues,
                    'recommendation': 'Review network policy configurations'
                })
    
    def _analyze_single_policy(self, policy):
        """Analyze a single network policy"""
        policy_name = policy['metadata']['name']
        namespace = policy['metadata']['namespace']
        
        analysis = {
            'name': policy_name,
            'namespace': namespace,
            'pod_selector': policy.get('spec', {}).get('podSelector', {}),
            'policy_types': policy.get('spec', {}).get('policyTypes', []),
            'ingress_rules': [],
            'egress_rules': [],
            'issues': [],
            'risk_score': 0
        }
        
        # Analyze ingress rules
        ingress_rules = policy.get('spec', {}).get('ingress', [])
        for i, rule in enumerate(ingress_rules):
            rule_analysis = self._analyze_ingress_rule(rule, i)
            analysis['ingress_rules'].append(rule_analysis)
            
            if rule_analysis['issues']:
                analysis['issues'].extend(rule_analysis['issues'])
                analysis['risk_score'] += sum(25 if issue['severity'] == 'CRITICAL' else 15 if issue['severity'] == 'HIGH' else 10 for issue in rule_analysis['issues'])
        
        # Analyze egress rules
        egress_rules = policy.get('spec', {}).get('egress', [])
        for i, rule in enumerate(egress_rules):
            rule_analysis = self._analyze_egress_rule(rule, i)
            analysis['egress_rules'].append(rule_analysis)
            
            if rule_analysis['issues']:
                analysis['issues'].extend(rule_analysis['issues'])
                analysis['risk_score'] += sum(25 if issue['severity'] == 'CRITICAL' else 15 if issue['severity'] == 'HIGH' else 10 for issue in rule_analysis['issues'])
        
        # Check for missing policy types
        if not analysis['policy_types']:
            analysis['issues'].append({
                'rule_type': 'Policy',
                'rule_index': 'N/A',
                'issue': 'Missing policy types',
                'severity': 'MEDIUM',
                'details': 'Network policy does not specify policy types'
            })
        
        return analysis
    
    def _analyze_ingress_rule(self, rule, rule_index):
        """Analyze an ingress rule"""
        rule_analysis = {
            'index': rule_index,
            'from': rule.get('from', []),
            'ports': rule.get('ports', []),
            'issues': []
        }
        
        # Check for overly permissive ingress
        if not rule_analysis['from']:
            rule_analysis['issues'].append({
                'rule_type': 'Ingress',
                'rule_index': rule_index,
                'issue': 'Overly permissive ingress rule',
                'severity': 'HIGH',
                'details': 'Ingress rule allows traffic from all sources'
            })
        
        # Check for specific port restrictions
        if not rule_analysis['ports']:
            rule_analysis['issues'].append({
                'rule_type': 'Ingress',
                'rule_index': rule_index,
                'issue': 'No port restrictions',
                'severity': 'MEDIUM',
                'details': 'Ingress rule allows traffic on all ports'
            })
        
        # Check for dangerous port combinations
        dangerous_ports = [22, 23, 3389, 445, 135, 137, 138, 139, 161, 162, 389, 636, 1433, 1521, 3306, 5432, 6379, 27017]
        for port in rule_analysis['ports']:
            if isinstance(port, dict) and 'port' in port:
                port_num = port['port']
                if isinstance(port_num, int) and port_num in dangerous_ports:
                    rule_analysis['issues'].append({
                        'rule_type': 'Ingress',
                        'rule_index': rule_index,
                        'issue': 'Dangerous port exposed',
                        'severity': 'HIGH',
                        'details': f'Ingress rule exposes potentially dangerous port: {port_num}'
                    })
        
        return rule_analysis
    
    def _analyze_egress_rule(self, rule, rule_index):
        """Analyze an egress rule"""
        rule_analysis = {
            'index': rule_index,
            'to': rule.get('to', []),
            'ports': rule.get('ports', []),
            'issues': []
        }
        
        # Check for overly permissive egress
        if not rule_analysis['to']:
            rule_analysis['issues'].append({
                'rule_type': 'Egress',
                'rule_index': rule_index,
                'issue': 'Overly permissive egress rule',
                'severity': 'MEDIUM',
                'details': 'Egress rule allows traffic to all destinations'
            })
        
        # Check for specific port restrictions
        if not rule_analysis['ports']:
            rule_analysis['issues'].append({
                'rule_type': 'Egress',
                'rule_index': rule_index,
                'issue': 'No port restrictions',
                'severity': 'LOW',
                'details': 'Egress rule allows traffic on all ports'
            })
        
        return rule_analysis
    
    def analyze_services(self):
        """Analyze service configurations and exposure"""
        print("[INFO] Analyzing service configurations...")
        
        service_analysis = {
            'services': [],
            'exposed_services': [],
            'service_issues': []
        }
        
        # Get all services
        services_result = self.run_kubectl("get services --all-namespaces -o yaml")
        if services_result['success']:
            try:
                services_data = yaml.safe_load(services_result['stdout'])
                if 'items' in services_data:
                    for service in services_data['items']:
                        service_info = self._analyze_single_service(service)
                        service_analysis['services'].append(service_info)
                        
                        if service_info['exposed']:
                            service_analysis['exposed_services'].append(service_info)
                        
                        if service_info['issues']:
                            service_analysis['service_issues'].extend(service_info['issues'])
            except yaml.YAMLError:
                pass
        
        self.results['network_analysis']['services'] = service_analysis
        
        # Add findings
        if service_analysis['exposed_services']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Service Exposure',
                'description': f'Found {len(service_analysis["exposed_services"])} exposed services',
                'details': service_analysis['exposed_services'],
                'recommendation': 'Review exposed services and restrict access where possible'
            })
        
        if service_analysis['service_issues']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Service Configuration',
                'description': f'Found {len(service_analysis["service_issues"])} service configuration issues',
                'details': service_analysis['service_issues'],
                'recommendation': 'Review service configurations'
            })
    
    def _analyze_single_service(self, service):
        """Analyze a single service"""
        service_name = service['metadata']['name']
        namespace = service['metadata']['namespace']
        service_type = service.get('spec', {}).get('type', 'ClusterIP')
        ports = service.get('spec', {}).get('ports', [])
        
        service_info = {
            'name': service_name,
            'namespace': namespace,
            'type': service_type,
            'ports': ports,
            'exposed': False,
            'issues': []
        }
        
        # Check if service is exposed externally
        if service_type in ['NodePort', 'LoadBalancer']:
            service_info['exposed'] = True
            service_info['issues'].append({
                'issue': 'Service exposed externally',
                'severity': 'MEDIUM',
                'details': f'Service {service_name} is exposed via {service_type}'
            })
        
        # Check for dangerous ports
        dangerous_ports = [22, 23, 3389, 445, 135, 137, 138, 139, 161, 162, 389, 636, 1433, 1521, 3306, 5432, 6379, 27017]
        for port in ports:
            port_num = port.get('port')
            if port_num in dangerous_ports:
                service_info['issues'].append({
                    'issue': 'Dangerous port exposed',
                    'severity': 'HIGH',
                    'details': f'Service {service_name} exposes potentially dangerous port: {port_num}'
                })
        
        return service_info
    
    def analyze_ingress(self):
        """Analyze ingress configurations"""
        print("[INFO] Analyzing ingress configurations...")
        
        ingress_analysis = {
            'ingresses': [],
            'ingress_issues': []
        }
        
        # Get all ingresses
        ingress_result = self.run_kubectl("get ingresses --all-namespaces -o yaml")
        if ingress_result['success']:
            try:
                ingress_data = yaml.safe_load(ingress_result['stdout'])
                if 'items' in ingress_data:
                    for ingress in ingress_data['items']:
                        ingress_info = self._analyze_single_ingress(ingress)
                        ingress_analysis['ingresses'].append(ingress_info)
                        
                        if ingress_info['issues']:
                            ingress_analysis['ingress_issues'].extend(ingress_info['issues'])
            except yaml.YAMLError:
                pass
        
        self.results['network_analysis']['ingress'] = ingress_analysis
        
        # Add findings
        if ingress_analysis['ingress_issues']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Ingress Configuration',
                'description': f'Found {len(ingress_analysis["ingress_issues"])} ingress configuration issues',
                'details': ingress_analysis['ingress_issues'],
                'recommendation': 'Review ingress configurations'
            })
    
    def _analyze_single_ingress(self, ingress):
        """Analyze a single ingress"""
        ingress_name = ingress['metadata']['name']
        namespace = ingress['metadata']['namespace']
        rules = ingress.get('spec', {}).get('rules', [])
        tls = ingress.get('spec', {}).get('tls', [])
        
        ingress_info = {
            'name': ingress_name,
            'namespace': namespace,
            'rules': rules,
            'tls': tls,
            'issues': []
        }
        
        # Check for TLS configuration
        if not tls:
            ingress_info['issues'].append({
                'issue': 'No TLS configuration',
                'severity': 'MEDIUM',
                'details': f'Ingress {ingress_name} does not have TLS configuration'
            })
        
        # Check for wildcard hosts
        for rule in rules:
            host = rule.get('host', '')
            if '*' in host:
                ingress_info['issues'].append({
                    'issue': 'Wildcard host',
                    'severity': 'LOW',
                    'details': f'Ingress {ingress_name} uses wildcard host: {host}'
                })
        
        return ingress_info
    
    def analyze_network_security(self):
        """Analyze overall network security posture"""
        print("[INFO] Analyzing network security posture...")
        
        security_analysis = {
            'network_policy_coverage': 0,
            'exposed_services_count': 0,
            'ingress_count': 0,
            'security_score': 0
        }
        
        # Calculate network policy coverage
        if 'policies' in self.results['network_analysis']:
            coverage = self.results['network_analysis']['policies']['coverage_analysis']
            security_analysis['network_policy_coverage'] = coverage['coverage_percentage']
        
        # Count exposed services
        if 'services' in self.results['network_analysis']:
            security_analysis['exposed_services_count'] = len(self.results['network_analysis']['services']['exposed_services'])
        
        # Count ingresses
        if 'ingress' in self.results['network_analysis']:
            security_analysis['ingress_count'] = len(self.results['network_analysis']['ingress']['ingresses'])
        
        # Calculate security score
        security_score = 100
        security_score -= (100 - security_analysis['network_policy_coverage']) * 0.5  # Network policy coverage
        security_score -= min(security_analysis['exposed_services_count'] * 5, 30)  # Exposed services
        security_score -= min(security_analysis['ingress_count'] * 2, 20)  # Ingresses
        
        security_analysis['security_score'] = max(0, security_score)
        
        self.results['network_analysis']['security_posture'] = security_analysis
    
    def generate_summary(self):
        """Generate network security summary"""
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
            'network_security_score': self.results['network_analysis'].get('security_posture', {}).get('security_score', 0)
        }
        
        # Generate recommendations
        if critical_findings > 0:
            self.results['recommendations'].append("CRITICAL: Address critical network security findings immediately")
        if high_findings > 0:
            self.results['recommendations'].append("HIGH: Address high-priority network security findings within 24 hours")
        if medium_findings > 0:
            self.results['recommendations'].append("MEDIUM: Address medium-priority findings within 1 week")
        if low_findings > 0:
            self.results['recommendations'].append("LOW: Review low-priority findings during next maintenance window")
        
        if total_findings == 0:
            self.results['recommendations'].append("No network security issues found - maintain current security posture")
    
    def run_audit(self):
        """Run complete network policy audit"""
        print("Starting Kubernetes Network Policy Audit...")
        print("=" * 50)
        
        self.get_cluster_info()
        self.analyze_network_policies()
        self.analyze_services()
        self.analyze_ingress()
        self.analyze_network_security()
        self.generate_summary()
        
        print("=" * 50)
        print("Network Policy Audit Complete!")
        print(f"Total Findings: {self.results['summary']['total_findings']}")
        print(f"Network Security Score: {self.results['summary']['network_security_score']}/100")
        
        return self.results

def main():
    """Main function"""
    auditor = KubernetesNetworkPolicyAuditor()
    results = auditor.run_audit()
    
    # Output results in JSON format
    print("\n" + "=" * 50)
    print("NETWORK POLICY AUDIT RESULTS (JSON):")
    print("=" * 50)
    print(json.dumps(results, indent=2))
    
    # Also save to file if possible
    try:
        output_file = f"/tmp/k8s_network_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Could not save to file: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
