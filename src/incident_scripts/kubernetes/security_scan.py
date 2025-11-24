#!/usr/bin/env python3
"""
Kubernetes Security Scanner for Incident Response
Comprehensive security assessment of Kubernetes clusters
"""

import os
import sys
import json
import subprocess
import yaml
import re
from datetime import datetime
from collections import defaultdict

class KubernetesSecurityScanner:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'cluster_info': {},
            'security_checks': {},
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
        
        # Get cluster info
        cluster_result = self.run_kubectl("cluster-info")
        if cluster_result['success']:
            self.results['cluster_info']['cluster_info'] = cluster_result['stdout']
        
        # Get current context
        context_result = self.run_kubectl("config current-context")
        if context_result['success']:
            self.results['cluster_info']['current_context'] = context_result['stdout']
        
        # Get namespaces
        ns_result = self.run_kubectl("get namespaces -o name")
        if ns_result['success']:
            namespaces = [ns.replace('namespace/', '') for ns in ns_result['stdout'].split('\n') if ns.strip()]
            self.results['cluster_info']['namespaces'] = namespaces
    
    def check_pod_security(self):
        """Check pod security contexts and configurations"""
        print("[INFO] Checking pod security contexts...")
        
        # Get all pods with security context details
        pods_result = self.run_kubectl("get pods --all-namespaces -o yaml")
        pod_security_issues = []
        
        if pods_result['success']:
            try:
                pods_data = yaml.safe_load(pods_result['stdout'])
                if 'items' in pods_data:
                    for pod in pods_data['items']:
                        pod_name = pod['metadata']['name']
                        namespace = pod['metadata']['namespace']
                        
                        # Check security context
                        security_context = pod.get('spec', {}).get('securityContext', {})
                        containers = pod.get('spec', {}).get('containers', [])
                        
                        pod_issues = []
                        
                        # Check if running as root
                        if security_context.get('runAsUser') == 0 or security_context.get('runAsNonRoot') == False:
                            pod_issues.append({
                                'issue': 'Running as root user',
                                'severity': 'HIGH',
                                'details': f'Pod {pod_name} in namespace {namespace} is running as root'
                            })
                        
                        # Check for privileged containers
                        if security_context.get('privileged') == True:
                            pod_issues.append({
                                'issue': 'Privileged container',
                                'severity': 'CRITICAL',
                                'details': f'Pod {pod_name} in namespace {namespace} has privileged containers'
                            })
                        
                        # Check container security contexts
                        for container in containers:
                            container_name = container['name']
                            container_security = container.get('securityContext', {})
                            
                            # Check for privileged containers
                            if container_security.get('privileged') == True:
                                pod_issues.append({
                                    'issue': 'Privileged container',
                                    'severity': 'CRITICAL',
                                    'details': f'Container {container_name} in pod {pod_name} is privileged'
                                })
                            
                            # Check for dangerous capabilities
                            capabilities = container_security.get('capabilities', {})
                            dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'DAC_OVERRIDE', 'FOWNER']
                            add_caps = capabilities.get('add', [])
                            
                            for cap in add_caps:
                                if cap in dangerous_caps:
                                    pod_issues.append({
                                        'issue': 'Dangerous capability',
                                        'severity': 'HIGH',
                                        'details': f'Container {container_name} has dangerous capability: {cap}'
                                    })
                            
                            # Check for host network
                            if pod.get('spec', {}).get('hostNetwork') == True:
                                pod_issues.append({
                                    'issue': 'Host network access',
                                    'severity': 'HIGH',
                                    'details': f'Pod {pod_name} uses host network'
                                })
                            
                            # Check for host PID
                            if pod.get('spec', {}).get('hostPID') == True:
                                pod_issues.append({
                                    'issue': 'Host PID access',
                                    'severity': 'HIGH',
                                    'details': f'Pod {pod_name} uses host PID namespace'
                                })
                            
                            # Check for host IPC
                            if pod.get('spec', {}).get('hostIPC') == True:
                                pod_issues.append({
                                    'issue': 'Host IPC access',
                                    'severity': 'MEDIUM',
                                    'details': f'Pod {pod_name} uses host IPC namespace'
                                })
                        
                        if pod_issues:
                            pod_security_issues.extend(pod_issues)
                            
            except yaml.YAMLError as e:
                print(f"[WARNING] Could not parse pods YAML: {e}")
        
        self.results['security_checks']['pod_security'] = {
            'total_issues': len(pod_security_issues),
            'issues': pod_security_issues
        }
        
        # Add findings
        if pod_security_issues:
            critical_issues = [i for i in pod_security_issues if i['severity'] == 'CRITICAL']
            high_issues = [i for i in pod_security_issues if i['severity'] == 'HIGH']
            medium_issues = [i for i in pod_security_issues if i['severity'] == 'MEDIUM']
            
            if critical_issues:
                self.results['findings'].append({
                    'severity': 'CRITICAL',
                    'category': 'Pod Security',
                    'description': f'Found {len(critical_issues)} critical pod security issues',
                    'details': critical_issues,
                    'recommendation': 'Immediately review and fix privileged containers and dangerous capabilities'
                })
            
            if high_issues:
                self.results['findings'].append({
                    'severity': 'HIGH',
                    'category': 'Pod Security',
                    'description': f'Found {len(high_issues)} high-severity pod security issues',
                    'details': high_issues,
                    'recommendation': 'Review and fix pod security contexts'
                })
            
            if medium_issues:
                self.results['findings'].append({
                    'severity': 'MEDIUM',
                    'category': 'Pod Security',
                    'description': f'Found {len(medium_issues)} medium-severity pod security issues',
                    'details': medium_issues,
                    'recommendation': 'Review pod security configurations'
                })
    
    def check_rbac_permissions(self):
        """Check RBAC permissions for over-privileged access"""
        print("[INFO] Checking RBAC permissions...")
        
        rbac_issues = []
        
        # Get all roles and cluster roles
        roles_result = self.run_kubectl("get roles --all-namespaces -o yaml")
        cluster_roles_result = self.run_kubectl("get clusterroles -o yaml")
        
        # Check for dangerous permissions in roles
        dangerous_verbs = ['*', 'create', 'delete', 'patch', 'update', 'escalate', 'impersonate']
        dangerous_resources = ['*', 'secrets', 'pods/exec', 'pods/portforward', 'nodes', 'persistentvolumes']
        
        def check_role_permissions(role_data, role_type):
            issues = []
            if 'items' in role_data:
                for role in role_data['items']:
                    role_name = role['metadata']['name']
                    namespace = role['metadata'].get('namespace', 'cluster-wide')
                    
                    rules = role.get('rules', [])
                    for rule in rules:
                        verbs = rule.get('verbs', [])
                        resources = rule.get('resources', [])
                        
                        # Check for wildcard permissions
                        if '*' in verbs and '*' in resources:
                            issues.append({
                                'role': role_name,
                                'namespace': namespace,
                                'type': role_type,
                                'issue': 'Wildcard permissions (*)',
                                'severity': 'CRITICAL',
                                'details': f'Role {role_name} has wildcard permissions'
                            })
                        
                        # Check for dangerous verb combinations
                        dangerous_verb_combos = [
                            ['*', 'secrets'],
                            ['create', 'delete', 'pods'],
                            ['escalate', '*'],
                            ['impersonate', '*']
                        ]
                        
                        for combo in dangerous_verb_combos:
                            if combo[0] in verbs and any(res in resources for res in combo[1:]):
                                issues.append({
                                    'role': role_name,
                                    'namespace': namespace,
                                    'type': role_type,
                                    'issue': f'Dangerous permission combination: {combo}',
                                    'severity': 'HIGH',
                                    'details': f'Role {role_name} has dangerous permission combination'
                                })
            
            return issues
        
        # Check regular roles
        if roles_result['success']:
            try:
                roles_data = yaml.safe_load(roles_result['stdout'])
                rbac_issues.extend(check_role_permissions(roles_data, 'Role'))
            except yaml.YAMLError:
                pass
        
        # Check cluster roles
        if cluster_roles_result['success']:
            try:
                cluster_roles_data = yaml.safe_load(cluster_roles_result['stdout'])
                rbac_issues.extend(check_role_permissions(cluster_roles_data, 'ClusterRole'))
            except yaml.YAMLError:
                pass
        
        # Check for cluster-admin bindings
        cluster_admin_result = self.run_kubectl("get clusterrolebindings -o yaml")
        if cluster_admin_result['success']:
            try:
                bindings_data = yaml.safe_load(cluster_admin_result['stdout'])
                if 'items' in bindings_data:
                    for binding in bindings_data['items']:
                        binding_name = binding['metadata']['name']
                        role_ref = binding.get('roleRef', {})
                        
                        if role_ref.get('name') == 'cluster-admin':
                            subjects = binding.get('subjects', [])
                            for subject in subjects:
                                rbac_issues.append({
                                    'role': 'cluster-admin',
                                    'namespace': 'cluster-wide',
                                    'type': 'ClusterRoleBinding',
                                    'issue': 'Cluster admin access',
                                    'severity': 'HIGH',
                                    'details': f'Subject {subject.get("name", "unknown")} has cluster-admin access via {binding_name}'
                                })
            except yaml.YAMLError:
                pass
        
        self.results['security_checks']['rbac'] = {
            'total_issues': len(rbac_issues),
            'issues': rbac_issues
        }
        
        if rbac_issues:
            critical_issues = [i for i in rbac_issues if i['severity'] == 'CRITICAL']
            high_issues = [i for i in rbac_issues if i['severity'] == 'HIGH']
            
            if critical_issues:
                self.results['findings'].append({
                    'severity': 'CRITICAL',
                    'category': 'RBAC',
                    'description': f'Found {len(critical_issues)} critical RBAC issues',
                    'details': critical_issues,
                    'recommendation': 'Immediately review and restrict wildcard permissions'
                })
            
            if high_issues:
                self.results['findings'].append({
                    'severity': 'HIGH',
                    'category': 'RBAC',
                    'description': f'Found {len(high_issues)} high-severity RBAC issues',
                    'details': high_issues,
                    'recommendation': 'Review and restrict over-privileged RBAC permissions'
                })
    
    def check_network_policies(self):
        """Check network security policies"""
        print("[INFO] Checking network policies...")
        
        # Get network policies
        netpol_result = self.run_kubectl("get networkpolicies --all-namespaces -o yaml")
        network_issues = []
        
        if netpol_result['success']:
            try:
                netpol_data = yaml.safe_load(netpol_result['stdout'])
                if 'items' in netpol_data:
                    total_policies = len(netpol_data['items'])
                    
                    # Check for missing network policies
                    namespaces_with_policies = set()
                    for policy in netpol_data['items']:
                        namespaces_with_policies.add(policy['metadata']['namespace'])
                    
                    all_namespaces = set(self.results['cluster_info'].get('namespaces', []))
                    namespaces_without_policies = all_namespaces - namespaces_with_policies
                    
                    # Remove system namespaces
                    system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease'}
                    namespaces_without_policies = namespaces_without_policies - system_namespaces
                    
                    if namespaces_without_policies:
                        network_issues.append({
                            'issue': 'Missing network policies',
                            'severity': 'MEDIUM',
                            'details': f'Namespaces without network policies: {list(namespaces_without_policies)}',
                            'recommendation': 'Implement network policies for namespace isolation'
                        })
                    
                    # Check for overly permissive policies
                    for policy in netpol_data['items']:
                        policy_name = policy['metadata']['name']
                        namespace = policy['metadata']['namespace']
                        
                        # Check ingress rules
                        ingress_rules = policy.get('spec', {}).get('ingress', [])
                        for rule in ingress_rules:
                            if not rule.get('from'):  # Allow all ingress
                                network_issues.append({
                                    'issue': 'Overly permissive ingress',
                                    'severity': 'MEDIUM',
                                    'details': f'NetworkPolicy {policy_name} in namespace {namespace} allows all ingress traffic',
                                    'recommendation': 'Restrict ingress rules to specific sources'
                                })
                        
                        # Check egress rules
                        egress_rules = policy.get('spec', {}).get('egress', [])
                        for rule in egress_rules:
                            if not rule.get('to'):  # Allow all egress
                                network_issues.append({
                                    'issue': 'Overly permissive egress',
                                    'severity': 'LOW',
                                    'details': f'NetworkPolicy {policy_name} in namespace {namespace} allows all egress traffic',
                                    'recommendation': 'Consider restricting egress rules'
                                })
                
            except yaml.YAMLError:
                pass
        
        self.results['security_checks']['network_policies'] = {
            'total_issues': len(network_issues),
            'issues': network_issues
        }
        
        if network_issues:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Network Security',
                'description': f'Found {len(network_issues)} network policy issues',
                'details': network_issues,
                'recommendation': 'Review and implement proper network policies'
            })
    
    def check_secrets_exposure(self):
        """Check for exposed secrets and credentials"""
        print("[INFO] Checking for exposed secrets...")
        
        secrets_issues = []
        
        # Get all secrets
        secrets_result = self.run_kubectl("get secrets --all-namespaces -o yaml")
        if secrets_result['success']:
            try:
                secrets_data = yaml.safe_load(secrets_result['stdout'])
                if 'items' in secrets_data:
                    for secret in secrets_data['items']:
                        secret_name = secret['metadata']['name']
                        namespace = secret['metadata']['namespace']
                        
                        # Check for default service account tokens
                        if secret_name.startswith('default-token-'):
                            secrets_issues.append({
                                'issue': 'Default service account token',
                                'severity': 'LOW',
                                'details': f'Secret {secret_name} in namespace {namespace} is a default service account token',
                                'recommendation': 'Use dedicated service accounts instead of default'
                            })
                        
                        # Check for secrets with suspicious names
                        suspicious_names = ['password', 'secret', 'key', 'token', 'credential']
                        if any(suspicious in secret_name.lower() for suspicious in suspicious_names):
                            secrets_issues.append({
                                'issue': 'Potentially sensitive secret name',
                                'severity': 'LOW',
                                'details': f'Secret {secret_name} in namespace {namespace} has a potentially sensitive name',
                                'recommendation': 'Review secret naming conventions'
                            })
                
            except yaml.YAMLError:
                pass
        
        # Check for secrets mounted in pods
        pods_result = self.run_kubectl("get pods --all-namespaces -o yaml")
        if pods_result['success']:
            try:
                pods_data = yaml.safe_load(pods_result['stdout'])
                if 'items' in pods_data:
                    for pod in pods_data['items']:
                        pod_name = pod['metadata']['name']
                        namespace = pod['metadata']['namespace']
                        
                        # Check volume mounts for secrets
                        volumes = pod.get('spec', {}).get('volumes', [])
                        for volume in volumes:
                            if 'secret' in volume:
                                secret_name = volume['secret'].get('secretName', 'unknown')
                                secrets_issues.append({
                                    'issue': 'Secret mounted in pod',
                                    'severity': 'LOW',
                                    'details': f'Secret {secret_name} is mounted in pod {pod_name} in namespace {namespace}',
                                    'recommendation': 'Review secret access and ensure proper RBAC'
                                })
                
            except yaml.YAMLError:
                pass
        
        self.results['security_checks']['secrets'] = {
            'total_issues': len(secrets_issues),
            'issues': secrets_issues
        }
        
        if secrets_issues:
            self.results['findings'].append({
                'severity': 'LOW',
                'category': 'Secrets Management',
                'description': f'Found {len(secrets_issues)} secret-related issues',
                'details': secrets_issues,
                'recommendation': 'Review secret management and access controls'
            })
    
    def check_admission_controllers(self):
        """Check admission controller configuration"""
        print("[INFO] Checking admission controllers...")
        
        admission_issues = []
        
        # Get API server configuration
        api_server_result = self.run_kubectl("get pods -n kube-system -l component=kube-apiserver -o yaml")
        if api_server_result['success']:
            try:
                api_server_data = yaml.safe_load(api_server_result['stdout'])
                if 'items' in api_server_data:
                    for pod in api_server_data['items']:
                        containers = pod.get('spec', {}).get('containers', [])
                        for container in containers:
                            args = container.get('args', [])
                            
                            # Check for important admission controllers
                            important_controllers = [
                                'PodSecurityPolicy',
                                'NodeRestriction',
                                'ServiceAccount',
                                'ResourceQuota',
                                'LimitRanger'
                            ]
                            
                            enabled_controllers = []
                            for arg in args:
                                if arg.startswith('--enable-admission-plugins='):
                                    enabled_controllers = arg.split('=')[1].split(',')
                                elif arg.startswith('--admission-control='):
                                    enabled_controllers = arg.split('=')[1].split(',')
                            
                            missing_controllers = []
                            for controller in important_controllers:
                                if controller not in enabled_controllers:
                                    missing_controllers.append(controller)
                            
                            if missing_controllers:
                                admission_issues.append({
                                    'issue': 'Missing admission controllers',
                                    'severity': 'MEDIUM',
                                    'details': f'Missing admission controllers: {missing_controllers}',
                                    'recommendation': 'Enable recommended admission controllers for security'
                                })
                
            except yaml.YAMLError:
                pass
        
        self.results['security_checks']['admission_controllers'] = {
            'total_issues': len(admission_issues),
            'issues': admission_issues
        }
        
        if admission_issues:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Admission Controllers',
                'description': f'Found {len(admission_issues)} admission controller issues',
                'details': admission_issues,
                'recommendation': 'Enable recommended admission controllers'
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
    
    def run_security_scan(self):
        """Run complete security scan"""
        print("Starting Kubernetes Security Scan...")
        print("=" * 50)
        
        self.get_cluster_info()
        self.check_pod_security()
        self.check_rbac_permissions()
        self.check_network_policies()
        self.check_secrets_exposure()
        self.check_admission_controllers()
        self.generate_summary()
        
        print("=" * 50)
        print("Security Scan Complete!")
        print(f"Total Findings: {self.results['summary']['total_findings']}")
        print(f"Security Score: {self.results['summary']['security_score']}/100")
        
        return self.results

def main():
    """Main function"""
    scanner = KubernetesSecurityScanner()
    results = scanner.run_security_scan()
    
    # Output results in JSON format
    print("\n" + "=" * 50)
    print("SECURITY SCAN RESULTS (JSON):")
    print("=" * 50)
    print(json.dumps(results, indent=2))
    
    # Also save to file if possible
    try:
        output_file = f"/tmp/k8s_security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Could not save to file: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
