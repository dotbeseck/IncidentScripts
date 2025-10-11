#!/usr/bin/env python3
"""
Kubernetes RBAC Analyzer for Incident Response
Deep analysis of RBAC permissions and privilege escalation paths
"""

import os
import sys
import json
import subprocess
import yaml
import re
from datetime import datetime
from collections import defaultdict, deque

class KubernetesRBACAnalyzer:
    def __init__(self):
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'cluster_info': {},
            'rbac_analysis': {},
            'privilege_escalation': {},
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
    
    def analyze_roles(self):
        """Analyze all roles and cluster roles"""
        print("[INFO] Analyzing roles and cluster roles...")
        
        roles_analysis = {
            'roles': [],
            'cluster_roles': [],
            'dangerous_permissions': [],
            'wildcard_permissions': []
        }
        
        # Get all roles
        roles_result = self.run_kubectl("get roles --all-namespaces -o yaml")
        if roles_result['success']:
            try:
                roles_data = yaml.safe_load(roles_result['stdout'])
                if 'items' in roles_data:
                    for role in roles_data['items']:
                        role_analysis = self._analyze_single_role(role, 'Role')
                        roles_analysis['roles'].append(role_analysis)
                        
                        # Check for dangerous permissions
                        if role_analysis['dangerous_permissions']:
                            roles_analysis['dangerous_permissions'].extend(role_analysis['dangerous_permissions'])
                        
                        if role_analysis['wildcard_permissions']:
                            roles_analysis['wildcard_permissions'].extend(role_analysis['wildcard_permissions'])
            except yaml.YAMLError:
                pass
        
        # Get all cluster roles
        cluster_roles_result = self.run_kubectl("get clusterroles -o yaml")
        if cluster_roles_result['success']:
            try:
                cluster_roles_data = yaml.safe_load(cluster_roles_result['stdout'])
                if 'items' in cluster_roles_data:
                    for role in cluster_roles_data['items']:
                        role_analysis = self._analyze_single_role(role, 'ClusterRole')
                        roles_analysis['cluster_roles'].append(role_analysis)
                        
                        # Check for dangerous permissions
                        if role_analysis['dangerous_permissions']:
                            roles_analysis['dangerous_permissions'].extend(role_analysis['dangerous_permissions'])
                        
                        if role_analysis['wildcard_permissions']:
                            roles_analysis['wildcard_permissions'].extend(role_analysis['wildcard_permissions'])
            except yaml.YAMLError:
                pass
        
        self.results['rbac_analysis']['roles'] = roles_analysis
        
        # Add findings for dangerous permissions
        if roles_analysis['dangerous_permissions']:
            self.results['findings'].append({
                'severity': 'HIGH',
                'category': 'RBAC Permissions',
                'description': f'Found {len(roles_analysis["dangerous_permissions"])} dangerous permissions',
                'details': roles_analysis['dangerous_permissions'],
                'recommendation': 'Review and restrict dangerous permissions'
            })
        
        if roles_analysis['wildcard_permissions']:
            self.results['findings'].append({
                'severity': 'CRITICAL',
                'category': 'RBAC Permissions',
                'description': f'Found {len(roles_analysis["wildcard_permissions"])} wildcard permissions',
                'details': roles_analysis['wildcard_permissions'],
                'recommendation': 'Immediately restrict wildcard permissions'
            })
    
    def _analyze_single_role(self, role, role_type):
        """Analyze a single role for dangerous permissions"""
        role_name = role['metadata']['name']
        namespace = role['metadata'].get('namespace', 'cluster-wide')
        
        analysis = {
            'name': role_name,
            'namespace': namespace,
            'type': role_type,
            'rules': [],
            'dangerous_permissions': [],
            'wildcard_permissions': [],
            'risk_score': 0
        }
        
        rules = role.get('rules', [])
        for rule in rules:
            rule_analysis = {
                'verbs': rule.get('verbs', []),
                'resources': rule.get('resources', []),
                'apiGroups': rule.get('apiGroups', []),
                'nonResourceURLs': rule.get('nonResourceURLs', []),
                'dangerous': False,
                'wildcard': False
            }
            
            # Check for wildcard permissions
            if '*' in rule_analysis['verbs'] or '*' in rule_analysis['resources']:
                rule_analysis['wildcard'] = True
                analysis['wildcard_permissions'].append({
                    'role': role_name,
                    'namespace': namespace,
                    'rule': rule_analysis,
                    'severity': 'CRITICAL'
                })
                analysis['risk_score'] += 50
            
            # Check for dangerous permission combinations
            dangerous_combinations = [
                {
                    'verbs': ['*'],
                    'resources': ['*'],
                    'severity': 'CRITICAL',
                    'description': 'Full cluster access'
                },
                {
                    'verbs': ['create', 'delete', 'patch', 'update'],
                    'resources': ['secrets'],
                    'severity': 'HIGH',
                    'description': 'Secret manipulation'
                },
                {
                    'verbs': ['create', 'delete', 'patch', 'update'],
                    'resources': ['pods'],
                    'severity': 'HIGH',
                    'description': 'Pod manipulation'
                },
                {
                    'verbs': ['escalate'],
                    'resources': ['*'],
                    'severity': 'CRITICAL',
                    'description': 'Privilege escalation'
                },
                {
                    'verbs': ['impersonate'],
                    'resources': ['*'],
                    'severity': 'CRITICAL',
                    'description': 'User impersonation'
                },
                {
                    'verbs': ['bind'],
                    'resources': ['roles', 'clusterroles'],
                    'severity': 'HIGH',
                    'description': 'Role binding'
                },
                {
                    'verbs': ['create', 'delete', 'patch', 'update'],
                    'resources': ['nodes'],
                    'severity': 'HIGH',
                    'description': 'Node manipulation'
                },
                {
                    'verbs': ['create', 'delete', 'patch', 'update'],
                    'resources': ['persistentvolumes'],
                    'severity': 'MEDIUM',
                    'description': 'Storage manipulation'
                }
            ]
            
            for combo in dangerous_combinations:
                if (any(verb in rule_analysis['verbs'] for verb in combo['verbs']) and
                    any(res in rule_analysis['resources'] for res in combo['resources'])):
                    rule_analysis['dangerous'] = True
                    analysis['dangerous_permissions'].append({
                        'role': role_name,
                        'namespace': namespace,
                        'rule': rule_analysis,
                        'combination': combo,
                        'severity': combo['severity']
                    })
                    analysis['risk_score'] += 25 if combo['severity'] == 'HIGH' else 15
            
            analysis['rules'].append(rule_analysis)
        
        return analysis
    
    def analyze_role_bindings(self):
        """Analyze role bindings and cluster role bindings"""
        print("[INFO] Analyzing role bindings...")
        
        bindings_analysis = {
            'role_bindings': [],
            'cluster_role_bindings': [],
            'cluster_admin_bindings': [],
            'over_privileged_bindings': []
        }
        
        # Get role bindings
        rb_result = self.run_kubectl("get rolebindings --all-namespaces -o yaml")
        if rb_result['success']:
            try:
                rb_data = yaml.safe_load(rb_result['stdout'])
                if 'items' in rb_data:
                    for binding in rb_data['items']:
                        binding_analysis = self._analyze_single_binding(binding, 'RoleBinding')
                        bindings_analysis['role_bindings'].append(binding_analysis)
                        
                        if binding_analysis['over_privileged']:
                            bindings_analysis['over_privileged_bindings'].append(binding_analysis)
            except yaml.YAMLError:
                pass
        
        # Get cluster role bindings
        crb_result = self.run_kubectl("get clusterrolebindings -o yaml")
        if crb_result['success']:
            try:
                crb_data = yaml.safe_load(crb_result['stdout'])
                if 'items' in crb_data:
                    for binding in crb_data['items']:
                        binding_analysis = self._analyze_single_binding(binding, 'ClusterRoleBinding')
                        bindings_analysis['cluster_role_bindings'].append(binding_analysis)
                        
                        if binding_analysis['over_privileged']:
                            bindings_analysis['over_privileged_bindings'].append(binding_analysis)
                        
                        # Check for cluster-admin bindings
                        if binding_analysis['role_name'] == 'cluster-admin':
                            bindings_analysis['cluster_admin_bindings'].append(binding_analysis)
            except yaml.YAMLError:
                pass
        
        self.results['rbac_analysis']['bindings'] = bindings_analysis
        
        # Add findings
        if bindings_analysis['cluster_admin_bindings']:
            self.results['findings'].append({
                'severity': 'HIGH',
                'category': 'RBAC Bindings',
                'description': f'Found {len(bindings_analysis["cluster_admin_bindings"])} cluster-admin bindings',
                'details': bindings_analysis['cluster_admin_bindings'],
                'recommendation': 'Review cluster-admin bindings and restrict access'
            })
        
        if bindings_analysis['over_privileged_bindings']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'RBAC Bindings',
                'description': f'Found {len(bindings_analysis["over_privileged_bindings"])} over-privileged bindings',
                'details': bindings_analysis['over_privileged_bindings'],
                'recommendation': 'Review and restrict over-privileged bindings'
            })
    
    def _analyze_single_binding(self, binding, binding_type):
        """Analyze a single role binding"""
        binding_name = binding['metadata']['name']
        namespace = binding['metadata'].get('namespace', 'cluster-wide')
        role_ref = binding.get('roleRef', {})
        subjects = binding.get('subjects', [])
        
        analysis = {
            'name': binding_name,
            'namespace': namespace,
            'type': binding_type,
            'role_name': role_ref.get('name', 'unknown'),
            'role_kind': role_ref.get('kind', 'unknown'),
            'subjects': subjects,
            'over_privileged': False,
            'risk_score': 0
        }
        
        # Check for over-privileged bindings
        if analysis['role_name'] in ['cluster-admin', 'admin', 'edit']:
            analysis['over_privileged'] = True
            analysis['risk_score'] += 30
        
        # Check for service accounts with high privileges
        for subject in subjects:
            if subject.get('kind') == 'ServiceAccount':
                if analysis['role_name'] in ['cluster-admin', 'admin']:
                    analysis['risk_score'] += 20
        
        return analysis
    
    def find_privilege_escalation_paths(self):
        """Find potential privilege escalation paths"""
        print("[INFO] Finding privilege escalation paths...")
        
        escalation_paths = []
        
        # Get all service accounts
        sa_result = self.run_kubectl("get serviceaccounts --all-namespaces -o yaml")
        if sa_result['success']:
            try:
                sa_data = yaml.safe_load(sa_result['stdout'])
                if 'items' in sa_data:
                    for sa in sa_data['items']:
                        sa_name = sa['metadata']['name']
                        namespace = sa['metadata']['namespace']
                        
                        # Check if service account has dangerous permissions
                        escalation_path = self._check_service_account_escalation(sa_name, namespace)
                        if escalation_path:
                            escalation_paths.append(escalation_path)
            except yaml.YAMLError:
                pass
        
        # Check for pods with service accounts that have high privileges
        pods_result = self.run_kubectl("get pods --all-namespaces -o yaml")
        if pods_result['success']:
            try:
                pods_data = yaml.safe_load(pods_result['stdout'])
                if 'items' in pods_data:
                    for pod in pods_data['items']:
                        pod_name = pod['metadata']['name']
                        namespace = pod['metadata']['namespace']
                        service_account = pod.get('spec', {}).get('serviceAccountName', 'default')
                        
                        # Check if pod can escalate privileges
                        escalation_path = self._check_pod_escalation(pod_name, namespace, service_account)
                        if escalation_path:
                            escalation_paths.append(escalation_path)
            except yaml.YAMLError:
                pass
        
        self.results['privilege_escalation']['paths'] = escalation_paths
        
        if escalation_paths:
            self.results['findings'].append({
                'severity': 'CRITICAL',
                'category': 'Privilege Escalation',
                'description': f'Found {len(escalation_paths)} potential privilege escalation paths',
                'details': escalation_paths,
                'recommendation': 'Immediately review and restrict privilege escalation paths'
            })
    
    def _check_service_account_escalation(self, sa_name, namespace):
        """Check if a service account can escalate privileges"""
        # This is a simplified check - in a real implementation, you'd need to
        # trace through all the role bindings and permissions
        
        # Check if service account has cluster-admin
        crb_result = self.run_kubectl(f"get clusterrolebindings -o yaml | grep -A 10 -B 10 '{sa_name}'")
        if crb_result['success'] and 'cluster-admin' in crb_result['stdout']:
            return {
                'type': 'ServiceAccount',
                'name': sa_name,
                'namespace': namespace,
                'escalation_path': 'ServiceAccount has cluster-admin access',
                'severity': 'CRITICAL'
            }
        
        return None
    
    def _check_pod_escalation(self, pod_name, namespace, service_account):
        """Check if a pod can escalate privileges"""
        # Check if pod has dangerous security context
        pod_result = self.run_kubectl(f"get pod {pod_name} -n {namespace} -o yaml")
        if pod_result['success']:
            try:
                pod_data = yaml.safe_load(pod_result['stdout'])
                security_context = pod_data.get('spec', {}).get('securityContext', {})
                
                # Check for privileged containers
                if security_context.get('privileged') == True:
                    return {
                        'type': 'Pod',
                        'name': pod_name,
                        'namespace': namespace,
                        'service_account': service_account,
                        'escalation_path': 'Pod has privileged security context',
                        'severity': 'HIGH'
                    }
                
                # Check for containers with dangerous capabilities
                containers = pod_data.get('spec', {}).get('containers', [])
                for container in containers:
                    container_security = container.get('securityContext', {})
                    capabilities = container_security.get('capabilities', {})
                    add_caps = capabilities.get('add', [])
                    
                    dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'DAC_OVERRIDE']
                    if any(cap in add_caps for cap in dangerous_caps):
                        return {
                            'type': 'Pod',
                            'name': pod_name,
                            'namespace': namespace,
                            'service_account': service_account,
                            'escalation_path': f'Container has dangerous capabilities: {add_caps}',
                            'severity': 'MEDIUM'
                        }
            except yaml.YAMLError:
                pass
        
        return None
    
    def analyze_service_accounts(self):
        """Analyze service account usage and permissions"""
        print("[INFO] Analyzing service accounts...")
        
        sa_analysis = {
            'service_accounts': [],
            'default_sa_usage': [],
            'over_privileged_sas': []
        }
        
        # Get all service accounts
        sa_result = self.run_kubectl("get serviceaccounts --all-namespaces -o yaml")
        if sa_result['success']:
            try:
                sa_data = yaml.safe_load(sa_result['stdout'])
                if 'items' in sa_data:
                    for sa in sa_data['items']:
                        sa_name = sa['metadata']['name']
                        namespace = sa['metadata']['namespace']
                        
                        sa_info = {
                            'name': sa_name,
                            'namespace': namespace,
                            'secrets': sa.get('secrets', []),
                            'image_pull_secrets': sa.get('imagePullSecrets', [])
                        }
                        
                        sa_analysis['service_accounts'].append(sa_info)
                        
                        # Check for default service account usage
                        if sa_name == 'default':
                            sa_analysis['default_sa_usage'].append(sa_info)
                        
                        # Check for over-privileged service accounts
                        if self._is_over_privileged_sa(sa_name, namespace):
                            sa_analysis['over_privileged_sas'].append(sa_info)
            except yaml.YAMLError:
                pass
        
        self.results['rbac_analysis']['service_accounts'] = sa_analysis
        
        # Add findings
        if sa_analysis['default_sa_usage']:
            self.results['findings'].append({
                'severity': 'LOW',
                'category': 'Service Accounts',
                'description': f'Found {len(sa_analysis["default_sa_usage"])} namespaces using default service account',
                'details': sa_analysis['default_sa_usage'],
                'recommendation': 'Use dedicated service accounts instead of default'
            })
        
        if sa_analysis['over_privileged_sas']:
            self.results['findings'].append({
                'severity': 'MEDIUM',
                'category': 'Service Accounts',
                'description': f'Found {len(sa_analysis["over_privileged_sas"])} over-privileged service accounts',
                'details': sa_analysis['over_privileged_sas'],
                'recommendation': 'Review and restrict service account permissions'
            })
    
    def _is_over_privileged_sa(self, sa_name, namespace):
        """Check if a service account is over-privileged"""
        # Check role bindings for this service account
        rb_result = self.run_kubectl(f"get rolebindings --all-namespaces -o yaml | grep -A 5 -B 5 '{sa_name}'")
        if rb_result['success']:
            if 'admin' in rb_result['stdout'] or 'edit' in rb_result['stdout']:
                return True
        
        # Check cluster role bindings
        crb_result = self.run_kubectl(f"get clusterrolebindings -o yaml | grep -A 5 -B 5 '{sa_name}'")
        if crb_result['success']:
            if 'cluster-admin' in crb_result['stdout'] or 'admin' in crb_result['stdout']:
                return True
        
        return False
    
    def generate_summary(self):
        """Generate RBAC analysis summary"""
        total_findings = len(self.results['findings'])
        critical_findings = len([f for f in self.results['findings'] if f['severity'] == 'CRITICAL'])
        high_findings = len([f for f in self.results['findings'] if f['severity'] == 'HIGH'])
        medium_findings = len([f for f in self.results['findings'] if f['severity'] == 'MEDIUM'])
        low_findings = len([f for f in self.results['findings'] if f['severity'] == 'LOW'])
        
        # Calculate risk score
        risk_score = 0
        for finding in self.results['findings']:
            if finding['severity'] == 'CRITICAL':
                risk_score += 25
            elif finding['severity'] == 'HIGH':
                risk_score += 15
            elif finding['severity'] == 'MEDIUM':
                risk_score += 10
            elif finding['severity'] == 'LOW':
                risk_score += 5
        
        self.results['summary'] = {
            'total_findings': total_findings,
            'critical': critical_findings,
            'high': high_findings,
            'medium': medium_findings,
            'low': low_findings,
            'risk_score': min(100, risk_score),
            'security_score': max(0, 100 - risk_score)
        }
        
        # Generate recommendations
        if critical_findings > 0:
            self.results['recommendations'].append("CRITICAL: Address critical RBAC findings immediately")
        if high_findings > 0:
            self.results['recommendations'].append("HIGH: Address high-priority RBAC findings within 24 hours")
        if medium_findings > 0:
            self.results['recommendations'].append("MEDIUM: Address medium-priority findings within 1 week")
        if low_findings > 0:
            self.results['recommendations'].append("LOW: Review low-priority findings during next maintenance window")
        
        if total_findings == 0:
            self.results['recommendations'].append("No RBAC issues found - maintain current security posture")
    
    def run_analysis(self):
        """Run complete RBAC analysis"""
        print("Starting Kubernetes RBAC Analysis...")
        print("=" * 50)
        
        self.get_cluster_info()
        self.analyze_roles()
        self.analyze_role_bindings()
        self.find_privilege_escalation_paths()
        self.analyze_service_accounts()
        self.generate_summary()
        
        print("=" * 50)
        print("RBAC Analysis Complete!")
        print(f"Total Findings: {self.results['summary']['total_findings']}")
        print(f"Risk Score: {self.results['summary']['risk_score']}/100")
        print(f"Security Score: {self.results['summary']['security_score']}/100")
        
        return self.results

def main():
    """Main function"""
    analyzer = KubernetesRBACAnalyzer()
    results = analyzer.run_analysis()
    
    # Output results in JSON format
    print("\n" + "=" * 50)
    print("RBAC ANALYSIS RESULTS (JSON):")
    print("=" * 50)
    print(json.dumps(results, indent=2))
    
    # Also save to file if possible
    try:
        output_file = f"/tmp/k8s_rbac_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_file}")
    except Exception as e:
        print(f"Could not save to file: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
