# Kubernetes Security Scripts Guide

## Overview

This collection of Kubernetes security scripts provides comprehensive analysis of your cluster's security posture, focusing on pod security, RBAC permissions, and network policies.

## Scripts Available

### 1. `security-scan.py`
**Purpose**: Comprehensive Kubernetes security assessment
**Runtime**: ~3-5 minutes
**Output**: JSON format with security findings and recommendations

**Features:**
- Pod security context analysis
- RBAC permission checking
- Network policy auditing
- Secret exposure detection
- Admission controller verification

### 2. `rbac-analyzer.py`
**Purpose**: Deep RBAC analysis and privilege escalation detection
**Runtime**: ~2-3 minutes
**Output**: JSON format with RBAC analysis and risk assessment

**Features:**
- Role and ClusterRole analysis
- Role binding analysis
- Privilege escalation path detection
- Service account analysis
- Risk scoring

### 3. `network-policy-audit.py`
**Purpose**: Network security policy analysis
**Runtime**: ~2-3 minutes
**Output**: JSON format with network security assessment

**Features:**
- Network policy coverage analysis
- Service exposure analysis
- Ingress configuration review
- Network security scoring

## Prerequisites

### Required Tools
- `kubectl` configured with cluster access
- Python 3.6+ with `yaml` module
- Appropriate RBAC permissions to read cluster resources

### Required Permissions
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-scanner
rules:
- apiGroups: [""]
  resources: ["pods", "services", "secrets", "nodes", "namespaces"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["serviceaccounts"]
  verbs: ["get", "list"]
```

## Usage Instructions

### Basic Execution

#### Security Scan
```bash
# Run comprehensive security scan
python3 security-scan.py

# Run with specific namespace
KUBECTL_NAMESPACE=production python3 security-scan.py
```

#### RBAC Analysis
```bash
# Run RBAC analysis
python3 rbac-analyzer.py

# Run with verbose output
python3 rbac-analyzer.py | jq '.findings[] | select(.severity == "CRITICAL")'
```

#### Network Policy Audit
```bash
# Run network policy audit
python3 network-policy-audit.py

# Run and save results
python3 network-policy-audit.py > network_audit_results.json
```

### Advanced Usage

#### Batch Execution
```bash
#!/bin/bash
# Run all security scripts
echo "Running Kubernetes Security Assessment..."

echo "1. Running Security Scan..."
python3 security-scan.py > security_scan_$(date +%Y%m%d_%H%M%S).json

echo "2. Running RBAC Analysis..."
python3 rbac-analyzer.py > rbac_analysis_$(date +%Y%m%d_%H%M%S).json

echo "3. Running Network Policy Audit..."
python3 network-policy-audit.py > network_audit_$(date +%Y%m%d_%H%M%S).json

echo "Security assessment complete!"
```

#### Integration with CI/CD
```yaml
# .github/workflows/k8s-security.yml
name: Kubernetes Security Scan
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup kubectl
      uses: azure/setup-kubectl@v1
    - name: Run Security Scan
      run: |
        python3 kubernetes/security-scan.py > security_scan.json
        python3 kubernetes/rbac-analyzer.py > rbac_analysis.json
        python3 kubernetes/network-policy-audit.py > network_audit.json
    - name: Upload Results
      uses: actions/upload-artifact@v2
      with:
        name: security-scan-results
        path: |
          security_scan.json
          rbac_analysis.json
          network_audit.json
```

## Expected Output

### Security Scan Output
```json
{
  "timestamp": "2024-12-10T15:30:00",
  "cluster_info": {
    "version": {
      "serverVersion": {
        "major": "1",
        "minor": "28",
        "gitVersion": "v1.28.2"
      }
    },
    "current_context": "production-cluster",
    "namespaces": ["default", "kube-system", "production"]
  },
  "security_checks": {
    "pod_security": {
      "total_issues": 3,
      "issues": [
        {
          "issue": "Privileged container",
          "severity": "CRITICAL",
          "details": "Pod nginx-deployment in namespace default has privileged containers"
        }
      ]
    },
    "rbac": {
      "total_issues": 1,
      "issues": [
        {
          "issue": "Wildcard permissions (*)",
          "severity": "CRITICAL",
          "details": "Role admin-role has wildcard permissions"
        }
      ]
    }
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "category": "Pod Security",
      "description": "Found 1 critical pod security issues",
      "recommendation": "Immediately review and fix privileged containers"
    }
  ],
  "summary": {
    "total_findings": 2,
    "critical": 2,
    "high": 0,
    "medium": 0,
    "low": 0,
    "security_score": 50
  }
}
```

### RBAC Analysis Output
```json
{
  "timestamp": "2024-12-10T15:30:00",
  "rbac_analysis": {
    "roles": {
      "roles": [
        {
          "name": "admin-role",
          "namespace": "default",
          "type": "Role",
          "dangerous_permissions": [
            {
              "role": "admin-role",
              "namespace": "default",
              "rule": {
                "verbs": ["*"],
                "resources": ["*"]
              },
              "severity": "CRITICAL"
            }
          ],
          "risk_score": 50
        }
      ]
    },
    "bindings": {
      "cluster_admin_bindings": [
        {
          "name": "cluster-admin-binding",
          "namespace": "cluster-wide",
          "type": "ClusterRoleBinding",
          "role_name": "cluster-admin",
          "subjects": [
            {
              "kind": "User",
              "name": "admin-user"
            }
          ]
        }
      ]
    }
  },
  "privilege_escalation": {
    "paths": [
      {
        "type": "ServiceAccount",
        "name": "default",
        "namespace": "default",
        "escalation_path": "ServiceAccount has cluster-admin access",
        "severity": "CRITICAL"
      }
    ]
  },
  "summary": {
    "total_findings": 3,
    "critical": 3,
    "high": 0,
    "medium": 0,
    "low": 0,
    "risk_score": 75,
    "security_score": 25
  }
}
```

### Network Policy Audit Output
```json
{
  "timestamp": "2024-12-10T15:30:00",
  "network_analysis": {
    "policies": {
      "policies": [
        {
          "name": "default-deny",
          "namespace": "default",
          "ingress_rules": [],
          "egress_rules": [],
          "issues": [],
          "risk_score": 0
        }
      ],
      "coverage_analysis": {
        "total_user_namespaces": 3,
        "namespaces_with_policies": 1,
        "namespaces_without_policies": 2,
        "coverage_percentage": 33.33
      }
    },
    "services": {
      "exposed_services": [
        {
          "name": "nginx-service",
          "namespace": "default",
          "type": "NodePort",
          "exposed": true,
          "issues": [
            {
              "issue": "Service exposed externally",
              "severity": "MEDIUM",
              "details": "Service nginx-service is exposed via NodePort"
            }
          ]
        }
      ]
    },
    "security_posture": {
      "network_policy_coverage": 33.33,
      "exposed_services_count": 1,
      "ingress_count": 0,
      "security_score": 65
    }
  },
  "summary": {
    "total_findings": 2,
    "critical": 0,
    "high": 0,
    "medium": 2,
    "low": 0,
    "network_security_score": 65
  }
}
```

## Security Findings Categories

### Critical Findings
- Privileged containers
- Wildcard RBAC permissions
- Cluster-admin access
- Privilege escalation paths

### High Findings
- Dangerous capabilities
- Host network access
- Secret manipulation permissions
- Pod manipulation permissions

### Medium Findings
- Missing network policies
- Exposed services
- Over-privileged bindings
- Missing admission controllers

### Low Findings
- Default service account usage
- Missing TLS configuration
- Wildcard hosts in ingress

## Remediation Recommendations

### Immediate Actions (Critical)
1. **Remove privileged containers**
   ```bash
   kubectl patch deployment <deployment> -p '{"spec":{"template":{"spec":{"securityContext":{"privileged":false}}}}}'
   ```

2. **Restrict wildcard permissions**
   ```yaml
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata:
     name: restricted-role
   rules:
   - apiGroups: [""]
     resources: ["pods"]
     verbs: ["get", "list"]
   ```

3. **Remove cluster-admin bindings**
   ```bash
   kubectl delete clusterrolebinding <binding-name>
   ```

### Short-term Actions (High)
1. **Implement network policies**
   ```yaml
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: default-deny
   spec:
     podSelector: {}
     policyTypes:
     - Ingress
     - Egress
   ```

2. **Restrict service exposure**
   ```bash
   kubectl patch service <service> -p '{"spec":{"type":"ClusterIP"}}'
   ```

3. **Enable admission controllers**
   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: admission-controller-config
   data:
     enable-admission-plugins: "PodSecurityPolicy,NodeRestriction,ServiceAccount"
   ```

### Long-term Actions (Medium/Low)
1. **Implement Pod Security Standards**
2. **Use dedicated service accounts**
3. **Enable TLS for all ingress**
4. **Implement resource quotas**
5. **Regular security scanning**

## Integration with SIEM

### Splunk Integration
```splunk
index=security source="k8s_security_scan" sourcetype="kubernetes_security"
| spath path=findings
| mvexpand findings
| eval severity=findings.severity
| stats count by severity
```

### ELK Stack Integration
```json
{
  "mappings": {
    "properties": {
      "timestamp": {"type": "date"},
      "cluster_info": {
        "properties": {
          "current_context": {"type": "keyword"}
        }
      },
      "findings": {
        "properties": {
          "severity": {"type": "keyword"},
          "category": {"type": "keyword"},
          "description": {"type": "text"}
        }
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied**
   ```
   Error: User "system:serviceaccount:default:default" cannot list resource "pods"
   Solution: Ensure proper RBAC permissions are configured
   ```

2. **Cluster Connection Failed**
   ```
   Error: Unable to connect to the server
   Solution: Verify kubectl configuration and cluster connectivity
   ```

3. **YAML Parse Errors**
   ```
   Error: YAMLError: while parsing a block mapping
   Solution: Check cluster resource configurations for malformed YAML
   ```

4. **Timeout Errors**
   ```
   Error: Command timed out after 30 seconds
   Solution: Increase timeout or check cluster performance
   ```

## Performance Considerations

- **Security Scan**: ~3-5 minutes on typical cluster
- **RBAC Analysis**: ~2-3 minutes on typical cluster
- **Network Audit**: ~2-3 minutes on typical cluster
- **Memory Usage**: <100MB during execution
- **CPU Impact**: Minimal, uses kubectl efficiently

## Security Considerations

1. **Read-Only Operations**: Scripts only read cluster state
2. **No Data Modification**: No changes to cluster resources
3. **Local Analysis**: No data sent externally
4. **Audit Trail**: All operations logged
5. **Minimal Permissions**: Uses least privilege principle

## Customization

Scripts can be easily customized for specific requirements:

1. **Add Custom Checks**: Modify the analysis functions
2. **Change Severity Levels**: Adjust severity thresholds
3. **Add New Categories**: Extend the findings structure
4. **Modify Output Format**: Change JSON structure as needed
5. **Add Custom Rules**: Implement organization-specific security rules

## Support

For issues or questions:
1. Check kubectl configuration and permissions
2. Verify cluster connectivity
3. Review script output for error messages
4. Test in non-production environment first
5. Review Kubernetes security best practices
