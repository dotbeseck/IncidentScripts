# Kubernetes Security Scripts - Execution Guide

## Overview

This guide explains how to run the Kubernetes security scripts against different targets: entire clusters, specific namespaces, individual nodes, or specific resources. Each script can be customized for different scenarios and environments.

## Prerequisites

### 1. Environment Setup

#### Install Required Tools
```bash
# Install kubectl
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install Python dependencies
pip3 install -r requirements.txt

# Verify installation
kubectl version --client
python3 --version
```

#### Configure kubectl Access
```bash
# Option 1: Use existing kubeconfig
export KUBECONFIG=/path/to/your/kubeconfig

# Option 2: Configure for cloud provider
# AWS EKS
aws eks update-kubeconfig --region us-west-2 --name my-cluster

# Google GKE
gcloud container clusters get-credentials my-cluster --zone us-central1-a

# Azure AKS
az aks get-credentials --resource-group myResourceGroup --name myAKSCluster

# Verify access
kubectl cluster-info
kubectl get nodes
```

### 2. Required Permissions

Create a service account with necessary permissions:

```yaml
# k8s-security-scanner-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: security-scanner
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: security-scanner
rules:
# Core resources
- apiGroups: [""]
  resources: ["pods", "services", "secrets", "nodes", "namespaces", "serviceaccounts"]
  verbs: ["get", "list"]
# Apps resources
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
  verbs: ["get", "list"]
# Networking resources
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies", "ingresses"]
  verbs: ["get", "list"]
# RBAC resources
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["roles", "clusterroles", "rolebindings", "clusterrolebindings"]
  verbs: ["get", "list"]
# Extensions
- apiGroups: ["extensions"]
  resources: ["ingresses"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: security-scanner
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: security-scanner
subjects:
- kind: ServiceAccount
  name: security-scanner
  namespace: default
```

Apply the RBAC configuration:
```bash
kubectl apply -f k8s-security-scanner-rbac.yaml
```

## Execution Scenarios

### 1. Full Cluster Analysis

#### Run All Scripts Against Entire Cluster
```bash
#!/bin/bash
# full-cluster-security-scan.sh

CLUSTER_NAME=$(kubectl config current-context)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="security-reports/${CLUSTER_NAME}_${TIMESTAMP}"

mkdir -p $OUTPUT_DIR

echo " Starting full cluster security analysis..."
echo "Cluster: $CLUSTER_NAME"
echo "Output Directory: $OUTPUT_DIR"
echo "=========================================="

# 1. Comprehensive Security Scan
echo " Running comprehensive security scan..."
python3 kubernetes/security-scan.py > $OUTPUT_DIR/security_scan.json
echo " Security scan complete"

# 2. RBAC Analysis
echo " Running RBAC analysis..."
python3 kubernetes/rbac-analyzer.py > $OUTPUT_DIR/rbac_analysis.json
echo " RBAC analysis complete"

# 3. Network Policy Audit
echo " Running network policy audit..."
python3 kubernetes/network-policy-audit.py > $OUTPUT_DIR/network_audit.json
echo " Network policy audit complete"

# 4. Generate summary report
echo " Generating summary report..."
cat > $OUTPUT_DIR/summary.md << EOF
# Security Analysis Summary

**Cluster:** $CLUSTER_NAME  
**Date:** $(date)  
**Analysis Type:** Full Cluster  

## Results Overview

### Security Scan
- **File:** security_scan.json
- **Findings:** $(jq '.summary.total_findings' $OUTPUT_DIR/security_scan.json)
- **Security Score:** $(jq '.summary.security_score' $OUTPUT_DIR/security_scan.json)/100

### RBAC Analysis
- **File:** rbac_analysis.json
- **Findings:** $(jq '.summary.total_findings' $OUTPUT_DIR/rbac_analysis.json)
- **Risk Score:** $(jq '.summary.risk_score' $OUTPUT_DIR/rbac_analysis.json)/100

### Network Policy Audit
- **File:** network_audit.json
- **Findings:** $(jq '.summary.total_findings' $OUTPUT_DIR/network_audit.json)
- **Network Security Score:** $(jq '.summary.network_security_score' $OUTPUT_DIR/network_audit.json)/100

## Critical Findings
$(jq -r '.findings[] | select(.severity == "CRITICAL") | "- " + .description' $OUTPUT_DIR/security_scan.json)
$(jq -r '.findings[] | select(.severity == "CRITICAL") | "- " + .description' $OUTPUT_DIR/rbac_analysis.json)
$(jq -r '.findings[] | select(.severity == "CRITICAL") | "- " + .description' $OUTPUT_DIR/network_audit.json)

## Recommendations
1. Address all CRITICAL findings immediately
2. Review HIGH severity findings within 24 hours
3. Plan remediation for MEDIUM findings within 1 week
4. Schedule review of LOW findings during next maintenance window
EOF

echo " Full cluster security analysis complete!"
echo " Results saved to: $OUTPUT_DIR"
```

#### Execute Full Cluster Scan
```bash
chmod +x full-cluster-security-scan.sh
./full-cluster-security-scan.sh
```

### 2. Namespace-Specific Analysis

#### Single Namespace Analysis
```bash
#!/bin/bash
# namespace-security-scan.sh

NAMESPACE=${1:-"default"}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="security-reports/${NAMESPACE}_${TIMESTAMP}"

mkdir -p $OUTPUT_DIR

echo " Analyzing namespace: $NAMESPACE"
echo "Output Directory: $OUTPUT_DIR"
echo "=========================================="

# Set namespace context
export KUBECTL_NAMESPACE=$NAMESPACE

# Run security scan for specific namespace
echo " Running security scan for namespace: $NAMESPACE"
python3 kubernetes/security-scan.py > $OUTPUT_DIR/security_scan.json

# Run RBAC analysis (still cluster-wide for RBAC)
echo " Running RBAC analysis..."
python3 kubernetes/rbac-analyzer.py > $OUTPUT_DIR/rbac_analysis.json

# Run network policy audit
echo " Running network policy audit..."
python3 kubernetes/network-policy-audit.py > $OUTPUT_DIR/network_audit.json

echo " Namespace analysis complete: $OUTPUT_DIR"
```

#### Execute Namespace Scan
```bash
# Analyze specific namespace
./namespace-security-scan.sh production

# Analyze default namespace
./namespace-security-scan.sh default

# Analyze multiple namespaces
for ns in production staging development; do
    ./namespace-security-scan.sh $ns
done
```

### 3. Node-Specific Analysis

#### Analyze Specific Node
```bash
#!/bin/bash
# node-security-scan.sh

NODE_NAME=${1}
if [ -z "$NODE_NAME" ]; then
    echo "Usage: $0 <node-name>"
    echo "Available nodes:"
    kubectl get nodes --no-headers | awk '{print $1}'
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="security-reports/node_${NODE_NAME}_${TIMESTAMP}"

mkdir -p $OUTPUT_DIR

echo " Analyzing node: $NODE_NAME"
echo "Output Directory: $OUTPUT_DIR"
echo "=========================================="

# Get node information
echo " Collecting node information..."
kubectl describe node $NODE_NAME > $OUTPUT_DIR/node_description.txt
kubectl get node $NODE_NAME -o yaml > $OUTPUT_DIR/node_yaml.yaml

# Get pods running on this node
echo " Collecting pods on node..."
kubectl get pods --all-namespaces --field-selector spec.nodeName=$NODE_NAME -o yaml > $OUTPUT_DIR/node_pods.yaml

# Run security scan (filtered for this node)
echo " Running security scan for node pods..."
python3 kubernetes/security-scan.py > $OUTPUT_DIR/security_scan.json

# Filter results for this node
echo " Filtering results for node: $NODE_NAME"
jq --arg node "$NODE_NAME" '
  .security_checks.pod_security.issues = (
    .security_checks.pod_security.issues | 
    map(select(.details | contains($node)))
  )
' $OUTPUT_DIR/security_scan.json > $OUTPUT_DIR/security_scan_filtered.json

echo " Node analysis complete: $OUTPUT_DIR"
```

#### Execute Node Scan
```bash
# List available nodes
kubectl get nodes

# Analyze specific node
./node-security-scan.sh worker-node-1

# Analyze all worker nodes
kubectl get nodes --no-headers | grep -v master | awk '{print $1}' | while read node; do
    ./node-security-scan.sh $node
done
```

### 4. Resource-Specific Analysis

#### Analyze Specific Resource Types
```bash
#!/bin/bash
# resource-security-scan.sh

RESOURCE_TYPE=${1:-"pods"}
NAMESPACE=${2:-"all"}

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="security-reports/${RESOURCE_TYPE}_${NAMESPACE}_${TIMESTAMP}"

mkdir -p $OUTPUT_DIR

echo " Analyzing resource type: $RESOURCE_TYPE"
echo "Namespace: $NAMESPACE"
echo "Output Directory: $OUTPUT_DIR"
echo "=========================================="

# Get resource information
if [ "$NAMESPACE" = "all" ]; then
    echo " Collecting all $RESOURCE_TYPE..."
    kubectl get $RESOURCE_TYPE --all-namespaces -o yaml > $OUTPUT_DIR/${RESOURCE_TYPE}_all.yaml
else
    echo " Collecting $RESOURCE_TYPE in namespace: $NAMESPACE"
    kubectl get $RESOURCE_TYPE -n $NAMESPACE -o yaml > $OUTPUT_DIR/${RESOURCE_TYPE}_${NAMESPACE}.yaml
fi

# Run appropriate security scan
case $RESOURCE_TYPE in
    "pods")
        echo " Running pod security analysis..."
        python3 kubernetes/security-scan.py > $OUTPUT_DIR/security_scan.json
        ;;
    "services")
        echo " Running network policy audit..."
        python3 kubernetes/network-policy-audit.py > $OUTPUT_DIR/network_audit.json
        ;;
    "roles"|"clusterroles"|"rolebindings"|"clusterrolebindings")
        echo " Running RBAC analysis..."
        python3 kubernetes/rbac-analyzer.py > $OUTPUT_DIR/rbac_analysis.json
        ;;
    *)
        echo " Running comprehensive security scan..."
        python3 kubernetes/security-scan.py > $OUTPUT_DIR/security_scan.json
        ;;
esac

echo " Resource analysis complete: $OUTPUT_DIR"
```

#### Execute Resource Scan
```bash
# Analyze all pods
./resource-security-scan.sh pods

# Analyze pods in specific namespace
./resource-security-scan.sh pods production

# Analyze services
./resource-security-scan.sh services

# Analyze RBAC resources
./resource-security-scan.sh roles
./resource-security-scan.sh clusterroles
```

### 5. Continuous Monitoring

#### Automated Daily Security Scan
```bash
#!/bin/bash
# daily-security-scan.sh

CLUSTER_NAME=$(kubectl config current-context)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/var/log/k8s-security/${CLUSTER_NAME}_${TIMESTAMP}"

mkdir -p $OUTPUT_DIR

echo "$(date): Starting daily security scan for cluster: $CLUSTER_NAME" | tee $OUTPUT_DIR/scan.log

# Run security scans
python3 kubernetes/security-scan.py > $OUTPUT_DIR/security_scan.json 2>> $OUTPUT_DIR/scan.log
python3 kubernetes/rbac-analyzer.py > $OUTPUT_DIR/rbac_analysis.json 2>> $OUTPUT_DIR/scan.log
python3 kubernetes/network-policy-audit.py > $OUTPUT_DIR/network_audit.json 2>> $OUTPUT_DIR/scan.log

# Check for critical findings
CRITICAL_FINDINGS=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' $OUTPUT_DIR/security_scan.json)
CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + $(jq '[.findings[] | select(.severity == "CRITICAL")] | length' $OUTPUT_DIR/rbac_analysis.json)))
CRITICAL_FINDINGS=$((CRITICAL_FINDINGS + $(jq '[.findings[] | select(.severity == "CRITICAL")] | length' $OUTPUT_DIR/network_audit.json)))

if [ $CRITICAL_FINDINGS -gt 0 ]; then
    echo "$(date): ALERT: $CRITICAL_FINDINGS critical findings detected!" | tee -a $OUTPUT_DIR/scan.log
    # Send alert (customize based on your alerting system)
    # curl -X POST -H 'Content-type: application/json' --data '{"text":"Critical K8s security findings detected!"}' $SLACK_WEBHOOK_URL
fi

echo "$(date): Daily security scan complete" | tee -a $OUTPUT_DIR/scan.log

# Clean up old reports (keep last 30 days)
find /var/log/k8s-security -name "*.json" -mtime +30 -delete
```

#### Set up Cron Job
```bash
# Add to crontab for daily execution at 2 AM
crontab -e

# Add this line:
0 2 * * * /path/to/daily-security-scan.sh
```

### 6. CI/CD Pipeline Integration

#### GitHub Actions Workflow
```yaml
# .github/workflows/k8s-security.yml
name: Kubernetes Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup kubectl
      uses: azure/setup-kubectl@v3
      with:
        version: 'v1.28.0'
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-west-2
    
    - name: Configure kubectl for EKS
      run: |
        aws eks update-kubeconfig --region us-west-2 --name ${{ secrets.EKS_CLUSTER_NAME }}
    
    - name: Setup Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.9'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
    
    - name: Run Security Scan
      run: |
        python3 kubernetes/security-scan.py > security_scan.json
        python3 kubernetes/rbac-analyzer.py > rbac_analysis.json
        python3 kubernetes/network-policy-audit.py > network_audit.json
    
    - name: Check for Critical Findings
      run: |
        CRITICAL_COUNT=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' security_scan.json)
        if [ $CRITICAL_COUNT -gt 0 ]; then
          echo " Critical security findings detected: $CRITICAL_COUNT"
          exit 1
        else
          echo " No critical security findings"
        fi
    
    - name: Upload Security Reports
      uses: actions/upload-artifact@v3
      with:
        name: security-reports
        path: |
          security_scan.json
          rbac_analysis.json
          network_audit.json
```

#### GitLab CI Pipeline
```yaml
# .gitlab-ci.yml
stages:
  - security-scan

k8s-security-scan:
  stage: security-scan
  image: python:3.9
  before_script:
    - pip install -r requirements.txt
    - curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    - chmod +x kubectl
    - mv kubectl /usr/local/bin/
    - aws eks update-kubeconfig --region us-west-2 --name $EKS_CLUSTER_NAME
  script:
    - python3 kubernetes/security-scan.py > security_scan.json
    - python3 kubernetes/rbac-analyzer.py > rbac_analysis.json
    - python3 kubernetes/network-policy-audit.py > network_audit.json
    - |
      CRITICAL_COUNT=$(jq '[.findings[] | select(.severity == "CRITICAL")] | length' security_scan.json)
      if [ $CRITICAL_COUNT -gt 0 ]; then
        echo " Critical security findings detected: $CRITICAL_COUNT"
        exit 1
      fi
  artifacts:
    reports:
      junit: security_scan.json
    paths:
      - security_scan.json
      - rbac_analysis.json
      - network_audit.json
  only:
    - main
    - schedules
```

### 7. Multi-Cluster Analysis

#### Analyze Multiple Clusters
```bash
#!/bin/bash
# multi-cluster-security-scan.sh

CLUSTERS=("production-cluster" "staging-cluster" "development-cluster")
BASE_OUTPUT_DIR="multi-cluster-security-reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p $BASE_OUTPUT_DIR

echo " Starting multi-cluster security analysis..."
echo "Clusters: ${CLUSTERS[*]}"
echo "Output Directory: $BASE_OUTPUT_DIR"
echo "=========================================="

for cluster in "${CLUSTERS[@]}"; do
    echo " Analyzing cluster: $cluster"
    
    # Switch to cluster context
    kubectl config use-context $cluster
    
    if [ $? -eq 0 ]; then
        CLUSTER_OUTPUT_DIR="$BASE_OUTPUT_DIR/${cluster}_${TIMESTAMP}"
        mkdir -p $CLUSTER_OUTPUT_DIR
        
        # Run security scans
        python3 kubernetes/security-scan.py > $CLUSTER_OUTPUT_DIR/security_scan.json
        python3 kubernetes/rbac-analyzer.py > $CLUSTER_OUTPUT_DIR/rbac_analysis.json
        python3 kubernetes/network-policy-audit.py > $CLUSTER_OUTPUT_DIR/network_audit.json
        
        echo " Cluster $cluster analysis complete"
    else
        echo " Failed to connect to cluster: $cluster"
    fi
done

# Generate multi-cluster summary
echo " Generating multi-cluster summary..."
cat > $BASE_OUTPUT_DIR/multi_cluster_summary.md << EOF
# Multi-Cluster Security Analysis Summary

**Date:** $(date)  
**Clusters Analyzed:** ${CLUSTERS[*]}  

## Results Overview

EOF

for cluster in "${CLUSTERS[@]}"; do
    CLUSTER_OUTPUT_DIR="$BASE_OUTPUT_DIR/${cluster}_${TIMESTAMP}"
    if [ -f "$CLUSTER_OUTPUT_DIR/security_scan.json" ]; then
        cat >> $BASE_OUTPUT_DIR/multi_cluster_summary.md << EOF
### $cluster
- **Security Score:** $(jq '.summary.security_score' $CLUSTER_OUTPUT_DIR/security_scan.json)/100
- **Total Findings:** $(jq '.summary.total_findings' $CLUSTER_OUTPUT_DIR/security_scan.json)
- **Critical Findings:** $(jq '.summary.critical' $CLUSTER_OUTPUT_DIR/security_scan.json)

EOF
    fi
done

echo " Multi-cluster security analysis complete!"
echo " Results saved to: $BASE_OUTPUT_DIR"
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Permission Denied
```bash
# Error: User cannot list resource "pods"
# Solution: Check RBAC permissions
kubectl auth can-i list pods --as=system:serviceaccount:default:security-scanner
kubectl auth can-i list roles --as=system:serviceaccount:default:security-scanner
```

#### 2. Cluster Connection Failed
```bash
# Error: Unable to connect to the server
# Solution: Verify kubectl configuration
kubectl config current-context
kubectl config get-contexts
kubectl cluster-info
```

#### 3. Resource Not Found
```bash
# Error: No resources found
# Solution: Check if resources exist
kubectl get pods --all-namespaces
kubectl get networkpolicies --all-namespaces
kubectl get roles --all-namespaces
```

#### 4. Script Execution Errors
```bash
# Error: Python module not found
# Solution: Install dependencies
pip3 install -r requirements.txt

# Error: YAML parse error
# Solution: Check cluster resource configurations
kubectl get pods -o yaml | head -20
```

## Best Practices

### 1. Security Considerations
- Use dedicated service accounts with minimal required permissions
- Store sensitive outputs in secure locations
- Rotate service account tokens regularly
- Monitor script execution logs

### 2. Performance Optimization
- Run scans during low-traffic periods
- Use resource quotas to limit script resource usage
- Consider running scans in parallel for large clusters
- Clean up old report files regularly

### 3. Integration Recommendations
- Set up automated alerting for critical findings
- Integrate with SIEM systems for centralized monitoring
- Use version control for security scan configurations
- Document remediation procedures for common findings

### 4. Maintenance
- Update scripts regularly for new security checks
- Review and update RBAC permissions as needed
- Monitor script performance and optimize as necessary
- Keep dependencies up to date

## Output Examples

### Successful Execution
```bash
$ ./full-cluster-security-scan.sh
 Starting full cluster security analysis...
Cluster: production-cluster
Output Directory: security-reports/production-cluster_20241210_143022
==========================================
 Running comprehensive security scan...
 Security scan complete
 Running RBAC analysis...
 RBAC analysis complete
 Running network policy audit...
 Network policy audit complete
 Generating summary report...
 Full cluster security analysis complete!
 Results saved to: security-reports/production-cluster_20241210_143022
```

### Critical Findings Alert
```bash
$ ./daily-security-scan.sh
Mon Dec 10 02:00:01 UTC 2024: Starting daily security scan for cluster: production-cluster
Mon Dec 10 02:03:45 UTC 2024: ALERT: 2 critical findings detected!
Mon Dec 10 02:03:45 UTC 2024: Daily security scan complete
```

This comprehensive guide covers all the different ways you can run the Kubernetes security scripts against various targets and scenarios! 