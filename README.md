# Incident Response Scripts Collection

A comprehensive collection of incident response and forensic analysis tools for AWS, Kubernetes, system analysis, and malware investigation.

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Tool Categories](#tool-categories)
- [Usage Examples](#usage-examples)
- [Contributing](#contributing)
- [Security Notice](#security-notice)
- [Troubleshooting](#troubleshooting)

## 🔍 Overview

This repository contains a curated set of incident response tools designed to help security professionals quickly gather forensic evidence, analyze system states, and investigate security incidents across multiple platforms and environments.

### Key Features

- **Multi-platform support**: Windows, macOS, Linux
- **Cloud forensics**: AWS EC2, EBS, Security Groups
- **Container analysis**: Kubernetes, Docker
- **Malware analysis**: PowerShell deobfuscation, recursive deobfuscation
- **Network forensics**: IP analysis, WHOIS lookups
- **Automated data collection**: System information, logs, processes

## 🛠 Prerequisites

### System Requirements
- **Python 3.7+** (for Python scripts)
- **PowerShell 5.1+** (for Windows scripts)
- **Bash 4.0+** (for shell scripts)
- **kubectl** (for Kubernetes tools)
- **AWS CLI** (for AWS tools)

### Required Python Packages
```bash
pip install -r requirements.txt
```

### AWS Prerequisites
- AWS CLI configured with appropriate credentials
- IAM permissions for EC2, STS, and EBS operations
- Cross-account access configured (for forensic snapshots)

### Kubernetes Prerequisites
- kubectl configured and authenticated
- Cluster admin or appropriate RBAC permissions
- Access to audit logs (if using audit parser)

## 📦 Installation

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/IncidentScripts.git
cd IncidentScripts

# Install Python dependencies
pip install -r requirements.txt

# Make scripts executable (Linux/macOS)
chmod +x aws/*.sh kubernetes/*.sh
```

### Manual Setup
```bash
# Install Python dependencies
pip install boto3 requests beautifulsoup4 colorama

# Configure AWS CLI (if using AWS tools)
aws configure

# Configure kubectl (if using Kubernetes tools)
kubectl config set-context your-context
```

## 🗂 Tool Categories

### 🔐 AWS Forensics (`aws/`)
- **`forensic-snapshot.py`** - Create and share EBS snapshots for forensic analysis
- **`security-group-audit.sh`** - Audit security groups for open ports
- **`windows-instances.sh`** - Discover running Windows instances

### ☸️ Kubernetes Analysis (`kubernetes/`)
- **`audit-parser.py`** - Parse Kubernetes audit logs for security concerns
- **`incident-response.sh`** - Comprehensive Kubernetes incident response data collection
- **`basic-collector.sh`** - Basic Kubernetes data gathering
- **`security-scan.py`** - Comprehensive Kubernetes security assessment
- **`rbac-analyzer.py`** - Deep RBAC analysis and privilege escalation detection
- **`network-policy-audit.py`** - Network security policy analysis

### 💻 System Analysis (`system-analysis/`)
- **`macos/incident-response.py`** - macOS system forensics
- **`macos/security-audit.py`** - macOS security assessment (RTR-compatible)
- **`macos/process-forensics.py`** - macOS process analysis and anomaly detection
- **`macos/docker-integrated.py`** - macOS with Docker analysis
- **`windows/incident-response.ps1`** - Windows system forensics
- **`docker/macos-docker.py`** - Docker container analysis

### 🦠 Malware Analysis (`malware-analysis/`)
- **`powershell-analyzer.py`** - Advanced PowerShell script analysis with MITRE ATT&CK mapping
- **`powershell-deobfuscator.py`** - PowerShell deobfuscation and transformation
- **`recursive-deobfuscator.py`** - Multi-layer Python malware deobfuscation

### 🌐 Network Analysis (`network/`)
- **`ip-analyzer.py`** - IP address analysis and WHOIS lookups

## 📖 Usage Examples

### AWS Forensic Snapshot
```bash
# Create snapshots for specific instances
python aws/forensic-snapshot.py -t 123456789012 -f instances.txt

# Create snapshots for individual instances
python aws/forensic-snapshot.py -t 123456789012 i-1234567890abcdef0 i-0987654321fedcba0
```

### Kubernetes Security Analysis
```bash
# Comprehensive security scan
python kubernetes/security-scan.py

# RBAC analysis
python kubernetes/rbac-analyzer.py

# Network policy audit
python kubernetes/network-policy-audit.py

# Parse audit logs for security concerns
python kubernetes/audit-parser.py audit.log -p

# Kubernetes incident response
./kubernetes/incident-response.sh -n production -o /tmp/ir_data
```

### macOS Security Analysis (CrowdStrike RTR Compatible)
```bash
# Comprehensive security audit
python system-analysis/macos/security-audit.py

# Process forensics analysis
python system-analysis/macos/process-forensics.py

# Standard incident response
python system-analysis/macos/incident-response.py
```

### PowerShell Malware Analysis
```bash
# Analyze suspicious PowerShell script
python malware-analysis/powershell-analyzer.py suspicious_script.ps1

# Deobfuscate encoded PowerShell
python malware-analysis/powershell-deobfuscator.py encoded_script.ps1
```

### System Incident Response
```bash
# Windows system analysis (PowerShell)
.\system-analysis\windows\incident-response.ps1

# Docker analysis
python system-analysis/docker/macos-docker.py
```

### Network Analysis
```bash
# Analyze IP addresses from log files
python network/ip-analyzer.py network_logs.csv results.csv
```

## 🔧 Configuration

### AWS Configuration
Create a `config.yaml` file for AWS tools:
```yaml
aws:
  regions:
    - us-east-1
    - us-west-2
    - eu-west-1
  default_region: us-east-1
  snapshot_tags:
    - Key: Purpose
      Value: IncidentResponse
    - Key: CreatedBy
      Value: SecurityTeam
```

### Kubernetes Configuration
Set environment variables for kubectl tools:
```bash
export KUBECONFIG=/path/to/your/kubeconfig
export K8S_NAMESPACE=production
```

## 📊 Output Formats

### JSON Output
Most tools support JSON output for integration with SIEM systems:
```bash
python system-analysis/macos/incident-response.py --format json --output incident_data.json
python kubernetes/security-scan.py > security_scan.json
python kubernetes/rbac-analyzer.py > rbac_analysis.json
```

### CSV Output
Network and audit tools can export to CSV:
```bash
python network/ip-analyzer.py input.csv --output results.csv
```

### HTML Reports
Some tools generate HTML reports for easy viewing:
```bash
python kubernetes/audit-parser.py audit.log --html report.html
```

## 🚨 Security Notice

⚠️ **IMPORTANT SECURITY CONSIDERATIONS**

- These tools are designed for authorized incident response activities only
- Ensure you have proper authorization before running any forensic tools
- Some tools may modify system state (e.g., creating snapshots, collecting logs)
- Review and understand what each tool does before execution
- Store collected data securely and follow data retention policies
- Be aware of legal and compliance requirements in your jurisdiction

### Best Practices
- Run tools in isolated environments when possible
- Document all actions taken during incident response
- Preserve chain of custody for forensic evidence
- Use read-only operations when possible
- Validate tool outputs before making decisions

## 🐛 Troubleshooting

### Common Issues

#### AWS Tools
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify permissions
aws ec2 describe-regions

# Check region availability
aws ec2 describe-availability-zones --region us-east-1
```

#### Kubernetes Tools
```bash
# Verify kubectl access
kubectl cluster-info

# Check permissions
kubectl auth can-i get pods

# Verify namespace access
kubectl get namespaces
```

#### Python Dependencies
```bash
# Update pip
pip install --upgrade pip

# Reinstall requirements
pip install -r requirements.txt --force-reinstall

# Check Python version
python --version
```

### Error Codes

| Error Code | Description | Solution |
|------------|-------------|----------|
| `AWS_ACCESS_DENIED` | Insufficient AWS permissions | Check IAM policies |
| `KUBE_CONFIG_ERROR` | kubectl not configured | Run `kubectl config` |
| `PYTHON_IMPORT_ERROR` | Missing Python package | Run `pip install -r requirements.txt` |
| `PERMISSION_DENIED` | Insufficient system permissions | Run with appropriate privileges |

### Log Files
- Check `incident_response.log` for detailed execution logs
- Review system logs for permission issues
- Monitor AWS CloudTrail for API call logs

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-tool`
3. **Follow coding standards**: Use consistent formatting and error handling
4. **Add tests**: Include unit tests for new functionality
5. **Update documentation**: Add usage examples and update README
6. **Submit a pull request**: Include a clear description of changes

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 *.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

- **Issues**: Report bugs and request features via [GitHub Issues](https://github.com/yourusername/IncidentScripts/issues)
- **Discussions**: Join community discussions in [GitHub Discussions](https://github.com/yourusername/IncidentScripts/discussions)
- **Security**: Report security issues privately via email

## 🙏 Acknowledgments

- AWS Security team for forensic best practices
- Kubernetes community for audit log insights
- MITRE ATT&CK framework for technique mapping
- Open source security community for inspiration

---

**⚠️ Disclaimer**: These tools are provided for educational and authorized incident response purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.
