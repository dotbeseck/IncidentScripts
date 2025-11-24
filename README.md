# Incident Scripts Collection

A comprehensive collection of incident response and forensic analysis tools for AWS, Kubernetes, system analysis, and malware investigation.

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
- [Tool Categories](#tool-categories)
- [Contributing](#contributing)

## Overview

This repository contains a curated set of incident response tools designed to help security professionals quickly gather forensic evidence, analyze system states, and investigate security incidents across multiple platforms and environments.

## Installation

### Prerequisites
- Python 3.7+
- PowerShell 5.1+ (for Windows scripts)
- Bash 4.0+ (for shell scripts)
- `kubectl` (for Kubernetes tools)
- `aws` CLI (for AWS tools)

### Install Package
```bash
git clone https://github.com/dotbeseck/IncidentScripts.git
cd IncidentScripts
pip install .
```

## Usage

The tools are now available under a unified CLI `incident-response`.

### AWS Forensics
```bash
# Create forensic snapshots
incident-response aws snapshot -t 123456789012 -i i-1234567890abcdef0
```

### Kubernetes Analysis
```bash
# Parse audit logs
incident-response k8s audit audit.log
```

### Shell Scripts
Legacy shell scripts are located in the `scripts/` directory and can be run directly:
```bash
./scripts/aws/security-group-audit.sh
./scripts/kubernetes/incident-response.sh
```

## Tool Categories

### AWS (`src/incident_scripts/aws/`)
- **Forensic Snapshot**: Create and share EBS snapshots.

### Kubernetes (`src/incident_scripts/kubernetes/`)
- **Audit Parser**: Parse Kubernetes audit logs.
- **RBAC Analyzer**: Analyze RBAC permissions.
- **Security Scan**: Comprehensive security assessment.

### Malware Analysis (`src/incident_scripts/malware/`)
- **PowerShell Analyzer**: Analyze suspicious PowerShell scripts.
- **Deobfuscators**: Tools to deobfuscate code.

### System Analysis (`src/incident_scripts/system/`)
- **macOS**: System forensics and security audits.
- **Docker**: Container analysis.

### Network (`src/incident_scripts/network/`)
- **IP Analyzer**: Analyze IP addresses.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Install dev dependencies: `pip install .[dev]` (if configured)
4. Submit a pull request
