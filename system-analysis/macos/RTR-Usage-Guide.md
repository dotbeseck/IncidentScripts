# macOS Security Scripts for CrowdStrike Falcon RTR

## Overview

These scripts are designed to run in CrowdStrike Falcon's Real Time Response (RTR) environment with minimal dependencies and maximum compatibility.

## Scripts Available

### 1. `security-audit.py`
**Purpose**: Comprehensive macOS security assessment
**Runtime**: ~2-3 minutes
**Output**: JSON format with security findings and recommendations

### 2. `process-forensics.py`
**Purpose**: Deep process analysis and anomaly detection
**Runtime**: ~1-2 minutes
**Output**: JSON format with process analysis and suspicious activity detection

## RTR Execution Instructions

### Method 1: Direct Upload and Execute

1. **Upload Script to RTR**:
   ```
   upload security-audit.py
   ```

2. **Make Executable**:
   ```
   runscript -CloudFile="security-audit.py" -CommandLine="chmod +x security-audit.py"
   ```

3. **Execute Script**:
   ```
   runscript -CloudFile="security-audit.py" -CommandLine="python3 security-audit.py"
   ```

### Method 2: Inline Execution

1. **Copy script content to RTR console**
2. **Execute directly**:
   ```
   runscript -Raw=```python3
   # [paste script content here]
   ```
   ```

### Method 3: One-liner Execution

For quick execution without file upload:

```bash
runscript -Raw=```python3
import os,sys,json,subprocess,plistlib
from datetime import datetime
from pathlib import Path

# [paste script content here]
```
```

## Expected Output

### Security Audit Script Output:
```json
{
  "timestamp": "2024-12-10T15:30:00",
  "hostname": "MacBook-Pro.local",
  "system_info": {
    "version": {
      "ProductName": "macOS",
      "ProductVersion": "14.2.1",
      "BuildVersion": "23C71"
    },
    "current_user": "admin"
  },
  "security_checks": {
    "sip": {
      "enabled": true,
      "status": "Enabled"
    },
    "gatekeeper": {
      "enabled": true,
      "status": "Enabled"
    },
    "filevault": {
      "enabled": true,
      "status": "Enabled"
    }
  },
  "findings": [
    {
      "severity": "MEDIUM",
      "category": "Network Security",
      "description": "Found 2 connections to suspicious ports",
      "recommendation": "Review network connections and block suspicious ports"
    }
  ],
  "summary": {
    "total_findings": 1,
    "security_score": 85
  }
}
```

### Process Forensics Script Output:
```json
{
  "timestamp": "2024-12-10T15:30:00",
  "hostname": "MacBook-Pro.local",
  "process_analysis": {
    "total_processes": 245,
    "orphaned_processes": [],
    "suspicious_relationships": []
  },
  "suspicious_processes": [
    {
      "process": {
        "pid": "1234",
        "command": "/tmp/suspicious_script.sh"
      },
      "reason": "Running from temporary directory",
      "severity": "MEDIUM"
    }
  ],
  "network_connections": {
    "total_connections": 45,
    "suspicious_network": []
  },
  "summary": {
    "total_processes": 245,
    "suspicious_processes": 1,
    "total_findings": 1
  }
}
```

## RTR-Specific Considerations

### 1. **Limited Dependencies**
- Scripts use only built-in Python modules
- No external package requirements
- Compatible with RTR's restricted environment

### 2. **Timeout Handling**
- All commands have 30-second timeouts
- Graceful handling of command failures
- No hanging processes

### 3. **Output Format**
- JSON output for easy parsing
- Structured data for SIEM integration
- Human-readable console output

### 4. **File System Access**
- Limited to `/tmp/` for output files
- Read-only access to system directories
- No modification of system files

### 5. **Network Access**
- No outbound network connections
- Local system analysis only
- Safe for restricted environments

## Troubleshooting

### Common Issues:

1. **Permission Denied**:
   ```
   Solution: Run with appropriate RTR permissions
   ```

2. **Command Not Found**:
   ```
   Solution: Scripts use standard macOS commands only
   ```

3. **Timeout Errors**:
   ```
   Solution: Commands have built-in timeouts, will continue execution
   ```

4. **JSON Parse Errors**:
   ```
   Solution: Check console output for raw results
   ```

## Integration with SIEM

### Splunk Integration:
```splunk
index=security source="crowdstrike_rtr" sourcetype="macos_security_audit"
| spath path=findings
| mvexpand findings
| eval severity=findings.severity
| stats count by severity
```

### ELK Stack Integration:
```json
{
  "mappings": {
    "properties": {
      "timestamp": {"type": "date"},
      "hostname": {"type": "keyword"},
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

## Security Considerations

1. **No Data Exfiltration**: Scripts don't send data externally
2. **Read-Only Operations**: No system modifications
3. **Local Analysis Only**: No network connections
4. **Minimal Footprint**: Lightweight and fast execution
5. **Audit Trail**: All actions logged in RTR console

## Performance Notes

- **Security Audit**: ~2-3 minutes on typical macOS system
- **Process Forensics**: ~1-2 minutes on typical macOS system
- **Memory Usage**: <50MB during execution
- **CPU Impact**: Minimal, uses system commands efficiently

## Customization

Scripts can be easily modified for specific requirements:

1. **Add Custom Checks**: Modify the check functions
2. **Change Severity Levels**: Adjust severity thresholds
3. **Add New Categories**: Extend the findings structure
4. **Modify Output Format**: Change JSON structure as needed

## Support

For issues or questions:
1. Check RTR console output for error messages
2. Verify script syntax and permissions
3. Test in non-production environment first
4. Review CrowdStrike RTR documentation for limitations
