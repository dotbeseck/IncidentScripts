import subprocess
import os
import json
from datetime import datetime, timedelta

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True, timeout=60)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return "Command timed out after 60 seconds"
    except Exception as e:
        return f"Error running command: {e}"

# ... [Previous functions remain the same] ...

def collect_recent_system_files():
    print("Collecting information on recently modified system files...")
    directories = [
        "/etc",
        "/var/log",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons"
    ]
    
    recent_files = {}
    for directory in directories:
        cmd = f"find {directory} -type f -mtime -1 -exec ls -la {{}} +"
        recent_files[directory] = run_command(cmd)
    
    return recent_files

def main():
    print("Starting macOS incident response data collection...")
    
    incident_data = {
        "timestamp": datetime.now().isoformat(),
        "system_info": collect_system_info(),
        "network_info": collect_network_info(),
        "process_info": collect_process_info(),
        "user_info": collect_user_info(),
        "file_system_info": collect_file_system_info(),
        "security_info": collect_security_info(),
        "docker_info": collect_docker_info(),
        "recent_logs": collect_system_logs(),
        "recent_system_files": collect_recent_system_files(),
    }

    output_file = f"macos_incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(incident_data, f, indent=2)

    print(f"\nIncident response data has been collected and saved to {output_file}")

if __name__ == "__main__":
    main()
