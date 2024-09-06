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

def collect_system_info():
    print("Collecting system information...")
    return {
        "hostname": run_command("hostname"),
        "os_version": run_command("sw_vers -productVersion"),
        "kernel_version": run_command("uname -r"),
        "uptime": run_command("uptime"),
        "current_users": run_command("who"),
    }

def collect_network_info():
    print("Collecting network information...")
    return {
        "ip_addresses": run_command("ifconfig | grep inet | grep -v inet6"),
        "routing_table": run_command("netstat -rn"),
        "open_connections": run_command("lsof -i -n -P"),
        "dns_config": run_command("cat /etc/resolv.conf"),
    }

def collect_process_info():
    print("Collecting process information...")
    return {
        "running_processes": run_command("ps aux"),
        "listening_ports": run_command("lsof -i -P | grep LISTEN"),
    }

def collect_user_info():
    print("Collecting user information...")
    return {
        "user_accounts": run_command("dscl . list /Users | grep -v '^_'"),
        "sudo_users": run_command("cat /etc/sudoers | grep -v '^#' | grep -v '^$'"),
        "login_history": run_command("last -10"),  # Limit to last 10 entries for speed
    }

def collect_file_system_info():
    print("Collecting file system information...")
    return {
        "disk_usage": run_command("df -h"),
        "mounted_volumes": run_command("mount"),
    }

def collect_security_info():
    print("Collecting security information...")
    return {
        "firewall_status": run_command("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"),
        "system_integrity_protection": run_command("csrutil status"),
        "gatekeeper_status": run_command("spctl --status"),
        "filevault_status": run_command("fdesetup status"),
        "software_updates": run_command("softwareupdate --list"),
    }

def collect_docker_info():
    print("Collecting Docker information...")
    docker_version = run_command("docker --version")
    if "Docker version" not in docker_version:
        return {"error": "Docker is not installed or not in PATH"}

    return {
        "version": docker_version,
        "running_containers": run_command("docker ps --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'"),
        "all_containers": run_command("docker ps -a --format '{{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'"),
        "images": run_command("docker images --format '{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}\t{{.Size}}'"),
        "networks": run_command("docker network ls --format '{{.ID}}\t{{.Name}}\t{{.Driver}}'"),
        "volumes": run_command("docker volume ls --format '{{.Name}}\t{{.Driver}}'")
    }

def collect_system_logs():
    print("Collecting recent system logs (last 1 hour)...")
    one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    return run_command(f"log show --start '{one_hour_ago}' --style syslog")

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
    }

    output_file = f"macos_incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(incident_data, f, indent=2)

    print(f"\nIncident response data has been collected and saved to {output_file}")

if __name__ == "__main__":
    main()
