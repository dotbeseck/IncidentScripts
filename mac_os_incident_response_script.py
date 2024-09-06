import subprocess
import os
import json
from datetime import datetime, timedelta
from tqdm import tqdm

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        return result.stdout.strip()
    except Exception as e:
        return f"Error running command: {e}"

def collect_system_info():
    return {
        "hostname": run_command("hostname"),
        "os_version": run_command("sw_vers -productVersion"),
        "kernel_version": run_command("uname -r"),
        "uptime": run_command("uptime"),
        "current_users": run_command("who"),
    }

def collect_network_info():
    return {
        "ip_addresses": run_command("ifconfig | grep inet | grep -v inet6"),
        "routing_table": run_command("netstat -rn"),
        "open_connections": run_command("lsof -i -n -P"),
        "dns_config": run_command("cat /etc/resolv.conf"),
    }

def collect_process_info():
    return {
        "running_processes": run_command("ps aux"),
        "listening_ports": run_command("lsof -i -P | grep LISTEN"),
    }

def collect_user_info():
    return {
        "user_accounts": run_command("dscl . list /Users | grep -v '^_'"),
        "sudo_users": run_command("cat /etc/sudoers | grep -v '^#' | grep -v '^$'"),
        "login_history": run_command("last"),
    }

def collect_file_system_info():
    return {
        "disk_usage": run_command("df -h"),
        "mounted_volumes": run_command("mount"),
        # Removed recent files collection to avoid permission prompts
    }

def collect_security_info():
    return {
        "firewall_status": run_command("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"),
        "system_integrity_protection": run_command("csrutil status"),
        "gatekeeper_status": run_command("spctl --status"),
        "filevault_status": run_command("fdesetup status"),
        "software_updates": run_command("softwareupdate --list"),
        "xprotect_version": run_command("system_profiler SPInstallHistoryDataType | grep -A 4 XProtectPlistConfigData"),
        # Removed or modified commands that might trigger permission prompts
    }

def collect_docker_info():
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
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    today = datetime.now().strftime("%Y-%m-%d")
    return run_command(f"log show --start '{yesterday} 00:00:00' --end '{today} 23:59:59'")

def main():
    collection_functions = [
        ("System Info", collect_system_info),
        ("Network Info", collect_network_info),
        ("Process Info", collect_process_info),
        ("User Info", collect_user_info),
        ("File System Info", collect_file_system_info),
        ("Security Info", collect_security_info),
        ("Docker Info", collect_docker_info),
        ("System Logs", collect_system_logs)
    ]

    incident_data = {"timestamp": datetime.now().isoformat()}

    with tqdm(total=len(collection_functions), desc="Collecting Data", unit="module") as pbar:
        for name, func in collection_functions:
            incident_data[name.lower().replace(" ", "_")] = func()
            pbar.update(1)
            pbar.set_description(f"Collected {name}")

    output_file = f"macos_incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(incident_data, f, indent=2)

    print(f"\nIncident response data has been collected and saved to {output_file}")

if __name__ == "__main__":
    main()
