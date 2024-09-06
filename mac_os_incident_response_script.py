import subprocess
import os
import json
from datetime import datetime, timedelta

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
        "recent_files": run_command("find /Users -type f -mtime -7 -ls"),
    }

def collect_security_info():
    return {
        "firewall_status": run_command("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate"),
        "system_integrity_protection": run_command("csrutil status"),
        "gatekeeper_status": run_command("spctl --status"),
        "filevault_status": run_command("fdesetup status"),
        "software_updates": run_command("softwareupdate --list"),
        "xprotect_version": run_command("system_profiler SPInstallHistoryDataType | grep -A 4 XProtectPlistConfigData"),
        "installed_applications": run_command("system_profiler SPApplicationsDataType"),
        "launch_agents": run_command("ls -la /Library/LaunchAgents /System/Library/LaunchAgents ~/Library/LaunchAgents"),
        "launch_daemons": run_command("ls -la /Library/LaunchDaemons /System/Library/LaunchDaemons"),
        "cron_jobs": run_command("crontab -l"),
        "ssh_config": run_command("cat /etc/ssh/sshd_config"),
        "root_ssh_keys": run_command("ls -la /var/root/.ssh"),
        "system_extensions": run_command("systemextensionsctl list"),
        "kernel_extensions": run_command("kextstat"),
        "signed_system_volume": run_command("csrutil authenticated-root status"),
        "active_directory_status": run_command("dsconfigad -show"),
        "touchid_for_sudo": run_command("grep pam_tid /etc/pam.d/sudo"),
        "network_time": run_command("systemsetup -getusingnetworktime"),
        "automatic_logout": run_command("systemsetup -getautologout"),
        "screensaver_settings": run_command("defaults read com.apple.screensaver"),
        "sip_compatibility_mode": run_command("csrutil internal"),
        "mdm_enrollment": run_command("profiles status -type enrollment"),
        "secure_token_status": run_command("diskutil apfs listUsers /"),
        "wifi_networks": run_command("networksetup -listpreferredwirelessnetworks en0"),
    }

def collect_system_logs():
    yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    today = datetime.now().strftime("%Y-%m-%d")
    return run_command(f"log show --start '{yesterday} 00:00:00' --end '{today} 23:59:59'")

def main():
    incident_data = {
        "timestamp": datetime.now().isoformat(),
        "system_info": collect_system_info(),
        "network_info": collect_network_info(),
        "process_info": collect_process_info(),
        "user_info": collect_user_info(),
        "file_system_info": collect_file_system_info(),
        "security_info": collect_security_info(),
        "system_logs": collect_system_logs(),
    }

    output_file = f"macos_incident_response_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output_file, 'w') as f:
        json.dump(incident_data, f, indent=2)

    print(f"Incident response data has been collected and saved to {output_file}")

if __name__ == "__main__":
    main()
