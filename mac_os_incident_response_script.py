
import os
import subprocess

def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8')

def collect_system_info():
    print("Collecting system information...")
    print("Hostname:", run_command("hostname"))
    print("System Date & Time:", run_command("date"))
    print("Uptime:", run_command("uptime"))

def list_running_processes():
    print("\nListing running processes...")
    print(run_command("ps aux"))

def network_info():
    print("\nGathering network information...")
    print("Current network connections:")
    print(run_command("netstat -an"))
    print("Listening ports:")
    print(run_command("lsof -i -P | grep LISTEN"))

def system_logs():
    print("\nRetrieving system logs...")
    # This command gets the recent entries from the system log
    print(run_command("log show --predicate 'eventMessage contains "error"' --last 1d"))

def main():
    collect_system_info()
    list_running_processes()
    network_info()
    system_logs()

if __name__ == "__main__":
    main()
