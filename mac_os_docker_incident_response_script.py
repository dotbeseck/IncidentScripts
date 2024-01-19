
import os
import subprocess

def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return e.output.decode('utf-8')

def docker_installed():
    docker_version = run_command("docker --version")
    if "Docker version" in docker_version:
        return True
    return False

def docker_running():
    docker_info = run_command("docker info")
    if "Server:" in docker_info:
        return True
    return False

def collect_docker_info():
    if not docker_installed():
        print("Docker is not installed on this host.")
        return
    if not docker_running():
        print("Docker daemon is not running.")
        return

    print("\nCollecting Docker information...")
    print("List of running Docker containers:")
    print(run_command("docker ps"))
    print("List of all Docker containers:")
    print(run_command("docker ps -a"))
    print("List of Docker images:")
    print(run_command("docker images"))
    print("Docker network settings:")
    print(run_command("docker network ls"))
    print("Detailed Docker network inspect:")
    for network in run_command("docker network ls --format '{{.Name}}'").splitlines():
        print(f"Network {network}:")
        print(run_command(f"docker network inspect {network}"))

def main():
    collect_system_info()
    list_running_processes()
    network_info()
    collect_docker_info()
    system_logs()

if __name__ == "__main__":
    main()
