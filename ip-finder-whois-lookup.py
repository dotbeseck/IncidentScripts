import csv
import json
import sys
import re
import requests
from ipaddress import ip_address
from collections import defaultdict
import io

def is_valid_ip(ip):
    try:
        ip_address(ip)
        return True
    except ValueError:
        return False

def extract_ips(file_path):
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    unique_ips = set()

    if file_path.endswith('.csv'):
        with open(file_path, 'r') as file:
            content = file.read()
    elif file_path.endswith('.json'):
        content = ""
        with open(file_path, 'r') as file:
            for line in file:
                try:
                    json_obj = json.loads(line)
                    content += json.dumps(json_obj)
                except json.JSONDecodeError:
                    content += line
    else:
        raise ValueError("Unsupported file format. Please use CSV or JSON.")

    ips = re.findall(ip_pattern, content)
    return set(ip for ip in ips if is_valid_ip(ip))

def get_org_name_from_ip(ip):
    try:
        response = requests.get(f'http://ipinfo.io/{ip}/json')
        if response.status_code == 200:
            data = response.json()
            return data.get('org', 'N/A'), data.get('country', 'N/A')
    except Exception as e:
        return f"IPInfo Error: {str(e)}", "N/A"
    return "No information found", "N/A"

def process_ips(ips, output=None):
    results = defaultdict(list)
    
    output_file = open(output, 'w', newline='') if output else io.StringIO()
    writer = csv.writer(output_file)
    writer.writerow(['IP', 'Organization', 'Country'])
    
    for ip in ips:
        org_name, country = get_org_name_from_ip(ip)
        writer.writerow([ip, org_name, country])
        results[org_name].append(ip)
        print(f"Processed: {ip} - Org: {org_name} - Country: {country}")

    if not output:
        print("\nDetailed Results:")
        print(output_file.getvalue())
    else:
        output_file.close()

    return results

def print_summary(results):
    print("\nSummary:")
    for org, ips in results.items():
        print(f"{org}: {len(ips)} IP(s)")

if __name__ == "__main__":
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print("Usage: python script.py input_file.[csv/json] [output_file.csv]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) == 3 else None
    
    try:
        unique_ips = extract_ips(input_file)
        print(f"Found {len(unique_ips)} unique IP addresses.")
        results = process_ips(unique_ips, output_file)
        if output_file:
            print(f"Results written to {output_file}")
        print_summary(results)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
