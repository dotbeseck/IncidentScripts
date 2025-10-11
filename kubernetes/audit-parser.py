#!/usr/bin/env python3
import json
import sys
import argparse

def find_first_json(text):
    """Enhanced JSON string extraction"""
    try:
        # Handle both regular and escaped JSON
        text = text.replace('\\"', '"').replace('\\\\', '\\')
        
        if text.startswith('"'):
            in_escape = False
            for i in range(1, len(text)):
                if text[i] == '\\' and not in_escape:
                    in_escape = True
                    continue
                if text[i] == '"' and not in_escape:
                    return text[:i+1]
                in_escape = False
                
        # Try to find JSON-like content even if it doesn't start with a quote
        import re
        json_pattern = r'({[^}]+})'
        match = re.search(json_pattern, text)
        if match:
            return match.group(1)
            
    except Exception as e:
        print(f"Error in find_first_json: {str(e)}")
    return text

def parse_k8s_field(field_data):
    """Parse a field that might be prefixed with k: or f: and contain escaped JSON"""
    if isinstance(field_data, (dict, list, int, bool)):
        return field_data
        
    if isinstance(field_data, str):
        # Remove k: or f: prefix if present
        if field_data.startswith(('k:', 'f:')):
            field_data = field_data[2:]
            
        try:
            # Handle escaped JSON strings
            cleaned = field_data.replace('\\"', '"').replace('\\\\', '\\')
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return field_data
            
    return field_data

def extract_field_recursive(obj, field_name):
    """Recursively extract fields that might be nested or prefixed"""
    results = []
    
    if isinstance(obj, dict):
        for key, value in obj.items():
            # Check if the key itself contains our field
            if isinstance(key, str):
                if field_name in key.lower():
                    parsed = parse_k8s_field(key)
                    if isinstance(parsed, dict) and field_name in parsed:
                        results.append(parsed[field_name])
                
            # Direct match in the value
            if field_name in value if isinstance(value, str) else False:
                parsed = parse_k8s_field(value)
                if isinstance(parsed, dict) and field_name in parsed:
                    results.append(parsed[field_name])
                    
            # Check direct key match
            if field_name in key if isinstance(key, str) else False:
                if isinstance(value, dict):
                    results.append(value)
                else:
                    parsed = parse_k8s_field(value)
                    if parsed is not None:
                        results.append(parsed)
                        
            # Recursive search
            if isinstance(value, dict):
                results.extend(extract_field_recursive(value, field_name))
            elif isinstance(value, list):
                results.extend(extract_field_recursive(value, field_name))
                    
    elif isinstance(obj, list):
        for item in obj:
            results.extend(extract_field_recursive(item, field_name))
            
    return results

def extract_container_specs(obj):
    """Extract all container specs from potentially deeply nested structures"""
    containers = []
    
    if isinstance(obj, dict):
        # Look for containers and initContainers at current level
        if 'containers' in obj:
            if isinstance(obj['containers'], list):
                containers.extend(obj['containers'])
        if 'initContainers' in obj:
            if isinstance(obj['initContainers'], list):
                containers.extend(obj['initContainers'])
                
        # Handle k: and f: prefixed fields
        for key, value in obj.items():
            if isinstance(key, str):
                # Handle prefixed fields that might contain container specs
                if key.startswith(('k:', 'f:')):
                    try:
                        parsed = parse_k8s_field(key)
                        if isinstance(parsed, dict):
                            containers.extend(extract_container_specs(parsed))
                    except:
                        pass
                
                # Continue recursive search
                if isinstance(value, (dict, list)):
                    containers.extend(extract_container_specs(value))
                    
    elif isinstance(obj, list):
        for item in obj:
            containers.extend(extract_container_specs(item))
            
    return containers

def extract_volume_mounts(obj):
    """Extract volume mounts from deeply nested structures"""
    mounts = []
    
    if isinstance(obj, dict):
        # Direct volumeMounts array
        if 'volumeMounts' in obj and isinstance(obj['volumeMounts'], list):
            for mount in obj['volumeMounts']:
                if isinstance(mount, dict):
                    mounts.append({
                        'mount': mount,
                        'container': obj.get('name', 'unknown')
                    })
        
        # Handle k: and f: prefixed fields
        for key, value in obj.items():
            if isinstance(key, str):
                # Handle prefixed volume mount specifications
                if key.startswith(('k:', 'f:')) and 'volumeMounts' in key:
                    try:
                        parsed = parse_k8s_field(key)
                        if isinstance(parsed, dict):
                            container_name = obj.get('name', 'unknown')
                            for mount in parsed.get('volumeMounts', []):
                                if isinstance(mount, dict):
                                    mounts.append({
                                        'mount': mount,
                                        'container': container_name
                                    })
                    except:
                        pass
                
                # Recursive search
                if isinstance(value, (dict, list)):
                    mounts.extend(extract_volume_mounts(value))
                    
    elif isinstance(obj, list):
        for item in obj:
            mounts.extend(extract_volume_mounts(item))
            
    return mounts

def extract_commands(obj):
    """Extract commands and args from deeply nested structures"""
    commands = []
    
    if isinstance(obj, dict):
        container_name = obj.get('name', 'unknown')
        
        # Check direct command and args
        if 'command' in obj:
            cmd_list = obj['command'] if isinstance(obj['command'], list) else [obj['command']]
            commands.extend([{'cmd': cmd, 'type': 'command', 'container': container_name} for cmd in cmd_list])
            
        if 'args' in obj:
            arg_list = obj['args'] if isinstance(obj['args'], list) else [obj['args']]
            commands.extend([{'cmd': arg, 'type': 'arg', 'container': container_name} for arg in arg_list])
        
        # Handle k: and f: prefixed fields
        for key, value in obj.items():
            if isinstance(key, str):
                if key.startswith(('k:', 'f:')):
                    try:
                        parsed = parse_k8s_field(key)
                        if isinstance(parsed, dict):
                            if 'command' in parsed:
                                cmd_list = parsed['command'] if isinstance(parsed['command'], list) else [parsed['command']]
                                commands.extend([{'cmd': cmd, 'type': 'command', 'container': container_name} for cmd in cmd_list])
                            if 'args' in parsed:
                                arg_list = parsed['args'] if isinstance(parsed['args'], list) else [parsed['args']]
                                commands.extend([{'cmd': arg, 'type': 'arg', 'container': container_name} for arg in arg_list])
                    except:
                        pass
                
                # Recursive search
                if isinstance(value, (dict, list)):
                    commands.extend(extract_commands(value))
                    
    elif isinstance(obj, list):
        for item in obj:
            commands.extend(extract_commands(item))
            
    return commands

def extract_volumes(obj):
    """Extract volumes from deeply nested structures"""
    volumes = []
    
    if isinstance(obj, dict):
        # Direct volumes array
        if 'volumes' in obj and isinstance(obj['volumes'], list):
            volumes.extend(obj['volumes'])
        
        # Handle k: and f: prefixed fields
        for key, value in obj.items():
            if isinstance(key, str):
                if key.startswith(('k:', 'f:')) and 'volumes' in key:
                    try:
                        parsed = parse_k8s_field(key)
                        if isinstance(parsed, dict) and 'volumes' in parsed:
                            volumes.extend(parsed['volumes'])
                    except:
                        pass
                
                # Recursive search in all values
                if isinstance(value, (dict, list)):
                    volumes.extend(extract_volumes(value))
                    
    elif isinstance(obj, list):
        for item in obj:
            volumes.extend(extract_volumes(item))
            
    return volumes

def extract_ports(obj):
    """Enhanced port extraction with container context"""
    ports = []
    if isinstance(obj, dict):
        # Look through all keys for port-like structures
        for key, value in obj.items():
            if isinstance(key, str):
                container_name = None
                
                # Try to find associated container name
                if isinstance(value, dict) and 'name' in value:
                    container_name = value.get('name')
                
                # Handle k: prefixed port specifications
                if key.startswith('k:') and 'containerPort' in key:
                    try:
                        port_str = key[2:].replace('\\"', '"')
                        port_data = json.loads(port_str)
                        if isinstance(port_data, dict) and 'containerPort' in port_data:
                            ports.append({
                                'port': port_data['containerPort'],
                                'container': container_name
                            })
                    except json.JSONDecodeError:
                        pass
                
                # Look for direct port specifications
                if isinstance(value, dict):
                    if 'containerPort' in value:
                        ports.append({
                            'port': value['containerPort'],
                            'container': container_name
                        })
                    
                # Recursively check nested objects
                if isinstance(value, (dict, list)):
                    nested_ports = extract_ports(value)
                    # If we have a container name, add it to any ports found without one
                    if container_name:
                        for port in nested_ports:
                            if not port.get('container'):
                                port['container'] = container_name
                    ports.extend(nested_ports)
                    
    elif isinstance(obj, list):
        for item in obj:
            ports.extend(extract_ports(item))
            
    return ports

def check_port_security(ports):
    """Check ports for security concerns"""
    concerns = []
    suspicious_ports = [22, 23, 3389, 445, 135, 137, 138, 139, 161, 162, 389, 636,
                       1433, 1521, 3306, 5432, 6379, 27017, 28017, 9443]
    
    for port_info in ports:
        port = port_info['port']
        container = port_info.get('container', 'unknown')
        
        if port in suspicious_ports:
            concerns.append(f"Suspicious port exposed: {port} [container: {container}]")
        if port < 1024 and port not in [80, 443]:
            concerns.append(f"Privileged port exposed: {port} [container: {container}]")
            
    return concerns

def check_security_concerns(obj):
    """Enhanced security check with aggressive nested structure traversal"""
    concerns = []
    
    if not obj or not isinstance(obj, dict):
        return concerns

    # Extract all container specs from the entire structure
    containers = extract_container_specs(obj)
    
    # Process each container's security context
    for container in containers:
        if not isinstance(container, dict):
            continue
            
        container_name = container.get('name', 'unknown')
        
        # Get container's security context
        security_context = container.get('securityContext', {})
        if isinstance(security_context, str):
            security_context = parse_k8s_field(security_context)
            
        if isinstance(security_context, dict):
            # Check for root user
            if security_context.get('runAsUser') == 0:
                concerns.append(f"Container explicitly configured to run as root [container: {container_name}]")
            if security_context.get('runAsNonRoot') == False:
                concerns.append(f"Container explicitly allows running as root [container: {container_name}]")
            
            # Check capabilities
            capabilities = security_context.get('capabilities', {})
            if isinstance(capabilities, dict):
                add_caps = capabilities.get('add', [])
                if 'ALL' in add_caps:
                    concerns.append(f"Container adds ALL capabilities [container: {container_name}]")
                dangerous_caps = ['SYS_ADMIN', 'NET_ADMIN', 'NET_RAW', 'SYS_PTRACE']
                for cap in add_caps:
                    if cap in dangerous_caps:
                        concerns.append(f"Container adds dangerous capability: {cap} [container: {container_name}]")

        # Volume Mount Checks using enhanced extraction
        volume_mounts = extract_volume_mounts(container)
        sensitive_paths = [
            '/proc', '/sys', '/var/run/docker.sock', '/var/run/crio.sock',
            '/etc/kubernetes', '/var/lib/kubelet', '/var/lib/etcd',
            '/etc/cni', '/opt/cni', '/var/lib/docker', '/root/.kube',
            '/root/.docker', '/home/admin/.kube', '/dev/mem', '/dev/kmem',
            '/dev/ports', '/.dockerenv', '/etc/shadow', '/etc/passwd',
            '/etc/ssh', '/etc/ssl', '/etc/kubernetes/pki'
        ]
        
        for mount_info in volume_mounts:
            mount = mount_info['mount']
            mount_path = mount.get('mountPath')
            if mount_path:
                for sensitive_path in sensitive_paths:
                    if mount_path.startswith(sensitive_path):
                        concerns.append(f"Sensitive path mounted: {mount_path} [container: {container_name}]")
                
                if not mount.get('readOnly', False):
                    concerns.append(f"Writeable volume mount: {mount_path} [container: {container_name}]")
        # Image Checks
        # Privilege Escalation Check
        if security_context.get('allowPrivilegeEscalation') == True:
            concerns.append(f"Container allows privilege escalation [container: {container_name}]")

        # Privileged Container Check
        if security_context.get('privileged') == True:
            concerns.append(f"Container runs in privileged mode [container: {container_name}]")

        # Read-only Root Filesystem Check
        if security_context.get('readOnlyRootFilesystem') == False:
            concerns.append(f"Container root filesystem is not read-only [container: {container_name}]")

        # Security Context Drop Capabilities Check
        if isinstance(capabilities, dict):
            if not capabilities.get('drop') or 'ALL' not in capabilities.get('drop', []):
                concerns.append(f"Container does not drop all capabilities by default [container: {container_name}]")

        # Resource Quota Checks (more specific)
        resources = container.get('resources', {})
        if not resources:
            concerns.append(f"No resource constraints specified [container: {container_name}]")
        else:
            limits = resources.get('limits', {})
            requests = resources.get('requests', {})
           
            if not limits.get('cpu'):
                concerns.append(f"No CPU limit set [container: {container_name}]")
            if not limits.get('memory'):
                concerns.append(f"No memory limit set [container: {container_name}]")
            if not requests.get('cpu'):
                concerns.append(f"No CPU request set [container: {container_name}]")
            if not requests.get('memory'):
                concerns.append(f"No memory request set [container: {container_name}]")

        # Liveness/Readiness Probe Checks
        if not container.get('livenessProbe'):
            concerns.append(f"No liveness probe configured [container: {container_name}]")
        if not container.get('readinessProbe'):
            concerns.append(f"No readiness probe configured [container: {container_name}]")

        # Specific Environment Variable Checks
        env_vars = container.get('env', [])
        sensitive_env_names = ['AWS_', 'KUBE_', 'PASS', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']
        for env in env_vars:
            if isinstance(env, dict) and 'name' in env:
                env_name = env['name']
                if any(sensitive in env_name.upper() for sensitive in sensitive_env_names):
                    concerns.append(f"Potentially sensitive environment variable used: {env_name} [container: {container_name}]")
        image = container.get('image', '')
        if isinstance(image, str):
            if ':latest' in image or not ':' in image:
                concerns.append(f"Using latest/floating tag [container: {container_name}]")
            if not image.startswith(('*.dkr.ecr.us-gov-east-1.amazonaws.com')):
                concerns.append(f"Image from untrusted registry: {image} [container: {container_name}]")

        # Resource Limit Checks
        resources = extract_field_recursive(container, 'resources')
        for resource in resources:
            if isinstance(resource, dict):
                if not resource.get('limits'):
                    concerns.append(f"No resource limits set [container: {container_name}]")
                if not resource.get('requests'):
                    concerns.append(f"No resource requests set [container: {container_name}]")


        # Command and Args Checks using enhanced extraction
        dangerous_commands = ['curl', 'wget', 'nc', 'ncat', 'netcat', 'nmap', 'ssh', 'telnet',
                            'bash', 'sh', 'ksh', 'csh', 'tsh', 'zsh']
        
        commands = extract_commands(container)
        for cmd_info in commands:
            cmd = cmd_info['cmd']
            if any(dangerous_cmd in cmd.lower() for dangerous_cmd in dangerous_commands):
                concerns.append(f"Potentially dangerous {cmd_info['type']}: {cmd} [container: {container_name}]")

    # Process pod-level security context
    def find_pod_security_context(obj):
        """Find the pod-level security context, avoiding container contexts"""
        if isinstance(obj, dict):
            # Only consider security contexts that are in a pod spec and not in a container
            for key in obj:
                if (key == 'spec' or key.startswith(('k:spec', 'f:spec'))) and 'securityContext' in obj:
                    if 'containers' not in obj and 'initContainers' not in obj:
                        return obj.get('securityContext')
            
            # Recursively search in all fields
            for key, value in obj.items():
                if isinstance(value, dict):
                    result = find_pod_security_context(value)
                    if result is not None:
                        return result
        return None

    # Pod Security Context Checks
    pod_security = find_pod_security_context(obj)
    if isinstance(pod_security, dict):
        if pod_security.get('hostNetwork'):
            concerns.append("Pod uses host network")
        if pod_security.get('hostPID'):
            concerns.append("Pod uses host PID namespace")
        if pod_security.get('hostIPC'):
            concerns.append("Pod uses host IPC namespace")
        if pod_security.get('runAsUser') == 0:
            concerns.append("Pod security context explicitly sets runAsUser: 0")
        if pod_security.get('runAsNonRoot') == False:
            concerns.append("Pod explicitly allows running as root")

    # Volume Checks using enhanced extraction
    volumes = extract_volumes(obj)
    for volume in volumes:
        if isinstance(volume, dict):
            # Host path volumes
            if host_path := volume.get('hostPath', {}).get('path'):
                concerns.append(f"Host path volume mounted: {host_path}")
            
            # Sensitive volume types
            if volume.get('secret'):
                secret_name = volume.get('secret', {}).get('name', 'unknown')
                if not volume.get('secret', {}).get('defaultMode') == 0o400:
                    concerns.append(f"Secret volume without restrictive permissions: {secret_name}")
            
            if volume.get('configMap'):
                config_name = volume.get('configMap', {}).get('name', 'unknown')
                concerns.append(f"ConfigMap mounted as volume: {config_name}")

            # Check for writable hostPath volumes
            if volume.get('hostPath', {}).get('type') not in ['Directory', 'File', 'Socket']:
                concerns.append(f"Writable hostPath volume: {volume.get('name', 'unknown')}")

    # Other pod-level checks

    spec = obj.get('spec', {})
    if isinstance(spec, str):
        spec = parse_k8s_field(spec)

    # Service Account Checks
    if spec.get('automountServiceAccountToken') != False:
        concerns.append("Pod automounts service account token (not explicitly disabled)")

    # Node Selector and Affinity Checks
    if not spec.get('nodeSelector') and not spec.get('affinity'):
        concerns.append("Pod has no node selector or affinity rules")

    # Namespace Checks
    metadata = obj.get('metadata', {})
    if not metadata.get('namespace') or metadata.get('namespace') == 'default':
        concerns.append("Resource in default namespace")

    # Label Checks
    if not metadata.get('labels'):
        concerns.append("Resource has no labels")

    # Pod Security Policy Checks
    if not metadata.get('annotations', {}).get('kubernetes.io/psp'):
        concerns.append("No Pod Security Policy specified")

    # Priority Class Check
    if not spec.get('priorityClassName'):
        concerns.append("No PriorityClass set")

    # Service Account Name Check
    if spec.get('serviceAccountName') == 'default':
        concerns.append("Using default ServiceAccount")

    # Host Aliases Check
    if spec.get('hostAliases'):
        concerns.append("Pod contains host aliases")

    # DNS Policy and Config Checks
    if spec.get('dnsPolicy') == 'ClusterFirstWithHostNet':
        concerns.append("Pod uses host network DNS policy")

    # Topology Spread Constraints
    if not spec.get('topologySpreadConstraints'):
        concerns.append("No topology spread constraints defined")

    # Security Context Additional Checks
    if pod_security:
        if pod_security.get('sysctls'):
            concerns.append("Pod modifies system settings through sysctls")
        if pod_security.get('fsGroup') == 0:
            concerns.append("Pod uses root fsGroup")
        if pod_security.get('supplementalGroups') and 0 in pod_security.get('supplementalGroups', []):
            concerns.append("Pod uses root supplemental group")

    return concerns

def parse_json_line(line):
    """Parse a single line containing JSON data"""
    try:
        # First, handle the outer JSON string
        first_decode = json.loads(line.strip())
        
        # Now try to parse the inner JSON
        if isinstance(first_decode, str):
            try:
                data = json.loads(first_decode)
            except json.JSONDecodeError:
                data = first_decode
        else:
            data = first_decode
        
        # Process both request and response objects
        request_obj = data.get('requestObject', {})
        response_obj = data.get('responseObject', {})
        
        # Extract ports from both objects with container context
        request_ports = extract_ports(request_obj)
        response_ports = extract_ports(response_obj)
        all_ports = request_ports + response_ports
        
        # Check ports for security concerns
        port_security_concerns = check_port_security(all_ports)
        
        # Process the rest of the data
        parsed_data = {
            'event_type': data.get('kind', 'Unknown'),
            'level': data.get('level', 'Unknown'),
            'stage': data.get('stage', 'Unknown'),
            'audit_id': data.get('auditID', ''),
            'verb': data.get('verb', 'Unknown'),
            'user': {
                'username': data.get('user', {}).get('username', ''),
                'groups': data.get('user', {}).get('groups', []),
                'uid': data.get('user', {}).get('uid', ''),
                'extra': data.get('user', {}).get('extra', {})
            },
            'source_ips': data.get('sourceIPs', []),
            'user_agent': data.get('userAgent', ''),
            'object_ref': {
                'resource': data.get('objectRef', {}).get('resource', ''),
                'namespace': data.get('objectRef', {}).get('namespace', ''),
                'name': data.get('objectRef', {}).get('name', ''),
                'uid': data.get('objectRef', {}).get('uid', ''),
                'api_group': data.get('objectRef', {}).get('apiGroup', ''),
                'api_version': data.get('objectRef', {}).get('apiVersion', ''),
                'resource_version': data.get('objectRef', {}).get('resourceVersion', ''),
                'subresource': data.get('objectRef', {}).get('subresource', '')
            },
            'security_concerns': {
                'ports': port_security_concerns,
                'other': check_security_concerns(request_obj) + check_security_concerns(response_obj)
            }
        }
        return parsed_data
        
    except json.JSONDecodeError as e:
        return {
            'error': f"JSON decode error: {str(e)}",
            'line_preview': line[:100] + "..." if len(line) > 100 else line
        }
    except Exception as e:
        return {
            'error': f"Unexpected error: {str(e)}",
            'line_preview': line[:100] + "..." if len(line) > 100 else line
        }

def print_summary(results):
    """Print a clean summary of the audit log findings with container context"""
    print("\n=== Audit Log Summary ===")
    print(f"Total events processed: {results['total_processed']}")
    print(f"Successful parses: {results['successful']}")
    print(f"Failed parses: {results['failed']}")
    print(f"Total security concerns found: {results['total_security_concerns']}")
    
    if results.get('events'):
        print("\n=== Notable Events ===")
        for event in results['events']:
            concerns = event.get('security_concerns', {})
            all_concerns = concerns.get('ports', []) + concerns.get('other', [])
            
            if all_concerns:  # Only print events with security concerns
                print(f"\nEvent Type: {event['event_type']}")
                print(f"User: {event['user']['username']}")
                print(f"Action: {event['verb']}")
                print(f"Namespace: {event.get('object_ref', {}).get('namespace', 'Unknown')}")
                print(f"Resource Name: {event.get('object_ref', {}).get('name', 'Unknown')}")
                print(f"Time: {event.get('timestamp', 'Unknown')}")
                
                # Group concerns by container
                container_concerns = {}
                non_container_concerns = []
                
                for concern in all_concerns:
                    # Check if the concern contains container context
                    if "[container:" in concern:
                        # Split on "[container:" and get the container name
                        parts = concern.split("[container:")
                        container_name = parts[1].split("]")[0].strip()
                        message = parts[0].strip()
                        
                        if container_name not in container_concerns:
                            container_concerns[container_name] = []
                        container_concerns[container_name].append(message)
                    else:
                        non_container_concerns.append(concern)
                
                # Print container-specific concerns
                if container_concerns:
                    print("\nContainer-specific concerns:")
                    for container, cont_concerns in container_concerns.items():
                        print(f"\nContainer: {container}")
                        for concern in cont_concerns:
                            print(f"  - {concern}")
                
                # Print non-container concerns
                if non_container_concerns:
                    print("\nPod-level concerns:")
                    for concern in non_container_concerns:
                        print(f"  - {concern}")
                
                print("-" * 50)

def process_file(filepath):
    """Process the audit log file"""
    results = []
    success_count = 0
    error_count = 0
    total_concerns = 0
    
    try:
        with open(filepath, 'r') as f:
            content = f.read()
            json_strings = [line.strip() for line in content.splitlines() if line.strip()]
            
            for i, json_str in enumerate(json_strings, 1):
                result = parse_json_line(json_str)
                if 'error' not in result:
                    # Count all security concerns
                    concerns = result.get('security_concerns', {})
                    concerns_count = len(concerns.get('ports', [])) + len(concerns.get('other', []))
                    total_concerns += concerns_count
                    
                    if concerns_count > 0:
                        print(f"\nFound {concerns_count} security concerns in event {i}")
                        
                    results.append(result)
                    success_count += 1
                else:
                    error_count += 1
                    print(f"Error on line {i}: {result['error']}")
                    
        return {
            'total_processed': success_count + error_count,
            'successful': success_count,
            'failed': error_count,
            'total_security_concerns': total_concerns,
            'events': results
        }
    except Exception as e:
        return {'error': f"File error: {str(e)}"}

def main():
    parser = argparse.ArgumentParser(description='Parse Kubernetes audit logs')
    parser.add_argument('input', help='File path')
    parser.add_argument('-p', '--pretty', action='store_true', help='Pretty print output')
    parser.add_argument('-j', '--json', action='store_true', help='Output complete JSON events to file')
    
    args = parser.parse_args()
    
    # Process security findings
    results = process_file(args.input)
    
    # Print summary
    print_summary(results)
    
    # If JSON output requested, write complete events
    if args.json and 'error' not in results:
        output_file = 'k8s_audit_events.json'
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nComplete JSON events written to: {output_file}")

if __name__ == "__main__":
    main()