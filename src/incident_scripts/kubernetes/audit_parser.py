#!/usr/bin/env python3
import json
import sys
import argparse
from incident_scripts.utils.logger import setup_logger
from incident_scripts.utils.config_loader import load_config

logger = setup_logger(__name__)
config = load_config()

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