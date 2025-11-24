#!/usr/bin/env python3
# Simple PowerShell Decoder - focuses just on decoding your specific file

import re
import sys
import base64

def decode_base64_command(encoded_command):
    """Decode a base64-encoded PowerShell command"""
    try:
        # Clean up the command - extract just the base64 part if needed
        if "-E " in encoded_command or "-e " in encoded_command:
            parts = encoded_command.split("-E ", 1)
            if len(parts) > 1:
                encoded_command = parts[1].strip()
            else:
                parts = encoded_command.split("-e ", 1)
                if len(parts) > 1:
                    encoded_command = parts[1].strip()
        
        # Remove any whitespace
        encoded_command = encoded_command.strip()
        
        # Fix padding if needed
        padding = len(encoded_command) % 4
        if padding != 0:
            encoded_command += '=' * (4 - padding)
        
        # Decode the Base64 string
        decoded_bytes = base64.b64decode(encoded_command)
        
        # Try UTF-16-LE first (standard for PowerShell encoding)
        try:
            decoded_command = decoded_bytes.decode('utf-16-le')
            return decoded_command
        except UnicodeDecodeError:
            # Fall back to UTF-8 if UTF-16-LE fails
            try:
                decoded_command = decoded_bytes.decode('utf-8')
                return decoded_command
            except UnicodeDecodeError:
                return "Error: Unable to decode with UTF-16-LE or UTF-8"
    except Exception as e:
        return f"Error decoding command: {str(e)}"

def decode_hex_pairs(hex_string, base=16):
    """Decode a string of hex pairs to ASCII characters"""
    try:
        # Split into pairs of characters
        hex_pairs = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]
        
        # Convert each pair from hex to ASCII
        result = ""
        for pair in hex_pairs:
            if len(pair) == 2:  # Ensure we have a complete pair
                try:
                    char_code = int(pair, base)
                    result += chr(char_code)
                except ValueError:
                    pass  # Skip invalid pairs
        
        return result
    except Exception as e:
        return f"Error decoding hex pairs: {str(e)}"

def extract_hex_transformation(decoded_script):
    """Look for the specific transformation pattern and extract/decode the content"""
    var_match = re.search(r'\$(\w+)\s*=\s*[\'"]([0-9A-Fa-f]+)[\'"]', decoded_script)
    if not var_match:
        return "No hex string variable found"
    
    hex_var_name = var_match.group(1)
    hex_string = var_match.group(2)
    
    # Look for the transformation pattern
    transform_match = re.search(
        r'\$(\w+)\s*=\s*\(\$' + re.escape(hex_var_name) + r'\s*-split\s*[\'"](?:\(\?<=\\\\G\\.\\.\)|.)[\'"].*\[char\].*ToInt32.*16',
        decoded_script
    )
    
    if transform_match:
        target_var = transform_match.group(1)
        decoded_content = decode_hex_pairs(hex_string, 16)
        return f"Variable ${target_var} contains the decoded content:\n\n{decoded_content}"
    
    # If pattern not found, just decode the hex string anyway
    decoded_content = decode_hex_pairs(hex_string, 16)
    return f"Hex string ${hex_var_name} decoded:\n\n{decoded_content}"

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_powershell_script>")
        sys.exit(1)

    ps1_file_path = sys.argv[1]
    try:
        with open(ps1_file_path, "r") as file:
            powershell_script = file.read()
        
        # Step 1: Print the original script
        print("Original Script:")
        print(powershell_script)
        print("\n" + "-"*50 + "\n")
        
        # Step 2: Decode base64 if present
        print("Attempting to decode base64...")
        if "-E " in powershell_script or "-e " in powershell_script:
            decoded_script = decode_base64_command(powershell_script)
            print("Decoded Script:")
            print(decoded_script)
            print("\n" + "-"*50 + "\n")
            
            # Step 3: Look for hex transformation
            print("Looking for hex transformations...")
            result = extract_hex_transformation(decoded_script)
            print(result)
        else:
            print("No base64 encoding detected.")
            
    except FileNotFoundError:
        print(f"Error: File '{ps1_file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
