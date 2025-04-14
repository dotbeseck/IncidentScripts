#!/usr/bin/env python3
# Enhanced PowerShell Deobfuscator
# This script analyzes obfuscated PowerShell scripts and extracts the hidden code

import re
import sys
import base64
import requests
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from queue import Queue
import threading

# Initialize colorama for colored output
init(autoreset=True)

# Global queue for thread results
result_queue = Queue()

# MITRE ATT&CK Technique mappings
MITRE_MAPPINGS = {
    # Credential Access
    r'mimikatz|dump|Get-Credential|ConvertTo-SecureString': 'T1003 - OS Credential Dumping',
    r'Get-ADUser|Get-ADGroupMember': 'T1087 - Account Discovery',
    r'Invoke-Kerberoast|Add-Type -AssemblyName System\.IdentityModel': 'T1558.003 - Kerberoasting',
    
    # Defense Evasion
    r'Set-MpPreference|Disable-WindowsOptionalFeature': 'T1562.001 - Impair Defenses: Disable or Modify Tools',
    r'New-ItemProperty|Set-ItemProperty|Remove-ItemProperty': 'T1112 - Modify Registry',
    r'Unblock-File': 'T1553.005 - Subvert Trust Controls: Mark-of-the-Web Bypass',
    r'Set-ExecutionPolicy': 'T1059.001 - PowerShell: ExecutionPolicy Bypass',
    
    # Execution
    r'Invoke-Expression|Invoke-Command': 'T1059.001 - PowerShell Command Invocation',
    r'Start-Process|Invoke-Item': 'T1204 - User Execution',
    
    # Additional techniques truncated for brevity
}
# Common PowerShell cmdlets and their descriptions (partial list)
common_cmdlets = {
    "New-Item": "Creates a new item.",
    "Invoke-WebRequest": "Gets content from a web page on the Internet.",
    "Invoke-Expression": "Runs commands or expressions on the local computer.",
    "Start-Process": "Starts one or more processes on the local computer.",
    # Many more cmdlets truncated for brevity
}

# Dictionary of common .NET classes and methods
dotnet_info = {
    "System.Net.WebClient": "Provides common methods for sending data to and receiving data from a resource identified by a URI.",
    "System.Convert": "Converts a base data type to another base data type.",
    # More entries truncated for brevity
}

def decode_base64_command(powershell_script):
    """Decode a base64-encoded PowerShell command"""
    try:
        # Check if this is a powershell command with -EncodedCommand/-E flag
        if re.search(r'powershell(.exe)?\s+(.+\s)?(-e|-ec|-encodedcommand)\s+', 
                     powershell_script, re.IGNORECASE):
            # Extract the base64 part after the flag
            match = re.search(r'(-e|-ec|-encodedcommand)\s+([A-Za-z0-9+/=]+)', 
                              powershell_script, re.IGNORECASE)
            if match:
                encoded_part = match.group(2)
            else:
                # Just take the last part of the command as potential base64
                encoded_part = powershell_script.split()[-1]
        else:
            # If no clear powershell command structure, assume the whole string might be base64
            encoded_part = powershell_script
        
        # Remove any whitespace
        encoded_part = encoded_part.strip()
        
        # Fix padding if needed
        padding = len(encoded_part) % 4
        if padding != 0:
            encoded_part += '=' * (4 - padding)
        
        # Decode the Base64 string
        try:
            decoded_bytes = base64.b64decode(encoded_part)
        except Exception as e:
            # Try an alternative approach - extract only valid base64 characters
            base64_chars = re.sub(r'[^A-Za-z0-9+/=]', '', encoded_part)
            padding = len(base64_chars) % 4
            if padding != 0:
                base64_chars += '=' * (4 - padding)
            decoded_bytes = base64.b64decode(base64_chars)
        
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
                return f"Error decoding command: Unable to decode with UTF-16-LE or UTF-8"
    except Exception as e:
        return f"Error decoding command: {str(e)}"

def is_base64(s):
    """Check if a string is likely base64 encoded"""
    try:
        # Check if the string contains only valid base64 characters and has valid padding
        if not re.match(r'^[A-Za-z0-9+/]*={0,2}$', s):
            return False
        
        # Try to decode it
        base64.b64decode(s)
        return True
    except Exception:
        return False

def extract_variables(powershell_script):
    """Extracts variables and their values from the PowerShell script"""
    variables = {}
    # Improved pattern to handle more complex variable assignments
    pattern = re.compile(r"\$(\w+)\s*=\s*([^;\r\n]+)")
    matches = pattern.findall(powershell_script)

    for match in matches:
        var_name = match[0]
        var_value = match[1].strip().strip("'\"")
        variables[var_name] = var_value
    return variables

def replace_variables(powershell_script, variables):
    """Replaces variables in the script with their actual values"""
    for var_name, var_value in variables.items():
        # Only replace if the value is a string and not too complex
        if isinstance(var_value, str) and not var_value.startswith('('):
            var_value_escaped = re.escape(var_value)
            powershell_script = re.sub(
                rf"\${var_name}\b", var_value_escaped, powershell_script
            )
    return powershell_script

# Network and information fetching functions omitted for brevity
def check_evasion_techniques(powershell_script):
    """Check for common malware evasion techniques"""
    evasion_techniques = []

    # Check for obfuscated commands
    if re.search(
        r"\-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD]|-[eE]", powershell_script
    ):
        evasion_techniques.append(("Use of encoded commands", Fore.RED))

    # Check for execution policy bypass
    if re.search(
        r"-[eE]x[eE]c[uU]t[iI]on[pP]ol[iI]cy\s+[bB]y[pP]ass|-[eE][pP]\s+[bB][yY]", powershell_script
    ):
        evasion_techniques.append(("Attempt to bypass execution policy", Fore.RED))

    # Check for hidden window execution
    if re.search(r"-[wW]indow[sS]tyle\s+[hH]idden|-[wW]\s+[hH]", powershell_script):
        evasion_techniques.append(("Attempt to run with hidden window", Fore.RED))

    # Check for use of aliases to obfuscate cmdlets
    alias_mappings = {
        "iex": "Invoke-Expression",
        "sal": "Set-Alias",
        "wget": "Invoke-WebRequest",
        "curl": "Invoke-WebRequest",
        "rv": "Remove-Variable",
        "saps": "Start-Process",
    }
    
    for alias_name in alias_mappings:
        if re.search(rf"\b{re.escape(alias_name)}\b", powershell_script, re.IGNORECASE):
            cmdlet_name = alias_mappings[alias_name]
            evasion_techniques.append(
                (f"Use of alias '{alias_name}' for {cmdlet_name}", Fore.YELLOW)
            )

    # More checks omitted for brevity

    return evasion_techniques
def process_variable_transformations(variables, powershell_script):
    """Process complex variable transformations including split-hex conversions"""
    transformed_variables = {}
    
    # Initialize transformed variables with original values
    for var_name, var_value in variables.items():
        transformed_variables[var_name] = {
            "original": var_value,
            "current": var_value,
            "transformations": []
        }
    
    # Look for variable transformations
    # Focus on the pattern in your uploaded file
    for line in powershell_script.split(';'):
        # Look for transformations in the format:
        # $var1 = ($var2 -split 'pattern' | % { transform }) -join ''
        if "-split" in line and "[char]" in line and "ToInt32" in line:
            # Extract variable names
            target_match = re.search(r'\$(\w+)\s*=', line)
            source_match = re.search(r'=\s*\(\$(\w+)\s*-split', line)
            
            if target_match and source_match:
                target_var = target_match.group(1)
                source_var = source_match.group(1)
                
                # Check if source variable exists
                if source_var in variables:
                    # Extract the base for conversion
                    base_match = re.search(r'ToInt32\(\$_\s*,\s*(\d+)\)', line)
                    base = 16  # Default to hex
                    if base_match:
                        base = int(base_match.group(1))
                    
                    source_value = variables[source_var]
                    
                    # Handle hex pair conversion
                    try:
                        # Split into pairs of characters
                        hex_pairs = [source_value[i:i+2] for i in range(0, len(source_value), 2)]
                        chars = []
                        for pair in hex_pairs:
                            if pair:  # Ensure we have a non-empty string
                                try:
                                    char_code = int(pair, base)
                                    chars.append(chr(char_code))
                                except ValueError:
                                    continue  # Skip invalid pairs
                        
                        result = ''.join(chars)
                        if target_var in transformed_variables:
                            transformed_variables[target_var]["current"] = result
                            transformed_variables[target_var]["transformations"].append(
                                f"Converted from hex pairs in ${source_var} to ASCII characters (base {base})"
                            )
                    except Exception as e:
                        if target_var in transformed_variables:
                            transformed_variables[target_var]["transformations"].append(
                                f"Failed to process transformation: {str(e)}"
                            )
    
    # Check for variables that are executed
    for var_name in variables:
        if re.search(rf'&\s*\${var_name}', powershell_script):
            if var_name in transformed_variables:
                transformed_variables[var_name]["transformations"].append("⚠️ THIS VARIABLE IS EXECUTED!")
    
    return transformed_variables
def analyze_powershell(powershell_script):
    """Enhanced analysis of PowerShell scripts with better deobfuscation"""
    original_script = powershell_script
    is_encoded = False

    # Check if the script is Base64 encoded
    if "-E " in powershell_script or "-e " in powershell_script or powershell_script.strip().lower().startswith('powershell -ec'):
        print(f"{Fore.YELLOW}Detected Base64 encoded command. Decoding...{Style.RESET_ALL}")
        decoded_script = decode_base64_command(powershell_script)
        if not decoded_script.startswith("Error decoding command:"):
            powershell_script = decoded_script
            is_encoded = True
        else:
            print(f"{Fore.RED}{decoded_script}{Style.RESET_ALL}")
            return  # Exit if decoding failed

    # Extract and analyze variables
    variables = extract_variables(powershell_script)
    
    # Process transformed variables
    transformed_variables = process_variable_transformations(variables, powershell_script)
    
    # Find variables that are executed
    executed_vars = []
    for var_name, info in transformed_variables.items():
        if any("EXECUTED" in t for t in info["transformations"]):
            executed_vars.append(var_name)
    
    # Extensive analysis and display code omitted for brevity

    return {
        "original_script": original_script,
        "decoded_script": powershell_script if is_encoded else original_script,
        "variables": variables,
        "transformed_variables": transformed_variables,
        "executed_variables": executed_vars
    }

# Main function
def main():
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python script.py <path_to_powershell_script>")
        sys.exit(1)

    ps1_file_path = sys.argv[1]
    try:
        with open(ps1_file_path, "r") as file:
            powershell_script = file.read()
        analyze_powershell(powershell_script)
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File '{ps1_file_path}' not found.")
    except Exception as e:
        print(f"{Fore.RED}An error occurred: {str(e)}")

if __name__ == "__main__":
    main()



