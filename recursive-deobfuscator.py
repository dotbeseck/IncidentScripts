#!/usr/bin/env python3
"""
Recursive Deobfuscator - Handles multiple layers of obfuscated Python code commonly seen in python malware. If the code uses base64, reverse strings, and zlib, this should iterate over and find the actual python
Usage: python recursive_deobfuscator.py [obfuscated_file.py]
"""

import base64
import zlib
import sys
import re
import os

def is_likely_obfuscated(content):
    """
    Check if the content is likely to be another layer of obfuscation
    """
    # Look for common obfuscation patterns
    patterns = [
        # Lambda functions for deobfuscation
        r'lambda\s+[_a-zA-Z0-9]+\s*:\s*__import__\(.*\)',
        # Base64 and zlib usage
        r'base64.*decode',
        r'zlib.*decompress',
        # Exec functions
        r'exec\s*\(',
        # Common obfuscated variable names
        r'__\s*=',
        r'_\s*=',
        # Long base64-like strings
        r'b\'[A-Za-z0-9+/=]{100,}\'',
        r"b\"[A-Za-z0-9+/=]{100,}\""
    ]
    
    for pattern in patterns:
        if re.search(pattern, content):
            return True
    
    # Check if the content is mostly printable ASCII characters
    # If it contains a lot of binary or strange characters, lets keep going
    printable = sum(c.isalnum() or c.isspace() for c in content)
    if printable < len(content) * 0.8:  # If less than 80% is printable
        return True
    
    return False

def extract_obfuscated_string(code):
    """
    Extract the obfuscated string from common patterns
    """
    # Pattern 1: exec((_)(b'...'))
    match = re.search(r"exec\(\(_\)\(b[\"']([^\"']+)[\"']\)\)", code)
    if match:
        return match.group(1)
    
    # Pattern 2: exec(__import__(...).decompress(...))
    match = re.search(r"exec\(__import__\(['\"]zlib['\"]\)\.decompress\(__import__\(['\"]base64['\"]\)\.b64decode\(['\"]([^\"']+)['\"]\)\)\)", code)
    if match:
        return match.group(1)
    
    # Pattern 3: Just the base64 string
    if re.match(r'^[A-Za-z0-9+/=]+$', code.strip()):
        return code
    
    # If no patterns match, return the original code
    return code

def deobfuscate_layer(obfuscated_string):
    """
    Deobfuscate a single layer of obfuscation
    """
    try:
        # First try the standard pattern: reverse + base64 + zlib
        reversed_string = obfuscated_string[::-1]
        decoded_data = base64.b64decode(reversed_string)
        decompressed_data = zlib.decompress(decoded_data)
        return decompressed_data.decode('utf-8', errors='replace')
    except Exception as e1:
        try:
            # Try direct base64 + zlib (no reversing)
            decoded_data = base64.b64decode(obfuscated_string)
            decompressed_data = zlib.decompress(decoded_data)
            return decompressed_data.decode('utf-8', errors='replace')
        except Exception as e2:
            # Try just base64 (no zlib)
            try:
                decoded_data = base64.b64decode(obfuscated_string)
                return decoded_data.decode('utf-8', errors='replace')
            except Exception as e3:
                return f"Error: Failed to deobfuscate. Layer probs uses something else.\nErrors:\n{str(e1)}\n{str(e2)}\n{str(e3)}"

def recursive_deobfuscate(code, max_depth=300):
    """
    Recursively deobfuscate code through multiple layers
    """
    result = code
    current_depth = 0
    
    print("Starting recursive deobfuscation...")
    
    while current_depth < max_depth:
        print(f"Attempting to deobfuscate layer {current_depth + 1}...")
        
        # Extract the obfuscated string pattern
        obfuscated_string = extract_obfuscated_string(result)
        
        # If extraction didn't change anything, try again with full content
        if obfuscated_string == result and not obfuscated_string.startswith("Error:"):
            # Either it's the raw string or we couldn't extract it properly
            pass
        
        # Deobfuscate this layer
        deobfuscated = deobfuscate_layer(obfuscated_string)
        
        # Check if we made progress
        if deobfuscated.startswith("Error:"):
            print(f"Failed to deobfuscate layer {current_depth + 1}.")
            print(deobfuscated)
            break
        
        # Check if we've reached the end of obfuscation
        if not is_likely_obfuscated(deobfuscated):
            print(f"Successfully deobfuscated {current_depth + 1} layers!")
            return deobfuscated
        
        # Update for next iteration
        result = deobfuscated
        current_depth += 1
        
        # Display a short preview of the current result
        preview = result[:100] + "..." if len(result) > 100 else result
        print(f"Layer {current_depth} result (preview): {preview}")
    
    if current_depth >= max_depth:
        print(f"Reached maximum recursion depth ({max_depth}). The code might have more layers.")
    
    return result

def main():
    if len(sys.argv) > 1:
        # Get input from file
        filename = sys.argv[1]
        if os.path.isfile(filename):
            with open(filename, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
        else:
            code = sys.argv[1]  # Use the argument directly as code
    else:
        # Use the embedded example if no file is provided
        code = "Check virustotal for main5_504.py"
    
    # Perform deobfuscation
    deobfuscated_code = recursive_deobfuscate(code)
    
    # Write the result to a file
    output_file = "deobfuscated_code.py"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(deobfuscated_code)
    
    print(f"\nDeobfuscated code has been written to {output_file}")
    
    # Also print a preview
    print("\nPreview of deobfuscated code:")
    print("=" * 80)
    preview_length = min(1000, len(deobfuscated_code))
    print(deobfuscated_code[:preview_length])
    if len(deobfuscated_code) > preview_length:
        print("\n... (output truncated) ...")
    print("=" * 80)

if __name__ == "__main__":
    main()
