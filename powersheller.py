import re
import requests
import sys
from bs4 import BeautifulSoup
from colorama import init, Fore, Style
from queue import Queue
import threading
import base64

# Initialize colorama
init(autoreset=True)

result_queue = Queue()


def decode_base64_command(powershell_script):
    """Decode a base64-encoded PowerShell command"""
    try:
        # Remove any whitespace and the 'powershell -EC' prefix if present
        cleaned_command = powershell_script.split()[-1]
        
        # Decode the Base64 string
        decoded_bytes = base64.b64decode(cleaned_command)
        
        # Convert the bytes to a string using UTF-16 Little Endian encoding
        decoded_command = decoded_bytes.decode('utf-16-le')
        return decoded_command
    except Exception as e:
        return f"Error decoding command: {str(e)}"

def is_base64(s):
    try:
        # Check if the string is Base64 encoded
        return base64.b64encode(base64.b64decode(s)).decode() == s
    except Exception:
        return False

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
    r'Invoke-Expression|IEX|Invoke-Command': 'T1059.001 - PowerShell',
    r'Start-Process|Invoke-Item': 'T1204 - User Execution',
    
    # Persistence
    r'New-Service|Set-Service': 'T1543.003 - Create or Modify System Process: Windows Service',
    r'New-ScheduledTask|Register-ScheduledTask': 'T1053.005 - Scheduled Task',
    r'New-LocalUser|Add-LocalGroupMember': 'T1136 - Create Account',
    
    # Discovery
    r'Get-Process|Get-Service|Get-Item|Get-ChildItem': 'T1057 - Process Discovery',
    r'Get-WmiObject|Get-CimInstance': 'T1047 - Windows Management Instrumentation',
    r'Test-NetConnection|Invoke-WebRequest': 'T1016 - System Network Configuration Discovery',
    
    # Lateral Movement
    r'New-PSSession|Enter-PSSession': 'T1021.006 - Remote Services: Windows Remote Management',
    r'Invoke-WMIMethod.*Win32_Process': 'T1047 - Windows Management Instrumentation',
    
    # Collection
    r'Get-Clipboard': 'T1115 - Clipboard Data',
    r'Compress-Archive': 'T1560 - Archive Collected Data',
    
    # Command and Control
    r'Invoke-WebRequest|DownloadString|Net\.WebClient': 'T1105 - Ingress Tool Transfer',
    
    # Impact
    r'Remove-Item|Clear-Content': 'T1485 - Data Destruction',
    
    # Additional Techniques
    r'Set-Location': 'T1005 - Data from Local System',
    r'Get-ADDomain|Get-ADForest': 'T1482 - Domain Trust Discovery',
    r'Get-DnsClientServerAddress': 'T1016 - System Network Configuration Discovery',
    r'Invoke-Mimikatz': 'T1003.001 - LSASS Memory',
    r'Invoke-BloodHound|Get-BloodHoundData': 'T1087 - Account Discovery',
    r'ConvertTo-SID|ConvertFrom-SID': 'T1087 - Account Discovery',
}

def detect_mitre_atomic(powershell_script):
    detected_techniques = set()
    for pattern, technique in MITRE_MAPPINGS.items():
        if re.search(pattern, powershell_script, re.IGNORECASE):
            detected_techniques.add(technique)
    return list(detected_techniques)

def fetch_cmdlet_from_url(cmdlet, base_url):
    """Fetches cmdlet information from a specific base URL."""
    url = f"{base_url}/{cmdlet.lower()}?view=powershell-7.2"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            description = soup.find("meta", {"name": "description"})
            if description:
                result_queue.put((cmdlet, description["content"]))
                return
        result_queue.put((cmdlet, None))
    except requests.RequestException as e:
        print(
            f"{Fore.YELLOW}Warning: Error fetching info for {cmdlet} from {base_url}: {str(e)}"
        )
        result_queue.put((cmdlet, None))


def threaded_cmdlet_lookup(cmdlet):
    """Fetch cmdlet information from multiple sources concurrently."""
    base_urls = [
        "https://learn.microsoft.com/en-us/powershell/module",
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core",
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility",
        "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management",
    ]

    threads = []
    for base_url in base_urls:
        thread = threading.Thread(target=fetch_cmdlet_from_url, args=(cmdlet, base_url))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    while not result_queue.empty():
        cmdlet, description = result_queue.get()
        if description:
            return description
    return None


def fetch_cmdlet_info(cmdlet):
    """Fetch information about a PowerShell cmdlet."""
    online_info = threaded_cmdlet_lookup(cmdlet)
    if online_info:
        return online_info

    common_cmdlets = {
        "New-Item": "Creates a new item.",
        "Join-Path": "Combines a path and a child path.",
        "Add-Type": "Adds a Microsoft .NET class to a PowerShell session.",
        "Get-ChildItem": "Gets the items and child items in one or more specified locations.",
        "Set-Location": "Sets the current working location to a specified location.",
        "Invoke-WebRequest": "Gets content from a web page on the Internet.",
        "ConvertTo-Json": "Converts an object to a JSON-formatted string.",
        "ConvertFrom-Json": "Converts a JSON-formatted string to a custom object.",
        "Get-Process": "Gets the processes that are running on the local computer.",
        "Sort-Object": "Sorts objects by property values.",
        "Select-Object": "Selects specified properties of an object or set of objects.",
        "Where-Object": "Selects objects from a collection based on their property values.",
        "ForEach-Object": "Performs an operation against each item in a collection of input objects.",
        "Get-Content": "Gets the content of the item at the specified location.",
        "Set-Content": "Writes or replaces the content in an item with new content.",
        "Out-File": "Sends output to a file.",
        "Get-Item": "Gets the item at the specified location.",
        "Remove-Item": "Deletes the specified items.",
        "Test-Path": "Determines whether all elements of a path exist.",
        "New-Object": "Creates an instance of a Microsoft .NET Framework or COM object.",
        "Get-Member": "Gets the properties and methods of objects.",
        "Measure-Object": "Calculates the numeric properties of objects, and the characters, words, and lines in string objects.",
        "Compare-Object": "Compares two sets of objects.",
        "Group-Object": "Groups objects that contain the same value for specified properties.",
        "Export-Csv": "Converts objects into a series of comma-separated value (CSV) strings and saves the strings to a file.",
        "Import-Csv": "Creates table-like custom objects from the items in a CSV file.",
        "Invoke-Expression": "Runs commands or expressions on the local computer.",
        "Start-Process": "Starts one or more processes on the local computer.",
        "Stop-Process": "Stops one or more running processes.",
        "New-ItemProperty": "Creates a new property for an item and sets its value.",
        "Set-ItemProperty": "Sets the value of a property of an item.",
        "Get-WmiObject": "Gets instances of Windows Management Instrumentation (WMI) classes or information about the available classes.",
        "Invoke-Command": "Runs commands on local and remote computers.",
        "Get-Service": "Gets the services on a local or remote computer.",
        "Start-Service": "Starts one or more stopped services.",
        "Stop-Service": "Stops one or more running services.",
        "Get-EventLog": "Gets the events in an event log, or a list of the event logs, on the local or remote computers.",
        "Write-EventLog": "Writes an event to an event log.",
        "Get-Help": "Displays information about PowerShell commands and concepts.",
        "Get-Command": "Gets all commands.",
        "Get-Module": "Gets the modules that have been imported or that can be imported into the current session.",
        "Import-Module": "Adds modules to the current session.",
        "Export-ModuleMember": "Specifies the module members that are exported.",
        "New-Module": "Creates a new dynamic module that exists only in memory.",
        "New-PSSession": "Creates a persistent connection to a local or remote computer.",
        "Enter-PSSession": "Starts an interactive session with a remote computer.",
        "Exit-PSSession": "Ends an interactive session with a remote computer.",
        "Invoke-RestMethod": "Sends an HTTP or HTTPS request to a RESTful web service.",
        "Out-Null": "Sends output to $null, effectively deleting it.",
        "Split-Path": "Returns the specified part of a path.",
        "Get-Random": "Gets a random number, selects random objects from a collection, or shuffles a collection randomly.",
    }

    if cmdlet in common_cmdlets:
        return common_cmdlets[cmdlet]

    if "-" in cmdlet and not cmdlet.startswith(
        ("Get-", "Set-", "New-", "Remove-", "Invoke-", "ConvertTo-", "ConvertFrom-")
    ):
        return f"Likely a custom function defined in the script. No standard documentation available."

    return f"No information found for {cmdlet}. It might be a custom function or cmdlet from a third-party module."


def extract_variables(powershell_script):
    """Extracts variables and their values from the PowerShell script"""
    variables = {}
    pattern = re.compile(r"\$(\w+)\s*=\s*([^;\n]+)")
    matches = pattern.findall(powershell_script)

    for match in matches:
        var_name = match[0]
        var_value = match[1].strip().strip("'\"")
        variables[var_name] = var_value
    return variables


def replace_variables(powershell_script, variables):
    """Replaces variables in the script with their actual values"""
    for var_name, var_value in variables.items():
        var_value_escaped = re.escape(var_value)
        powershell_script = re.sub(
            rf"\${var_name}\b", var_value_escaped, powershell_script
        )
    return powershell_script


def online_dotnet_lookup(dotnet_item):
    """Attempt to fetch .NET class or method information from Microsoft Docs"""
    base_url = "https://docs.microsoft.com/en-us/dotnet/api/"
    url = f"{base_url}{dotnet_item.lower()}?view=netframework-4.8"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            description = soup.find("meta", {"name": "description"})
            if description:
                return description["content"]
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}Warning: Error fetching info for {dotnet_item}: {str(e)}")
    return None


def fetch_dotnet_info(dotnet_item):
    """Fetch information about a .NET class or method"""
    online_info = online_dotnet_lookup(dotnet_item)
    if online_info:
        return online_info

    # Fallback to local dictionary if online lookup fails
    dotnet_info = {
        "System.Net.WebClient": "Provides common methods for sending data to and receiving data from a resource identified by a URI.",
        "System.Convert": "Converts a base data type to another base data type.",
        "System.Text.Encoding": "Represents a character encoding.",
        "System.Reflection.Assembly": "Represents an assembly, which is a reusable, versionable, and self-describing building block of a common language runtime application.",
        "System.Diagnostics.Process": "Provides access to local and remote processes and enables you to start and stop local system processes.",
        "System.Net.ServicePointManager": "Provides connection management for HTTP connections.",
        "System.Environment": "Provides information about, and means to manipulate, the current environment and platform.",
        "System.IO.File": "Provides static methods for the creation, copying, deletion, moving, and opening of files.",
        "System.IO.Compression.ZipFile": "Provides static methods for creating, extracting, and opening zip archives.",
        "System.Management.Automation.PSObject": "Provides a way to access the public properties of an object.",
        "System.Management.Automation.ScriptBlock": "Represents a unit of executable PowerShell script.",
        "System.Security.Cryptography.AesManaged": "Provides a managed implementation of the Advanced Encryption Standard (AES) symmetric algorithm.",
        "System.Security.Cryptography.RSACryptoServiceProvider": "Provides an implementation of the RSA algorithm.",
        "System.DirectoryServices.ActiveDirectory.Domain": "Represents an Active Directory Domain Services domain.",
        "System.Runtime.InteropServices.Marshal": "Provides a collection of methods for allocating unmanaged memory, copying unmanaged memory blocks, and converting managed to unmanaged types.",
    }
    return dotnet_info.get(
        dotnet_item, f"No detailed information available for {dotnet_item}"
    )


def analyze_variable_content(var_name, var_value, powershell_script):
    """Analyze the content and usage of a specific variable"""
    analysis = []

    if re.search(r"HKCU:\\\\|HKLM:\\\\", var_value, re.IGNORECASE):
        analysis.append("Contains a registry path")
        if re.search(
            r"\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
            var_value,
            re.IGNORECASE,
        ):
            analysis.append("Points to the Run key (potential persistence mechanism)")
    usage_analysis = []
    if re.search(rf"\${var_name}.*New-ItemProperty", powershell_script):
        usage_analysis.append("Used to create or modify registry values")

    if re.search(rf"\${var_name}.*Set-ItemProperty", powershell_script):
        usage_analysis.append("Used to set registry values")
    # Check if the variable is assigned a command or expression
    if var_value.strip().startswith("(") and var_value.strip().endswith(")"):
        analysis.append("Contains a command or expression")

        # Analyze the content of the command/expression
        if "New-Object" in var_value:
            if "System.Net.WebClient" in var_value:
                analysis.append("Creates a WebClient object")
            elif "System.IO." in var_value:
                analysis.append("Creates an IO-related object")
            # Add more specific object creation checks as needed

        if "DownloadString" in var_value:
            analysis.append("Downloads content from a URL")

        if "FromBase64String" in var_value:
            analysis.append("Decodes Base64 string")

        # Add more specific command/expression analyses as needed

    # Check if the variable contains a URL
    elif re.match(r"https?://", var_value):
        analysis.append("Contains a URL")

    # Check if the variable contains what looks like Base64 data
    elif re.match(r"^[A-Za-z0-9+/]{50,}={0,2}$", var_value):
        analysis.append("Contains likely Base64-encoded data")

    # Check if the variable contains a file path
    elif "\\" in var_value or "/" in var_value:
        analysis.append("Contains a file path")

    # Analyze how the variable is used in the script
    usage_analysis = []
    if re.search(rf"\${var_name}\s*=\s*Get-Random", powershell_script):
        usage_analysis.append("Assigned a random value")

    if re.search(rf"\${var_name}.*DownloadString", powershell_script):
        usage_analysis.append("Used to download content")

    if re.search(
        rf"\${var_name}.*(Start-Process|Invoke-Expression)", powershell_script
    ):
        usage_analysis.append("Used in command execution")

    if re.search(
        rf"\${var_name}.*(New-ItemProperty|Set-ItemProperty).*HKCU|HKLM",
        powershell_script,
    ):
        usage_analysis.append("Used in registry operations")

    if usage_analysis:
        analysis.extend(usage_analysis)

    return "; ".join(analysis) if analysis else "Purpose unclear or general variable"


def breakdown_variables(variables, powershell_script):
    """Provide a detailed analysis for each variable based on its content and usage in the script"""
    variable_info = {}

    for var_name, var_value in variables.items():
        purpose = analyze_variable_content(var_name, var_value, powershell_script)

        variable_info[var_name] = {"value": var_value, "purpose": purpose}

    return variable_info


def online_dotnet_lookup(dotnet_item):
    """Attempt to fetch .NET class or method information from Microsoft Docs"""
    base_url = "https://docs.microsoft.com/en-us/dotnet/api/"
    url = f"{base_url}{dotnet_item.lower()}?view=netframework-4.8"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            description = soup.find("meta", {"name": "description"})
            if description:
                return description["content"]
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}Warning: Error fetching info for {dotnet_item}: {str(e)}")
    return None

def breakdown_script(powershell_script):
    """Detailed analysis and breakdown of PowerShell actions"""
    breakdown = []
    cmdlets_used = set(re.findall(r"(\w+-\w+)", powershell_script))
    dotnet_items_used = set(
        re.findall(r"(System\.\w+(?:\.\w+)*(?:::[\w.]+)?)", powershell_script)
    )

    # General analysis
    if re.search(
        r"(New-ItemProperty|Set-ItemProperty).*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        powershell_script,
        re.IGNORECASE,
    ):
        breakdown.append(("Modifies the Run key for persistence", Fore.RED))

    if any(
        cmd in cmdlets_used
        for cmd in ["Invoke-WebRequest", "DownloadString", "Net.WebClient"]
    ):
        breakdown.append(("Downloads content from the internet", Fore.RED))

    if any(cmd in cmdlets_used for cmd in ["Set-Content", "Add-Content", "Out-File"]):
        breakdown.append(("Writes data to a file", Fore.YELLOW))

    if "Compression.ZipFile" in powershell_script or "Expand-Archive" in cmdlets_used:
        breakdown.append(("Handles ZIP archive operations", Fore.YELLOW))

    if "Start-Process" in cmdlets_used or "Invoke-Expression" in cmdlets_used:
        breakdown.append(("Executes commands or starts processes", Fore.RED))

    if "FromBase64String" in powershell_script:
        breakdown.append(("Decodes Base64-encoded data", Fore.YELLOW))

    if "Get-Random" in cmdlets_used:
        breakdown.append(("Generates random values", Fore.YELLOW))

    if "Get-WmiObject" in cmdlets_used or "Get-CimInstance" in cmdlets_used:
        breakdown.append(("Gathers system information", Fore.YELLOW))

    # PowerShell Cmdlets analysis
    breakdown.append(("PowerShell Cmdlets Used:", Fore.GREEN))
    for cmdlet in sorted(cmdlets_used):
        info = fetch_cmdlet_info(cmdlet)
        breakdown.append((f"{Fore.BLUE}{cmdlet}: {Fore.GREEN}{info}", Style.DIM))

    # .NET Methods and Classes analysis
    if dotnet_items_used:
        breakdown.append((".NET Methods and Classes Used:", Fore.GREEN))
        for dotnet_item in sorted(dotnet_items_used):
            info = fetch_dotnet_info(dotnet_item)
            breakdown.append((f"  {dotnet_item}: {info}", Fore.MAGENTA))

    return breakdown


def check_mitre_attack_techniques(powershell_script):
    """Check for common MITRE ATT&CK techniques"""
    techniques = []

    # T1059.001 - PowerShell
    if re.search(r"-[eE]nc[oO]ded[cC]ommand", powershell_script):
        techniques.append(("T1059.001", "PowerShell: Use of encoded commands"))

    # T1003 - Credential Dumping
    if re.search(
        r"(Get-Process\s+lsass|Out-Minidump|Invoke-Mimikatz)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            ("T1003", "Credential Dumping: Possible attempt to dump credentials")
        )

    # T1112 - Modify Registry
    if re.search(
        r"(New-ItemProperty|Set-ItemProperty|Remove-ItemProperty)", powershell_script
    ):
        techniques.append(("T1112", "Modify Registry: Registry modifications detected"))

    # T1057 - Process Discovery
    if "Get-Process" in powershell_script:
        techniques.append(("T1057", "Process Discovery: Enumerating processes"))

    # T1082 - System Information Discovery
    if re.search(
        r"(Get-WmiObject\s+Win32_OperatingSystem|Get-ComputerInfo)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            ("T1082", "System Information Discovery: Gathering system information")
        )

    # T1140 - Deobfuscate/Decode Files or Information
    if re.search(
        r"(FromBase64String|System\.Text\.Encoding\.UTF8\.GetString)", powershell_script
    ):
        techniques.append(
            (
                "T1140",
                "Deobfuscate/Decode Files or Information: Decoding Base64 or encoded content",
            )
        )

    # T1105 - Ingress Tool Transfer
    if re.search(
        r"(Invoke-WebRequest|Net\.WebClient|Start-BitsTransfer)", powershell_script
    ):
        techniques.append(
            ("T1105", "Ingress Tool Transfer: Downloading content from the internet")
        )

    # T1053 - Scheduled Task/Job
    if re.search(
        r"(Register-ScheduledTask|New-ScheduledTaskAction)", powershell_script
    ):
        techniques.append(
            ("T1053", "Scheduled Task/Job: Creating or modifying scheduled tasks")
        )

    # T1036 - Masquerading
    if re.search(r"(Set-ItemProperty.*\.exe|Rename-Item.*\.exe)", powershell_script):
        techniques.append(
            ("T1036", "Masquerading: Possible attempt to disguise executables")
        )

    # T1070 - Indicator Removal on Host
    if re.search(r"(Clear-EventLog|Remove-Item\s+.*\\.*\.log)", powershell_script):
        techniques.append(
            ("T1070", "Indicator Removal on Host: Clearing logs or deleting files")
        )

    # T1027 - Obfuscated Files or Information
    if re.search(r"(ConvertTo-SecureString|-join|ForEach|%{\$_})", powershell_script):
        techniques.append(
            (
                "T1027",
                "Obfuscated Files or Information: Possible obfuscation techniques",
            )
        )

    # T1218 - Signed Binary Proxy Execution
    if re.search(
        r"(rundll32\.exe|regsvr32\.exe|certutil\.exe)", powershell_script, re.IGNORECASE
    ):
        techniques.append(
            (
                "T1218",
                "Signed Binary Proxy Execution: Use of system binaries to proxy execution",
            )
        )

    # T1055 - Process Injection
    if re.search(
        r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread)", powershell_script
    ):
        techniques.append(
            ("T1055", "Process Injection: Possible use of process injection techniques")
        )

    # T1497 - Virtualization/Sandbox Evasion
    if re.search(
        r"(Get-WmiObject\s+Win32_ComputerSystem|Get-CimInstance\s+Win32_ComputerSystem)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            (
                "T1497",
                "Virtualization/Sandbox Evasion: Checking for virtualization artifacts",
            )
        )

    # T1518 - SOFTWARE Discovery
    if re.search(
        r"(Get-ItemProperty\s+HKLM:\SOFTWARE|Get-WmiObject\s+Win32_Product)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            ("T1518", "SOFTWARE Discovery: Enumerating installed software")
        )

    # T1087 - Account Discovery
    if re.search(
        r"(Get-LocalUser|Get-LocalGroup|Net\s+User)", powershell_script, re.IGNORECASE
    ):
        techniques.append(("T1087", "Account Discovery: Enumerating user accounts"))

    # T1021 - Remote Services
    if re.search(r"(New-PSSession|Enter-PSSession|Invoke-Command)", powershell_script):
        techniques.append(("T1021", "Remote Services: Use of PowerShell remoting"))

    # T1562 - Impair Defenses
    if re.search(
        r"(Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true|New-NetFirewallRule)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            ("T1562", "Impair Defenses: Attempting to disable security controls")
        )

    # T1547 - Boot or Logon Autostart Execution
    if re.search(
        r"(New-ItemProperty.*Run|New-ItemProperty.*RunOnce)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            ("T1547", "Boot or Logon Autostart Execution: Adding autostart entries")
        )

    # T1552 - Unsecured Credentials
    if re.search(
        r"(Get-ChildItem.*\.txt|Select-String\s+-Pattern\s+password)",
        powershell_script,
        re.IGNORECASE,
    ):
        techniques.append(
            ("T1552", "Unsecured Credentials: Possible search for credentials in files")
        )

    # T1018 - Remote System Discovery
    if re.search(
        r"(Get-NetNeighbor|nbtstat\s+-n|net\s+view)", powershell_script, re.IGNORECASE
    ):
        techniques.append(
            ("T1018", "Remote System Discovery: Enumerating network systems")
        )

    return techniques


def check_evasion_techniques(powershell_script):
    """Check for common malware evasion techniques"""
    evasion_techniques = []

    # Check for obfuscated commands
    if re.search(
        r"\-[eE][nN][cC][oO][dD][eE][dD][cC][oO][mM][mM][aA][nN][dD]", powershell_script
    ):
        evasion_techniques.append(("Use of encoded commands", Fore.RED))

    # Check for execution policy bypass
    if re.search(
        r"-[eE]x[eE]c[uU]t[iI]on[pP]ol[iI]cy\s+[bB]y[pP]ass", powershell_script
    ):
        evasion_techniques.append(("Attempt to bypass execution policy", Fore.RED))

    # Check for hidden window execution
    if re.search(r"-[wW]indow[sS]tyle\s+[hH]idden", powershell_script):
        evasion_techniques.append(("Attempt to run with hidden window", Fore.RED))

    # Check for use of aliases to obfuscate cmdlets
    aliases = {
        "iex": "Invoke-Expression",
        "sal": "Set-Alias",
        "wget": "Invoke-WebRequest",
        "curl": "Invoke-WebRequest",
        "rv": "Remove-Variable",
        "saps": "Start-Process",
    }
    for alias, cmdlet in aliases.items():
        if re.search(rf"\b{re.escape(alias)}\b", powershell_script, re.IGNORECASE):
            evasion_techniques.append(
                (f"Use of alias '{alias}' for {cmdlet}", Fore.YELLOW)
            )

    # Check for string manipulation to construct commands
    if re.search(r'\([\'"][^\'"]+[\'"]\s*\+\s*[\'"][^\'"]+[\'"]\)', powershell_script):
        evasion_techniques.append(
            ("String concatenation used to construct commands", Fore.YELLOW)
        )

    # Check for use of environment variables to obfuscate paths
    if re.search(
        r"\$env:(?:TEMP|APPDATA|PROGRAMDATA|USERPROFILE|WINDIR)",
        powershell_script,
        re.IGNORECASE,
    ):
        evasion_techniques.append(
            ("Use of environment variables to obfuscate paths", Fore.YELLOW)
        )

    # Check for use of Invoke-Expression with variables
    if re.search(r"Invoke-Expression\s*\$", powershell_script, re.IGNORECASE):
        evasion_techniques.append(
            (
                "Use of Invoke-Expression with variables (potential dynamic execution)",
                Fore.RED,
            )
        )

    # Check for Base64 encoded strings
    if re.search(r"[A-Za-z0-9+/]{50,}={0,2}", powershell_script):
        evasion_techniques.append(
            ("Presence of likely Base64 encoded data", Fore.YELLOW)
        )

    # Check for use of reflection to load assemblies
    if re.search(r"\[Reflection.Assembly\]::Load", powershell_script):
        evasion_techniques.append(("Use of reflection to load assemblies", Fore.YELLOW))

    return evasion_techniques


def check_malware_techniques(powershell_script):
    """Check for common malware techniques in PowerShell"""
    malware_techniques = []

    # Check for downloading and executing
    if re.search(
        r"(Invoke-WebRequest|DownloadString).*Invoke-Expression",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(("Download and execute pattern detected", Fore.RED))

    # Check for PowerShell downgrade
    if re.search(r"-version\s+2", powershell_script, re.IGNORECASE):
        malware_techniques.append(
            ("Attempt to use PowerShell version 2 (downgrade attack)", Fore.RED)
        )

    # Check for disabling security features
    if re.search(
        r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(("Attempt to disable real-time monitoring", Fore.RED))

    # Check for common malware file operations
    if re.search(
        r"(New-Object\s+System\.IO\.FileStream|\.Write\(.*\[Convert\]::FromBase64String)",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(
            ("Suspicious file write operation (possible dropper behavior)", Fore.RED)
        )

    # Check for registry modifications for persistence
    if re.search(
        r"(New-ItemProperty|Set-ItemProperty).*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(
            ("Modification of run keys for persistence", Fore.RED)
        )

    # Check for scheduled task creation
    if re.search(
        r"(New-ScheduledTask|Register-ScheduledTask)", powershell_script, re.IGNORECASE
    ):
        malware_techniques.append(
            (
                "Creation of scheduled tasks (possible persistence mechanism)",
                Fore.YELLOW,
            )
        )

    # Check for disabling Windows Defender
    if re.search(
        r"Set-MpPreference\s+-DisableRealtimeMonitoring\s+\$true",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(("Attempt to disable Windows Defender", Fore.RED))

    # Check for use of reflective DLL injection techniques
    if re.search(
        r"(VirtualAlloc|WriteProcessMemory|CreateRemoteThread)",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(
            (
                "Use of memory manipulation functions (possible injection technique)",
                Fore.RED,
            )
        )

    # Check for use of common keylogging techniques
    if re.search(
        r"(GetAsyncKeyState|GetForegroundWindow|GetWindowText)",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(
            ("Use of API calls commonly associated with keylogging", Fore.RED)
        )

    # Check for use of common sandbox evasion techniques
    if re.search(
        r"(Get-WmiObject\s+Win32_ComputerSystem|Get-WmiObject\s+Win32_LogicalDisk)",
        powershell_script,
        re.IGNORECASE,
    ):
        malware_techniques.append(
            ("Gathering system information (possible sandbox evasion)", Fore.YELLOW)
        )

    return malware_techniques


def check_persistence_techniques(powershell_script):
    """Check for common persistence techniques"""
    persistence_techniques = []

    # Check for Run and RunOnce registry keys
    if re.search(
        r"(HKCU|HKLM):\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\(Run|RunOnce)",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(
            ("Modification of Run/RunOnce registry keys", Fore.RED)
        )

    # Check for startup folder
    if re.search(
        r"\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(("Access to Startup folder", Fore.RED))

    # Check for WMI event subscription
    if re.search(
        r"(New-CimInstance|Set-WmiInstance).*EventFilter",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(
            ("WMI event subscription (possible fileless persistence)", Fore.RED)
        )

    # Check for scheduled tasks
    if re.search(
        r"(Register-ScheduledTask|New-ScheduledTaskAction)",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(
            ("Creation or modification of scheduled tasks", Fore.RED)
        )

    # Check for service creation or modification
    if re.search(r"(New-Service|Set-Service)", powershell_script, re.IGNORECASE):
        persistence_techniques.append(("Service creation or modification", Fore.RED))

    # Check for Group Policy modification
    if re.search(r"(New-GPO|Set-GPRegistryValue)", powershell_script, re.IGNORECASE):
        persistence_techniques.append(("Group Policy modification", Fore.RED))

    # Check for Office macro autorun keys
    if re.search(
        r"HKCU:\\\\SOFTWARE\\\\Microsoft\\\\Office\.*\\\\Word\\\\Security\\\\VBAWarnings",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(
            ("Modification of Office macro settings", Fore.RED)
        )

    # Check for AppInit_DLLs
    if re.search(
        r"HKLM:\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(("Modification of AppInit_DLLs", Fore.RED))

    # Check for ScreenSaver persistence
    if re.search(
        r"HKCU:\\Control Panel\\Desktop\\SCRNSAVE\\.EXE",
        powershell_script,
        re.IGNORECASE,
    ):
        persistence_techniques.append(("ScreenSaver executable modification", Fore.RED))

    return persistence_techniques


def check_windows_exe_mimicry(powershell_script):
    """Check for scripts mimicking common Windows executables"""
    mimicry_attempts = []

    common_exes = [
        "svchost",
        "lsass",
        "csrss",
        "winlogon",
        "explorer",
        "smss",
        "wininit",
        "mmc",
        "conhost",
        "taskmgr",
        "dwm",
        "notepad",
        "cmd",
        "powershell",
        "rundll32",
        "regsvr32",
        "services",
        "spoolsv",
        "dllhost",
        "logonui",
        "wuauclt",
        "vssvc",
        "client32",
    ]

    for exe in common_exes:
        if re.search(rf"\b{re.escape(exe)}\.exe\b", powershell_script, re.IGNORECASE):
            mimicry_attempts.append((f"Possible mimicry of {exe}.exe", Fore.YELLOW))

    # Check for creation of executables with these names
    if re.search(r"New-Item.*\.exe", powershell_script, re.IGNORECASE):
        for exe in common_exes:
            if re.search(
                rf"New-Item.*{re.escape(exe)}\.exe", powershell_script, re.IGNORECASE
            ):
                mimicry_attempts.append(
                    (f"Creation of file mimicking {exe}.exe", Fore.RED)
                )

    return mimicry_attempts



def analyze_powershell(powershell_script):
    original_script = powershell_script
    is_encoded = False

    # Check if the script is Base64 encoded
    if is_base64(powershell_script) or powershell_script.strip().lower().startswith('powershell -ec'):
        print(f"{Fore.YELLOW}Detected Base64 encoded command. Decoding...{Style.RESET_ALL}")
        decoded_script = decode_base64_command(powershell_script)
        if not decoded_script.startswith("Error decoding command:"):
            powershell_script = decoded_script
            is_encoded = True
        else:
            print(f"{Fore.RED}{decoded_script}{Style.RESET_ALL}")
            return  # Exit if decoding failed

    variables = extract_variables(powershell_script)
    replaced_script = replace_variables(powershell_script, variables)

    print(f"{Fore.GREEN}{Style.BRIGHT}Original Script:{Style.RESET_ALL}")
    print(original_script)
    
    if is_encoded:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}Decoded Script:{Style.RESET_ALL}")
        print(powershell_script)

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Detailed Breakdown of Actions:{Style.RESET_ALL}")
    breakdown = breakdown_script(replaced_script)
    for item, color in breakdown:
        if item.startswith("Uses"):
            entity, description = item.split(":", 1)
            entity = entity.replace("Uses ", "")
            print(f"{color}- Uses {Style.BRIGHT}{entity}{Style.NORMAL}:{description}")
        else:
            print(f"{color}- {item}")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}MITRE ATT&CK Techniques Detected:{Style.RESET_ALL}")
    mitre_techniques = check_mitre_attack_techniques(powershell_script)
    if mitre_techniques:
        for technique_id, description in mitre_techniques:
            print(f"{Fore.RED}- {technique_id}: {description}")
    else:
        print(f"{Fore.GREEN}No common MITRE ATT&CK techniques detected.")

    atomic_techniques = detect_mitre_atomic(powershell_script)
    if atomic_techniques:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}Atomic Techniques Detected:{Style.RESET_ALL}")
        for technique in atomic_techniques:
            print(f"- {technique}")
    else:
        print(f"{Fore.GREEN} No Atomic Red Team Tactics Found.")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Evasion Techniques Detected:{Style.RESET_ALL}")
    evasion_techniques = check_evasion_techniques(powershell_script)
    if evasion_techniques:
        for technique, color in evasion_techniques:
            print(f"{color}- {technique}")
    else:
        print(f"{Fore.GREEN}No common evasion techniques detected.")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Malware Techniques Detected:{Style.RESET_ALL}")
    malware_techniques = check_malware_techniques(powershell_script)
    if malware_techniques:
        for technique, color in malware_techniques:
            print(f"{color}- {technique}")
    else:
        print(f"{Fore.GREEN}No common malware techniques detected.")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Persistence Techniques Detected:{Style.RESET_ALL}")
    persistence_techniques = check_persistence_techniques(powershell_script)
    if persistence_techniques:
        for technique, color in persistence_techniques:
            print(f"{color}- {technique}")
    else:
        print(f"{Fore.GREEN}No common persistence techniques detected.")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Windows Executable Mimicry Detected:{Style.RESET_ALL}")
    mimicry_attempts = check_windows_exe_mimicry(powershell_script)
    if mimicry_attempts:
        for attempt, color in mimicry_attempts:
            print(f"{color}- {attempt}")
    else:
        print(f"{Fore.GREEN}No attempts to mimic common Windows executables detected.")

    print(f"\n{Fore.GREEN}{Style.BRIGHT}Detailed Variable Analysis:{Style.RESET_ALL}")
    variable_info = breakdown_variables(variables, replaced_script)
    for var_name, info in variable_info.items():
        print(f"{Fore.CYAN}Variable: ${var_name}")
        print(f"{Fore.YELLOW}  Value: {info['value']}")
        print(f"{Fore.MAGENTA}  Purpose: {info['purpose']}")
        print()

    # Check for obfuscation
    if re.search(r'\w+\s*\+\s*\w+', powershell_script):
        print("Possible string concatenation obfuscation detected.")
    
    if re.search(r'(\[char\](\d+|\$\w+)\s*\+?)+', powershell_script):
        print("Possible character code obfuscation detected.")

    # Check for less common but powerful cmdlets
    powerful_cmdlets = ['Invoke-WmiMethod', 'Add-MpPreference', 'New-PSDrive', 'Out-MinidumpXXX']
    for cmdlet in powerful_cmdlets:
        if cmdlet in powershell_script:
            print(f"Powerful cmdlet detected: {cmdlet}")

    # Check for script block and module logging
    if 'Set-PSDebug' in powershell_script or 'Set-StrictMode' in powershell_script:
        print("Script attempts to modify PowerShell debugging or strict mode.")

# The main function remains unchanged
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

# Add this line at the end of your script
if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
