# Windows Incident Response Data Collection Script

# Function to safely run commands and handle errors
function Run-Command {
    param (
        [string]$command
    )
    try {
        $result = Invoke-Expression -Command $command
        return $result
    }
    catch {
        return "Error running command: $_"
    }
}

# Collect System Information
function Get-SystemInfo {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering System Information" -PercentComplete 10
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
    $uptimeString = "{0} days, {1} hours, {2} minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes

    return @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = $os.Caption
        OSBuildNumber = $os.BuildNumber
        SystemUptime = $uptimeString
        CurrentUsers = Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty UserName
    }
}

# Collect Network Information
function Get-NetworkInfo {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering Network Information" -PercentComplete 25
    return @{
        IPAddresses = Get-NetIPAddress | Select-Object IPAddress, InterfaceAlias
        NetworkAdapters = Get-NetAdapter | Select-Object Name, InterfaceDescription, Status
        DNSServers = Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
        OpenConnections = Get-NetTCPConnection | Where-Object State -eq 'Established'
    }
}

# Collect Process Information
function Get-ProcessInfo {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering Process Information" -PercentComplete 40
    return @{
        RunningProcesses = Get-Process | Select-Object ProcessName, Id, CPU, WorkingSet, Path
        Services = Get-Service | Select-Object Name, DisplayName, Status
    }
}

# Collect User Information
function Get-UserInfo {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering User Information" -PercentComplete 55
    return @{
        LocalUsers = Get-LocalUser | Select-Object Name, Enabled, LastLogon
        LocalAdministrators = Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource
        LogonSessions = Get-WmiObject Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, AuthenticationPackage
    }
}

# Collect File System Information
function Get-FileSystemInfo {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering File System Information" -PercentComplete 70
    return @{
        DiskUsage = Get-Volume | Select-Object DriveLetter, FileSystemLabel, FileSystem, SizeRemaining, Size
        RecentFiles = Get-ChildItem -Path $env:USERPROFILE -Recurse -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, LastWriteTime
    }
}

# Collect Security Information
function Get-SecurityInfo {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering Security Information" -PercentComplete 85
    
    # Function to safely get local security policy
    function Get-LocalSecurityPolicy {
        try {
            $tempFile = "C:\Windows\Temp\secpol_temp.cfg"
            $null = secedit /export /cfg $tempFile
            $securityPolicy = Get-Content $tempFile
            Remove-Item $tempFile -Force
            return $securityPolicy
        }
        catch {
            return "Unable to export local security policy: $_"
        }
    }

    return @{
        FirewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
        AntiVirusProduct = Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct | Select-Object displayName, productState
        InstalledUpdates = Get-HotFix | Select-Object HotFixID, InstalledOn
        BitLockerStatus = Get-BitLockerVolume | Select-Object MountPoint, EncryptionMethod, VolumeStatus
        ScheduledTasks = Get-ScheduledTask | Where-Object {$_.State -ne 'Disabled'} | Select-Object TaskName, State, LastRunTime
        PowerShellExecutionPolicy = Get-ExecutionPolicy
        InstalledSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor
        StartupPrograms = Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location
        SMBShares = Get-SmbShare | Select-Object Name, Path, Description
        LocalSecurityPolicy = Get-LocalSecurityPolicy
        # Additional security checks
        WindowsDefenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, NISEnabled, OnAccessProtectionEnabled, RealTimeProtectionEnabled
        AdminAccountStatus = Get-LocalUser | Where-Object {$_.Name -eq 'Administrator'} | Select-Object Name, Enabled
        GuestAccountStatus = Get-LocalUser | Where-Object {$_.Name -eq 'Guest'} | Select-Object Name, Enabled
        PasswordPolicy = Get-LocalUser | Select-Object Name, PasswordExpires, PasswordLastSet, PasswordRequired
        AuditPolicy = auditpol /get /category:* | Out-String
    }
}

# Collect System Logs
function Get-SystemLogs {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Gathering System Logs" -PercentComplete 95
    $yesterday = (Get-Date).AddDays(-1)
    return Get-WinEvent -FilterHashtable @{LogName='System','Application','Security'; StartTime=$yesterday} -ErrorAction SilentlyContinue
}

# Main function to collect all data
function Collect-IncidentResponseData {
    Write-Progress -Activity "Collecting Incident Response Data" -Status "Initializing..." -PercentComplete 0

    $incidentData = @{
        Timestamp = Get-Date -Format o
        SystemInfo = Get-SystemInfo
        NetworkInfo = Get-NetworkInfo
        ProcessInfo = Get-ProcessInfo
        UserInfo = Get-UserInfo
        FileSystemInfo = Get-FileSystemInfo
        SecurityInfo = Get-SecurityInfo
        SystemLogs = Get-SystemLogs
    }

    Write-Progress -Activity "Collecting Incident Response Data" -Status "Saving Data..." -PercentComplete 98

    $outputFile = "Windows_Incident_Response_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    $incidentData | ConvertTo-Json -Depth 10 | Out-File $outputFile

    Write-Progress -Activity "Collecting Incident Response Data" -Status "Complete" -PercentComplete 100
    Write-Host "Incident response data has been collected and saved to $outputFile"
}

# Run the main function
Collect-IncidentResponseData
