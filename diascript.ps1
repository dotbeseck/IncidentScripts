# Extended Incident Response Diagnostic Script for Windows

# File to store the output
$OutputFile = "C:\Windows\Temp\windows_diagnostic_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".txt"

# Creating the output file
New-Item -Path $OutputFile -ItemType File -Force

# Function to execute a command and write its output to the file
function Write-OutputToFile {
    param(
        [string]$Command
    )

    # Executing the command and writing its output
    Invoke-Expression $Command | Out-File -Append -FilePath $OutputFile
}

# Writing diagnostics to the file
"Windows Incident Response Diagnostic Report" | Out-File -FilePath $OutputFile
"Generated on $(Get-Date)" | Out-File -Append -FilePath $OutputFile
"-----------------------------------" | Out-File -Append -FilePath $OutputFile

# Checking running processes
"1. Running Processes:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-Process | Format-Table -AutoSize"

# Reviewing open network connections
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"2. Open Network Connections:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-NetTCPConnection | Format-Table -AutoSize"

# Inspecting system logs
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"3. System Event Logs:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-EventLog -LogName System -Newest 50 | Format-Table -AutoSize"

# Application Event Logs
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"4. Application Event Logs:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-EventLog -LogName Application -Newest 50 | Format-Table -AutoSize"

# Security Event Logs
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"5. Security Event Logs:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-EventLog -LogName Security -Newest 50 | Format-Table -AutoSize"

# PowerShell Operational Logs
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"6. PowerShell Operational Logs:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational -MaxEvents 50 | Format-Table -AutoSize"

# Analyzing the file system
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"7. File System Analysis:" | Out-File -Append -FilePath $OutputFile
"Documents Directory Contents:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-ChildItem '$Env:USERPROFILE\Documents' | Format-Table -AutoSize"

# Checking environment variables
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"8. Environment Variables:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-ChildItem Env: | Format-Table -AutoSize"

# Verifying user information
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"9. User Information:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-WmiObject -Class Win32_UserAccount | Format-Table -AutoSize"

# Reviewing command history
"-----------------------------------" | Out-File -Append -FilePath $OutputFile
"10. Command History:" | Out-File -Append -FilePath $OutputFile
Write-OutputToFile "Get-History | Format-Table -AutoSize"

Write-Host "Diagnostic report generated at $OutputFile"
