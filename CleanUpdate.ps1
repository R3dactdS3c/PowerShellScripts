<#
.DESCRIPTION
    Runs SFC, DISM, Disk Cleanup, Drive Optimization, Windows Updates, and CHKDSK (last).

.AUTHOR
    Max Redacted

.VERSION
    0.1.3
.LICENSE
    GNUv3.0
#>

param (
    [string]$LogFile = "$env:SystemDrive\SystemCheck.log"
)

function Test-IsAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "$timestamp [$Level] - $Message"
    Add-Content -Path $LogFile -Value $entry
    Write-Host $entry
}

function Run-SFC {
    Write-Log "Running SFC scan..."
    sfc /scannow | ForEach-Object { Write-Log $_ }
}

function Run-DISM {
    Write-Log "Running DISM restore health..."
    DISM /Online /Cleanup-Image /RestoreHealth | ForEach-Object { Write-Log $_ }
}

function Install-PSWindowsUpdateModule {
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Log "Installing PSWindowsUpdate module..."
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser
        Install-Module -Name PSWindowsUpdate -Force -Scope CurrentUser
    }
    Import-Module PSWindowsUpdate
}

function Run-WindowsUpdates {
    Write-Log "Checking for Windows and Microsoft updates..."
    Install-PSWindowsUpdateModule
    Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
    $updates = Get-WindowsUpdate -AcceptAll -IgnoreReboot
    if ($updates) {
        Write-Log "Installing updates..."
        Install-WindowsUpdate -AcceptAll -IgnoreReboot -AutoReboot | ForEach-Object {
            Write-Log $_.Title
        }
    } else {
        Write-Log "No updates available."
    }
}

function Run-DiskCleanup {
    Write-Log "Running Disk Cleanup..."
    $cleanmgr = "$env:SystemRoot\System32\cleanmgr.exe"
    $sageset = 1
    Start-Process -FilePath $cleanmgr -ArgumentList "/sageset:$sageset" -Wait
    Start-Process -FilePath $cleanmgr -ArgumentList "/sagerun:$sageset" -Wait
    Write-Log "Disk Cleanup completed."
}

function Run-DriveOptimization {
    Write-Log "Running drive optimization..."
    Optimize-Volume -DriveLetter C -Verbose | ForEach-Object { Write-Log $_ }
}

function Run-CHKDSK {
    Write-Log "Scheduling CHKDSK on C: drive..."
    $chkdskCommand = "chkdsk C: /F /R /X"
    Write-Log "Executing: $chkdskCommand"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c $chkdskCommand" -Verb RunAs -Wait
    Write-Log "CHKDSK scheduled. A reboot may be required."
}

# Main Execution
if (-not (Test-IsAdmin)) {
    Write-Log "Script must be run as Administrator." "ERROR"
    Write-Host "Please run this script as Administrator."
    exit 1
}

Write-Log "System maintenance started."

# Run SFC and DISM twice
for ($i = 1; $i -le 2; $i++) {
    Write-Log "Starting pass $i of system checks..."
    Run-SFC
    Run-DISM
    Write-Log "Completed pass $i."
}

# Run Disk Cleanup and Optimization
Run-DiskCleanup
Run-DriveOptimization

# Run Windows and Microsoft Updates
Run-WindowsUpdates

# Run CHKDSK last
Run-CHKDSK

Write-Log "System maintenance completed. Reboot may be required for CHKDSK."
