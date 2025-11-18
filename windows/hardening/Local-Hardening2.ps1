<#
.SYNOPSIS
    Comprehensive Windows Hardening Script with OS Detection and Enhanced Error Handling
    
.DESCRIPTION
    This script performs comprehensive Windows hardening operations with automatic OS detection,
    platform-specific configurations, robust error handling, and detailed logging.
    
    Supported Operating Systems:
    - Windows Server 2016
    - Windows Server 2019
    - Windows Server 2022
    - Windows 7
    - Windows 10
    - Windows 11
    
.PARAMETER LogPath
    Specifies the path for log files. Default: C:\Windows\Logs\Hardening
    
.EXAMPLE
    .\Local-Hardening2.ps1
    
.NOTES
    Version: 2.0
    Author: BYU-CCDC Team
    Requires: Administrator privileges
    Last Updated: 2024
    
    Change Log:
    v2.0 - Added comprehensive OS detection, platform-specific hardening, robust error handling,
           enhanced user feedback, and comprehensive logging
#>

[CmdletBinding()]
param(
    [string]$LogPath = "C:\Windows\Logs\Hardening"
)

#region Script Configuration and Global Variables

$ErrorActionPreference = "Continue"
$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening"
$portsFile = "ports.json"
$usersFile = "users.txt"
$advancedAuditingFile = "advancedAuditing.ps1"
$patchURLFile = "patchURLs.json"

# Global variables for tracking
$script:OperationResults = @{
    Total = 0
    Successful = 0
    Failed = 0
    Skipped = 0
    CriticalErrors = @()
    Warnings = @()
}

$script:LogFile = $null
$script:OSInfo = $null
$script:OSVersion = $null
$script:OSBuild = $null
$script:OSEdition = $null
$script:IsServer = $false
$script:IsServerCore = $false
$script:CurrentUser = $null
$script:UserArray = @()
$script:PortsObject = $null
$script:DefenderStatus = "Unknown"
$script:WindowsUpdateStatus = "Unknown"
$script:EternalBlueStatus = "Unknown"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Function names for tracking
$functionNames = @(
    "Initialize Context", "Get Competition Users", "Disable Users", "Enable Windows Defender", 
    "Quick Harden", "Add Competition Users", "Remove RDP Users", "Configure Firewall", 
    "Disable Unnecessary Services", "Enable Advanced Auditing", "Configure Splunk", 
    "EternalBlue Mitigated", "Upgrade SMB", "Patch Mimikatz", "Run Windows Updates", 
    "Set Execution Policy"
)

$script:log = @{}

#endregion

#region OS Detection Functions

<#
.SYNOPSIS
    Detects and identifies the Windows operating system version.
    
.DESCRIPTION
    Uses WMI/CIM to detect the OS version, build number, edition, and whether it's a Server or Client OS.
    Also detects Server Core installations.
    
.OUTPUTS
    PSCustomObject with OS information
#>
function Get-OperatingSystemInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Detecting operating system..."
        
        # Use CIM for better compatibility, fallback to WMI if needed
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        } catch {
            Write-Warning "CIM query failed, falling back to WMI..."
            $osInfo = Get-WmiObject -Class Win32_OperatingSystem
        }
        
        $caption = $osInfo.Caption
        $version = $osInfo.Version
        $buildNumber = $osInfo.BuildNumber
        $productType = $osInfo.ProductType  # 1=Workstation, 2=Domain Controller, 3=Server
        
        # Determine OS edition
        $edition = $osInfo.OperatingSystemSKU
        $editionName = switch ($edition) {
            { $_ -in 4, 27, 28, 48, 49, 50, 161, 162 } { "Server Core" }
            { $_ -in 7, 8, 10, 48, 49, 50, 161, 162 } { "Server" }
            default { "Client" }
        }
        
        # Detect Server Core
        $isServerCore = $false
        if ($productType -in 2, 3) {
            try {
                $serverFeatures = Get-WindowsFeature
                if ($serverFeatures) {
                    $guiFeature = $serverFeatures | Where-Object { $_.Name -eq "Server-Gui-Mgmt-Infra" -or $_.Name -eq "Server-Gui-Shell" }
                    $isServerCore = ($guiFeature -and $guiFeature.InstallState -ne "Installed")
                }
            } catch {
                # If Get-WindowsFeature fails, check for Server Core indicators
                $isServerCore = ($caption -match "Server Core" -or $editionName -eq "Server Core")
            }
        }
        
        # Parse OS version
        $osVersion = "Unknown"
        $osFamily = "Unknown"
        
        if ($caption -match "Windows Server 2022") {
            $osVersion = "Windows Server 2022"
            $osFamily = "Server2022"
        } elseif ($caption -match "Windows Server 2019") {
            $osVersion = "Windows Server 2019"
            $osFamily = "Server2019"
        } elseif ($caption -match "Windows Server 2016") {
            $osVersion = "Windows Server 2016"
            $osFamily = "Server2016"
        } elseif ($caption -match "Windows 11") {
            $osVersion = "Windows 11"
            $osFamily = "Client11"
        } elseif ($caption -match "Windows 10") {
            $osVersion = "Windows 10"
            $osFamily = "Client10"
        } elseif ($caption -match "Windows 7") {
            $osVersion = "Windows 7"
            $osFamily = "Client7"
        } elseif ($caption -match "Windows Server 2012 R2") {
            $osVersion = "Windows Server 2012 R2"
            $osFamily = "Server2012R2"
        } elseif ($caption -match "Windows Server 2012") {
            $osVersion = "Windows Server 2012"
            $osFamily = "Server2012"
        } elseif ($caption -match "Windows Server 2008 R2") {
            $osVersion = "Windows Server 2008 R2"
            $osFamily = "Server2008R2"
        } elseif ($caption -match "Windows Server 2008") {
            $osVersion = "Windows Server 2008"
            $osFamily = "Server2008"
        } elseif ($caption -match "Windows 8") {
            $osVersion = "Windows 8"
            $osFamily = "Client8"
        } elseif ($caption -match "Windows Vista") {
            $osVersion = "Windows Vista"
            $osFamily = "ClientVista"
        } elseif ($caption -match "Windows XP") {
            $osVersion = "Windows XP"
            $osFamily = "ClientXP"
        }
        
        $result = [PSCustomObject]@{
            Caption = $caption
            Version = $version
            BuildNumber = $buildNumber
            OSVersion = $osVersion
            OSFamily = $osFamily
            Edition = $editionName
            IsServer = ($productType -in 2, 3)
            IsServerCore = $isServerCore
            ProductType = $productType
        }
        
        Write-Host "`n[INFO] OS Detection: $($result.OSVersion) (Build $($result.BuildNumber)) - $($result.Edition)" -ForegroundColor Cyan
        Write-Log -Level "INFO" -Message "OS Detection: $($result.OSVersion) (Build $($result.BuildNumber)) - $($result.Edition)"
        
        return $result
        
    } catch {
        Write-Error "Failed to detect operating system: $($_.Exception.Message)"
        throw
    }
}

#endregion

#region Logging Functions

<#
.SYNOPSIS
    Initializes the logging system.
#>
function Initialize-Logging {
    [CmdletBinding()]
    param()
    
    try {
        # Create log directory if it doesn't exist
        if (-not (Test-Path $LogPath)) {
            New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
            Write-Verbose "Created log directory: $LogPath"
        }
        
        # Create timestamped log file
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "Hardening_$timestamp.log"
        $script:LogFile = Join-Path $LogPath $logFileName
        
        # Write log header
        $header = @"
========================================
Windows Hardening Script Execution Log
========================================
Start Time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
OS Version: $($script:OSInfo.OSVersion)
OS Build: $($script:OSInfo.BuildNumber)
OS Edition: $($script:OSInfo.Edition)
Is Server: $($script:OSInfo.IsServer)
Is Server Core: $($script:OSInfo.IsServerCore)
Current User: $($script:CurrentUser)
Script Version: 2.0
========================================

"@
        
        $header | Out-File -FilePath $script:LogFile -Encoding UTF8
        Write-Host "Log file created: $script:LogFile" -ForegroundColor Cyan
        
    } catch {
        Write-Warning "Failed to initialize logging: $($_.Exception.Message)"
        $script:LogFile = $null
    }
}

<#
.SYNOPSIS
    Writes a message to the log file and optionally to console.
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL")]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [switch]$Console
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file
    if ($script:LogFile) {
        try {
            $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding UTF8
        } catch {
            Write-Warning "Failed to write to log file: $($_.Exception.Message)"
        }
    }
    
    # Write to console if requested
    if ($Console -or $Level -in "ERROR", "CRITICAL", "WARNING") {
        $color = switch ($Level) {
            "SUCCESS" { "Green" }
            "WARNING" { "Yellow" }
            "ERROR" { "Red" }
            "CRITICAL" { "Red" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    }
}

<#
.SYNOPSIS
    Updates the operation tracking log.
#>
function Update-Log {
    param(
        [string]$key,
        [string]$value
    )
    $script:log[$key] = $value
}

<#
.SYNOPSIS
    Initializes the function execution log.
#>
function Initialize-Log {
    foreach ($func in $functionNames) {
        Update-Log $func "Not executed"
    }
}

<#
.SYNOPSIS
    Prints the execution summary log.
#>
function Print-Log {
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "### Script Execution Summary ###" -ForegroundColor Green
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Execution Summary ===" -Console
    
    # Display OS information
    if ($script:OSInfo) {
        Write-Host "`nOperating System:" -ForegroundColor Yellow
        Write-Host "  Version: $($script:OSInfo.OSVersion)" -ForegroundColor White
        Write-Host "  Build: $($script:OSInfo.BuildNumber)" -ForegroundColor White
        Write-Host "  Edition: $($script:OSInfo.Edition)" -ForegroundColor White
        Write-Host "  Is Server: $($script:OSInfo.IsServer)" -ForegroundColor White
        Write-Log -Level "INFO" -Message "OS: $($script:OSInfo.OSVersion) (Build $($script:OSInfo.BuildNumber))"
    }
    
    # Print individual operation results
    Write-Host "`nIndividual Operations:" -ForegroundColor Yellow
    foreach ($entry in $script:log.GetEnumerator()) {
        # Skip Stanford Harden in executive summary
        if ($entry.Key -eq "Run Stanford Harden") {
            continue
        }
        
        $status = $entry.Value
        
        # Override status with actual system state for Windows Update and Defender
        if ($entry.Key -eq "Run Windows Updates" -and $script:WindowsUpdateStatus) {
            if ($script:WindowsUpdateStatus -eq "Completed") {
                $status = "Completed"
            } elseif ($script:WindowsUpdateStatus -like "Completed*") {
                $status = $script:WindowsUpdateStatus
            } elseif ($script:WindowsUpdateStatus -like "Failed*") {
                $status = $script:WindowsUpdateStatus
            }
        }
        
        if ($entry.Key -eq "Enable Windows Defender" -and $script:DefenderStatus) {
            if ($script:DefenderStatus -eq "Enabled") {
                $status = "Enabled"
            } elseif ($script:DefenderStatus -eq "Disabled") {
                $status = "Disabled/Failed"
            } else {
                $status = "$status (Status: $script:DefenderStatus)"
            }
        }
        
        $color = switch -Wildcard ($status) {
            "*successfully*" { "Green" }
            "*Enabled*" { "Green" }
            "*Completed*" { "Green" }
            "*Mitigated*" { "Green" }
            "*Failed*" { "Red" }
            "*Disabled*" { "Red" }
            "*Skipped*" { "Yellow" }
            default { "White" }
        }
        Write-Host "  $($entry.Key): " -NoNewline -ForegroundColor White
        Write-Host $status -ForegroundColor $color
        Write-Log -Level "INFO" -Message "$($entry.Key): $status"
    }
    
    # Print operation statistics
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "### Operation Statistics ###" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host "Total Operations Attempted: $($script:OperationResults.Total)" -ForegroundColor White
    Write-Host "  Successful Operations: $($script:OperationResults.Successful)" -ForegroundColor Green
    Write-Host "  Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
    Write-Host "  Skipped Operations: $($script:OperationResults.Skipped)" -ForegroundColor Yellow
    
    Write-Log -Level "INFO" -Message "Total Operations: $($script:OperationResults.Total)" -Console
    Write-Log -Level "INFO" -Message "Successful: $($script:OperationResults.Successful)" -Console
    Write-Log -Level "INFO" -Message "Failed: $($script:OperationResults.Failed)" -Console
    Write-Log -Level "INFO" -Message "Skipped: $($script:OperationResults.Skipped)" -Console
    
    # Display skipped operations with reasons
    if ($script:OperationResults.Skipped -gt 0) {
        Write-Host "`nSkipped Operations (with reasons):" -ForegroundColor Yellow
        $skippedOps = $script:log.GetEnumerator() | Where-Object { $_.Value -like "*Skipped*" }
        foreach ($op in $skippedOps) {
            Write-Host "  - $($op.Key): $($op.Value)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Skipped: $($op.Key) - $($op.Value)"
        }
    }
    
    if ($script:OperationResults.CriticalErrors.Count -gt 0) {
        Write-Host "`n" + ("=" * 60) -ForegroundColor Red
        Write-Host "### Critical Errors ###" -ForegroundColor Red
        Write-Host ("=" * 60) -ForegroundColor Red
        foreach ($error in $script:OperationResults.CriticalErrors) {
            Write-Host "  - $error" -ForegroundColor Red
            Write-Log -Level "CRITICAL" -Message "Critical Error: $error" -Console
        }
    }
    
    if ($script:OperationResults.Warnings.Count -gt 0) {
        Write-Host "`n### Warnings ###" -ForegroundColor Yellow
        foreach ($warning in $script:OperationResults.Warnings) {
            Write-Host "  - $warning" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Warning: $warning" -Console
        }
    }
    
    Write-Host ("`n" + ("=" * 60)) -ForegroundColor Cyan
}

#endregion

#region Error Handling Functions

<#
.SYNOPSIS
    Executes a hardening operation with comprehensive error handling.
    
.DESCRIPTION
    Wraps hardening operations in try-catch blocks, tracks success/failure,
    and provides appropriate user feedback.
    
.PARAMETER OperationName
    Name of the operation being performed.
    
.PARAMETER ScriptBlock
    The script block to execute.
    
.PARAMETER IsCritical
    Whether this operation is critical (script will halt on failure).
    
.PARAMETER OSCompatibility
    Array of OS families this operation is compatible with. If empty, applies to all.
#>
function Invoke-HardeningOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OperationName,
        
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [switch]$IsCritical,
        
        [string[]]$OSCompatibility = @(),
        
        [string]$ProgressMessage = ""
    )
    
    $script:OperationResults.Total++
    
    # Check OS compatibility
    if ($OSCompatibility.Count -gt 0) {
        if ($script:OSInfo.OSFamily -notin $OSCompatibility) {
            $message = "[SKIPPED] Operation '$OperationName' is not compatible with $($script:OSInfo.OSVersion) (OS Family: $($script:OSInfo.OSFamily))"
            Write-Host $message -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message $message -Console
            $script:OperationResults.Skipped++
            $script:OperationResults.Warnings += $message
            Update-Log $OperationName "Skipped - OS incompatible ($($script:OSInfo.OSFamily))"
            return
        }
    }
    
    try {
        Write-Host "`n[EXECUTING] $OperationName..." -ForegroundColor Cyan
        if ($ProgressMessage) {
            Write-Host "[INFO] $ProgressMessage" -ForegroundColor White
        }
        Write-Log -Level "INFO" -Message "Starting operation: $OperationName" -Console
        if ($script:OSInfo) {
            Write-Host "[INFO] Applying configuration for $($script:OSInfo.OSVersion)..." -ForegroundColor DarkGray
        }
        
        # Execute the script block
        & $ScriptBlock
        
        $message = "[SUCCESS] $OperationName completed successfully"
        Write-Host $message -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message $message -Console
        $script:OperationResults.Successful++
        Update-Log $OperationName "Executed successfully"
        
    } catch {
        $errorMessage = "[FAILED] $OperationName : $($_.Exception.Message)"
        Write-Host $errorMessage -ForegroundColor Red
        Write-Host "[ERROR DETAILS] Exception Type: $($_.Exception.GetType().FullName)" -ForegroundColor DarkRed
        if ($_.Exception.InnerException) {
            Write-Host "[ERROR DETAILS] Inner Exception: $($_.Exception.InnerException.Message)" -ForegroundColor DarkRed
        }
        Write-Log -Level "ERROR" -Message $errorMessage -Console
        Write-Log -Level "ERROR" -Message "Exception Type: $($_.Exception.GetType().FullName)"
        if ($_.Exception.InnerException) {
            Write-Log -Level "ERROR" -Message "Inner Exception: $($_.Exception.InnerException.Message)"
        }
        
        $script:OperationResults.Failed++
        Update-Log $OperationName "Failed with error: $($_.Exception.Message)"
        
        if ($IsCritical) {
            $script:OperationResults.CriticalErrors += "$OperationName : $($_.Exception.Message)"
            Write-Host "`n[CRITICAL] Operation '$OperationName' failed. This is a critical operation." -ForegroundColor Red
            Write-Log -Level "CRITICAL" -Message "Critical operation failed: $OperationName" -Console
            
            $continue = Read-Host "Continue with remaining operations? (y/n)"
            if ($continue -ne "y" -and $continue -ne "Y") {
                throw "Script halted due to critical error in: $OperationName"
            }
        }
    }
}

<#
.SYNOPSIS
    Validates prerequisites before executing an operation.
#>
function Test-Prerequisite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$PrerequisiteType,
        
        [Parameter(Mandatory=$true)]
        [string]$Value,
        
        [string]$OperationName = "Unknown"
    )
    
    try {
        switch ($PrerequisiteType) {
            "RegistryPath" {
                if (-not (Test-Path $Value)) {
                    Write-Host "[WARNING] Registry path not found for $OperationName : $Value" -ForegroundColor Yellow
                    Write-Log -Level "WARNING" -Message "Prerequisite check failed for $OperationName : Registry path not found: $Value" -Console
                    return $false
                }
            }
            "Service" {
                $service = Get-Service -Name $Value
                if (-not $service) {
                    Write-Host "[WARNING] Service not found for $OperationName : $Value" -ForegroundColor Yellow
                    Write-Log -Level "WARNING" -Message "Prerequisite check failed for $OperationName : Service not found: $Value" -Console
                    return $false
                }
            }
            "File" {
                if (-not (Test-Path $Value)) {
                    Write-Host "[WARNING] File not found for $OperationName : $Value" -ForegroundColor Yellow
                    Write-Log -Level "WARNING" -Message "Prerequisite check failed for $OperationName : File not found: $Value" -Console
                    return $false
                }
            }
        }
        return $true
    } catch {
        Write-Host "[WARNING] Prerequisite check error for $OperationName : $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "Prerequisite check error for $OperationName : $($_.Exception.Message)" -Console
        return $false
    }
}

<#
.SYNOPSIS
    Sets a registry value with comprehensive error handling and OS-specific validation.
    
.DESCRIPTION
    Creates or updates a registry value with proper error handling, prerequisite checking,
    and OS-specific path validation.
#>
function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$true)]
        [string]$Name,
        
        [Parameter(Mandatory=$true)]
        [object]$Value,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("String", "DWord", "QWord", "MultiString", "ExpandString", "Binary")]
        [string]$PropertyType,
        
        [string]$OperationName = "Registry Operation",
        
        [switch]$CreatePathIfMissing
    )
    
    try {
        # Validate prerequisite - check if registry path exists
        if (-not (Test-Path $Path)) {
            if ($CreatePathIfMissing) {
                Write-Host "[INFO] Creating registry path: $Path" -ForegroundColor Cyan
                New-Item -Path $Path -Force | Out-Null
                Write-Log -Level "SUCCESS" -Message "Created registry path: $Path"
            } else {
                $message = "Registry path not found and CreatePathIfMissing not specified: $Path"
                Write-Host "[SKIPPED] $message" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "$OperationName - $message" -Console
                $script:OperationResults.Skipped++
                return $false
            }
        }
        
        # Check if property exists, if not create it
        $existingValue = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        
        if ($null -ne $existingValue -and $existingValue.PSObject.Properties[$Name]) {
            # Property exists, update it
            Set-ItemProperty -Path $Path -Name $Name -Value $Value | Out-Null
            Write-Host "[SUCCESS] Updated registry value: $Path\$Name = $Value" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Updated registry value: $Path\$Name = $Value"
        } else {
            # Property doesn't exist, create it
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force | Out-Null
            Write-Host "[SUCCESS] Created and set registry value: $Path\$Name = $Value" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Created registry value: $Path\$Name = $Value"
        }
        
        return $true
        
    } catch {
        $errorMessage = "Failed to set registry value $Path\$Name : $($_.Exception.Message)"
        Write-Host "[ERROR] $errorMessage" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "$OperationName - $errorMessage" -Console
        throw
    }
}

#endregion

#region Pre-flight Checks

<#
.SYNOPSIS
    Performs pre-flight checks before script execution.
#>
function Test-Prerequisites {
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== Pre-flight Checks ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks ===" -Console
    
    $allChecksPassed = $true
    
    # Check administrator privileges
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if (-not $isAdmin) {
            Write-Host "[FAIL] Script must be run as Administrator" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Administrator privileges required" -Console
            $allChecksPassed = $false
        } else {
            Write-Host "[PASS] Running with Administrator privileges" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Administrator privileges confirmed"
        }
    } catch {
        Write-Host "[FAIL] Could not verify administrator privileges" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Could not verify administrator privileges: $($_.Exception.Message)" -Console
        $allChecksPassed = $false
    }
    
    # Check OS compatibility
    try {
        if ($script:OSInfo.OSVersion -eq "Unknown") {
            Write-Host "[WARN] Unknown OS version detected. Some operations may not work correctly." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Unknown OS version detected"
        } else {
            Write-Host "[PASS] OS detected: $($script:OSInfo.OSVersion)" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "OS detected: $($script:OSInfo.OSVersion)"
        }
    } catch {
        Write-Host "[FAIL] OS detection failed" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "OS detection failed: $($_.Exception.Message)" -Console
        $allChecksPassed = $false
    }
    
    # Check PowerShell version
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 3) {
            Write-Host "[WARN] PowerShell version $psVersion may not support all features" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "PowerShell version $psVersion detected"
        } else {
            Write-Host "[PASS] PowerShell version: $psVersion" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "PowerShell version: $psVersion"
        }
    } catch {
        Write-Host "[WARN] Could not determine PowerShell version" -ForegroundColor Yellow
        Write-Log -Level "WARNING" -Message "Could not determine PowerShell version"
    }
    
    Write-Host "`n=== Pre-flight Checks Complete ===" -ForegroundColor Cyan
    Write-Log -Level "INFO" -Message "=== Pre-flight Checks Complete ===" -Console
    
    if (-not $allChecksPassed) {
        Write-Host "`n[WARNING] Some pre-flight checks failed. The script may not function correctly." -ForegroundColor Yellow
        $continue = Read-Host "Continue anyway? (y/n)"
        if ($continue -ne "y") {
            throw "Pre-flight checks failed. Script aborted by user."
        }
    }
    
    return $allChecksPassed
}

#endregion

#region Core Hardening Functions

<#
.SYNOPSIS
    Initializes the script context and downloads required files.
#>
function Initialize-Context {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Initialize Context" -ScriptBlock {
        # Download needed files
        $neededFiles = @($portsFile, $advancedAuditingFile, $patchURLFile)
        foreach ($file in $neededFiles) {
            $filename = $(Split-Path -Path $file -Leaf)
            if (-not (Test-Path "$pwd\$filename")) {
                Write-Host "Downloading $filename..." -ForegroundColor Cyan
                try {
                    Invoke-WebRequest -Uri "$ccdcRepoWindowsHardeningPath/$file" -OutFile "$pwd\$filename"              
                    Write-Log -Level "SUCCESS" -Message "Downloaded $filename"
                } catch {
                    Write-Log -Level "WARNING" -Message "Failed to download $filename : $($_.Exception.Message)"
                    throw "Failed to download required file: $filename"
                }
            } else {
                Write-Verbose "File already exists: $filename"
            }
        }
        
        # Set global variables
        $script:CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        # Load userfile and portdata
        if (Test-Path ".\users.txt") {
            [string[]]$script:UserArray = Get-Content -Path ".\users.txt"
            Write-Log -Level "INFO" -Message "Loaded $($script:UserArray.Count) users from users.txt"
        } else {
            [string[]]$script:UserArray = @()
            Write-Log -Level "INFO" -Message "No users.txt found, using empty array"
        }
        
        if (Test-Path ".\ports.json") {
            $script:PortsObject = Get-Content -Path ".\ports.json" -Raw | ConvertFrom-Json
            Write-Log -Level "INFO" -Message "Loaded ports configuration from ports.json"
        } else {
            # Fallback port definitions
            $script:PortsObject = @{ ports = @{
                '53'   = @{ description = 'DNS' }
                '3389' = @{ description = 'RDP' }
                '80'   = @{ description = 'HTTP' }
                '445'  = @{ description = 'SMB' }
                '139'  = @{ description = 'NetBIOS Session' }
                '22'   = @{ description = 'SSH' }
                '88'   = @{ description = 'Kerberos' }
                '67'   = @{ description = 'DHCP Server' }
                '68'   = @{ description = 'DHCP Client' }
                '135'  = @{ description = 'RPC' }
                '389'  = @{ description = 'LDAP' }
                '636'  = @{ description = 'LDAPS' }
                '3268' = @{ description = 'Global Catalog' }
                '3269' = @{ description = 'Global Catalog SSL' }
                '464'  = @{ description = 'Kerberos Change/Set Password' }
            } }
            Write-Log -Level "WARNING" -Message "ports.json not found, using fallback port definitions"
        }
        
        Write-Host "Context initialized successfully" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Initializes the system by setting up logging and context.
    This function combines Initialize-Log and Initialize-Context to ensure
    proper system initialization before running hardening operations.
#>
function Initialize-System {
    [CmdletBinding()]
    param()
    
    Write-Host "`nInitializing system..." -ForegroundColor Cyan
    
    try {
        # Initialize function execution log
        Initialize-Log
        
        # Initialize context (downloads files, sets variables)
        Initialize-Context
        
        Write-Host "Initialization complete" -ForegroundColor Green
    } catch {
        Write-Host "Initialization failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "System initialization failed: $($_.Exception.Message)" -Console
        throw "System initialization failed: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
    Prompts user for competition usernames.
#>
function GetCompetitionUsers {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Get Competition Users" -ScriptBlock {
        # Prompt the user for the first username
        $user1 = Read-Host "Please enter the first username"
        
        # Prompt the user for the second username
        $user2 = Read-Host "Please enter the second username"
        
        # Combine the usernames with a newline between them
        $content = "$user1`n$user2"
        
        # Write the usernames to users.txt in the current directory
        Set-Content -Path ".\users.txt" -Value $content        
        # Wait a moment to ensure file system has updated
        Start-Sleep -Milliseconds 500
        
        # Verify file was created and has content
        if (-not (Test-Path ".\users.txt")) {
            throw "users.txt was not created successfully"
        }
        
        $verifyContent = Get-Content ".\users.txt"
        if ($verifyContent.Count -eq 0) {
            throw "users.txt is empty after creation"
        }
        
        # Update the global UserArray variable
        [string[]]$script:UserArray = $verifyContent
        
        # Notify the user that the file has been created
        Write-Host "The file users.txt has been created with the provided usernames." -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message "Created users.txt with usernames: $user1, $user2"
    }
}

<#
.SYNOPSIS
    Generates a random password.
#>
function GeneratePassword {
    [CmdletBinding()]
    param()
    
    try {
        $PasswordLength = 10
        $CharacterSet = @{
            Uppercase   = (97..122) | Get-Random -Count 10 | % {[char]$_}
            Lowercase   = (65..90)  | Get-Random -Count 10 | % {[char]$_}
            Numeric     = (48..57)  | Get-Random -Count 10 | % {[char]$_}
            SpecialChar = (33..47)+(58..64)+(91..96)+(123..126) | Get-Random -Count 10 | % {[char]$_}
        }
        $StringSet = $CharacterSet.Uppercase + $CharacterSet.Lowercase + $CharacterSet.Numeric + $CharacterSet.SpecialChar
        $password = -join(Get-Random -Count $PasswordLength -InputObject $StringSet)
        return $password
    } catch {
        Write-Log -Level "ERROR" -Message "Password generation failed: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Disables all local users except competition users and optionally additional specified users.
#>
function Disable-AllUsers {
    [CmdletBinding()]
    param()
    
    try {
        Write-Host "Mass Disable Users" -ForegroundColor Cyan
        
        # Check if users.txt exists
        if (-not (Test-Path ".\users.txt")) {
            Write-Host "[FAILED] users.txt not found. Run 'Get Competition Users' first." -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "users.txt not found for mass disable users"
            return
        }
        
        # Read competition users from users.txt
        $competitionUsers = Get-Content ".\users.txt"
        
        Write-Host "`nCompetition users that will be KEPT ENABLED:" -ForegroundColor Yellow
        $competitionUsers | ForEach-Object { Write-Host "  - $_" }
        
        # Get all local users
        $allLocalUsers = Get-LocalUser
        
        # Find users that are NOT in competition list
        $usersToDisable = $allLocalUsers | Where-Object { $_.Name -notin $competitionUsers }
        
        if ($usersToDisable.Count -eq 0) {
            Write-Host "`nNo additional users to disable." -ForegroundColor Green
            return
        }
        
        Write-Host "`nThe following users will be disabled:" -ForegroundColor Yellow
        $usersToDisable | ForEach-Object { Write-Host "  - $($_.Name)" }
        
        # Prompt for additional users to keep enabled
        $keepAdditional = Read-Host "`nDo you want to keep any additional users enabled? (y/n)"
        
        $usersToKeep = @()
        if ($keepAdditional -eq "y") {
            Write-Host "`nEnter usernames to keep enabled (one per line, blank line to finish):"
            do {
                $username = Read-Host
                if ($username -ne "") {
                    $usersToKeep += $username
                }
            } while ($username -ne "")
        }
        
        # Disable users not in competition list or keep list
        foreach ($user in $usersToDisable) {
            if ($user.Name -notin $usersToKeep) {
                try {
                    Disable-LocalUser -Name $user.Name
                    Write-Host "[SUCCESS] Disabled user: $($user.Name)" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Disabled user: $($user.Name)"
                } catch {
                    Write-Host "[FAILED] Could not disable user $($user.Name): $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "Could not disable user $($user.Name): $($_.Exception.Message)"
                }
            } else {
                Write-Host "[SKIPPED] Keeping user enabled: $($user.Name)" -ForegroundColor Cyan
                Write-Log -Level "INFO" -Message "Keeping user enabled: $($user.Name)"
            }
        }
        
        Write-Host "`nMass disable users completed" -ForegroundColor Green
        Write-Log -Level "SUCCESS" -Message "Mass disable users completed"
    } catch {
        Write-Host "[FAILED] Mass disable users failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Failed to disable users: $($_.Exception.Message)"
        throw
    }
}

<#
.SYNOPSIS
    Disables users with confirmation prompt.
#>
function Disable-Users {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Disable Users" -ScriptBlock {
        $confirmation = Prompt-Yes-No -Message "Mass disable users (y/n)?"
        if ($confirmation.toLower() -eq "y") {
            Disable-AllUsers
            Write-Host "All users disabled but your own" -ForegroundColor Green
        } else {
            Write-Host "Skipping..." -ForegroundColor Yellow
            Write-Log -Level "INFO" -Message "User disabled operation skipped by user"
            throw "Operation skipped by user"
        }
    }
}

<#
.SYNOPSIS
    Prompts user to set a password for a local user.
#>
function Get-Set-Password {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$user
    )
    
    try {
        # Verify user exists first
        $localUser = Get-LocalUser -Name $user        
        $pw = Read-Host -AsSecureString -Prompt "New password for '$user'?"
        $conf = Read-Host -AsSecureString -Prompt "Confirm password"
        
        # Convert SecureString to plain text for comparison
        $pwPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))
        $confPlainText = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($conf))
        
        if ($pwPlainText -eq $confPlainText -and $pwPlainText -ne "") {
            # Attempt to set the password
            try {
                $securePassword = ConvertTo-SecureString -AsPlainText $pwPlainText -Force
                $localUser | Set-LocalUser -Password $securePassword                
                # Verify the password was actually changed by attempting to read user again
                # (This is a basic verification - the Set-LocalUser should throw if it fails)
                $verifyUser = Get-LocalUser -Name $user                
                Write-Host "[SUCCESS] Password updated for user: $user" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Password updated for user: $user"
                
                # Clear the plaintext passwords from memory
                $pwPlainText = $null
                $confPlainText = $null
                $securePassword = $null
                [System.GC]::Collect()
                $pw.Dispose()
                $conf.Dispose()
                return $true
            } catch {
                Write-Host "[FAILED] Could not update password for $user - $($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Failed to update password for $($user): $($_.Exception.Message)"
                
                # Clear the plaintext passwords from memory
                $pwPlainText = $null
                $confPlainText = $null
                [System.GC]::Collect()
                $pw.Dispose()
                $conf.Dispose()
                return $false
            }
        } else {
            Write-Host "[FAILED] Either the passwords didn't match, or you typed nothing" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Password confirmation failed for user: $user"
            
            # Clear the plaintext passwords from memory
            $pwPlainText = $null
            $confPlainText = $null
            [System.GC]::Collect()
            $pw.Dispose()
            $conf.Dispose()
            return $false
        }
    } catch {
        Write-Host "[FAILED] Error with password submission for $($user): $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Please try again...`n" -ForegroundColor Yellow
        Write-Log -Level "ERROR" -Message "Error in Get-Set-Password for $($user): $($_.Exception.Message)"
        return $false
    }
}

<#
.SYNOPSIS
    Adds competition-specific users with certain privileges.
#>
function Add-Competition-Users {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Add Competition Users" -ScriptBlock {
        # Check if users.txt exists and has content
        if (-not (Test-Path ".\users.txt")) {
            Write-Host "users.txt not found. Please run 'Get Competition Users' first." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "users.txt not found"
            throw "users.txt not found"
        }
        
        # Wait a moment to ensure file is fully written if it was just created
        Start-Sleep -Milliseconds 500
        
        # Read users from file with error handling
        try {
            $users = Get-Content ".\users.txt"
            if ($users.Count -eq 0) {
                Write-Host "users.txt is empty. Please run 'Get Competition Users' first." -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "users.txt is empty"
                throw "users.txt is empty"
            }
            # Update the global UserArray
            [string[]]$script:UserArray = $users
        } catch {
            Write-Host "Failed to read users.txt: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Failed to read users.txt: $($_.Exception.Message)"
            throw "Failed to read users.txt: $($_.Exception.Message)"
        }
        
        if ($script:UserArray.Count -eq 0) {
            Write-Host "No users defined in users.txt. Please run 'Get Competition Users' first." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "No users defined in users.txt"
            throw "No users defined"
        }
        
        foreach ($user in $script:UserArray) {
            if ($user -eq "") { continue }
            
            # Check if user already exists
            $existingUser = Get-LocalUser -Name $user
            if ($existingUser) {
                Write-Host "User '$user' already exists, skipping creation" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "User '$user' already exists"
                continue
            }
            
            $splat = @{
                Name = $user
                Password = (ConvertTo-SecureString -String (GeneratePassword) -AsPlainText -Force)
            }
            New-LocalUser @splat
            Write-Log -Level "SUCCESS" -Message "Created user: $user"
            
            $userIndex = [array]::IndexOf($script:UserArray, $user)
            
            if ($userIndex -eq 0) {
                Add-LocalGroupMember -Group "Administrators" -Member $user
                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $user
                Write-Log -Level "SUCCESS" -Message "Added $user to Administrators and Remote Desktop Users groups"
                
                while ($true) {
                    if (Get-Set-Password -user $user) { break }
                }
            }
            
            if ($userIndex -eq 1) {
                Add-LocalGroupMember -Group "Remote Desktop Users" -Member $user
                Write-Log -Level "SUCCESS" -Message "Added $user to Remote Desktop Users group"
                
                while ($true) {
                    if (Get-Set-Password -user $user) { break }
                }
            }
        }
        
        $userInfos = Print-Users
        
        $confirmation = Prompt-Yes-No -Message "Any users you'd like to enable (y/n)?"
        if ($confirmation.ToLower() -eq "y") {
            $enableUsers = Get-Comma-Separated-List -category "users"
            $enableUsers | ForEach-Object {
                Enable-LocalUser -Name $_
                Write-Log -Level "SUCCESS" -Message "Enabled user: $_"
                $userInfos = Print-Users
            }
        }
        
        $confirmation = Prompt-Yes-No -Message "Any users you'd like to disable (y/n)?"
        if ($confirmation.ToLower() -eq "y") {
            $disableUsers = Get-Comma-Separated-List -category "users"
            $disableUsers | ForEach-Object {
                Disable-LocalUser -Name $_
                Write-Log -Level "SUCCESS" -Message "Disabled user: $_"
                $userInfos = Print-Users
            }
        }
        
        $userOutput = Print-Users
        if ($userOutput -ne $null) {
            $outputText = $userOutput -join "`n`n"
            $outputText | Out-File -FilePath "UserPerms.txt" -Encoding UTF8
            Write-Host "`nUser permissions have been exported to .\UserPerms.txt" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Exported user permissions to UserPerms.txt"
        }
    }
}

<#
.SYNOPSIS
    Removes users from Remote Desktop Users group except specified ones.
#>
function Remove-RDP-Users {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Remove RDP Users" -ScriptBlock {
        # Check if users.txt exists and has content
        if (-not (Test-Path ".\users.txt")) {
            Write-Host "users.txt not found. Please run 'Get Competition Users' first." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "users.txt not found for RDP removal"
            throw "users.txt not found"
        }
        
        # Wait a moment to ensure file is fully written if it was just created
        Start-Sleep -Milliseconds 500
        
        # Read users from file with error handling
        try {
            $users = Get-Content ".\users.txt"
            if ($users.Count -eq 0) {
                Write-Host "users.txt is empty. Please run 'Get Competition Users' first." -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "users.txt is empty for RDP removal"
                throw "users.txt is empty"
            }
            # Update the global UserArray
            [string[]]$script:UserArray = $users
        } catch {
            Write-Host "Failed to read users.txt: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Failed to read users.txt: $($_.Exception.Message)"
            throw "Failed to read users.txt: $($_.Exception.Message)"
        }
        
        if ($script:UserArray.Count -lt 2) {
            Write-Host "Insufficient users defined. Need at least 2 users in users.txt" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Insufficient users defined for RDP removal"
            throw "Insufficient users defined"
        }
        
        $usersToRemove = Get-LocalUser -Name * | Where-Object {
            $_.name -ne $script:UserArray[0] -and $_.name -ne $script:UserArray[1]
        }
        
        foreach ($user in $usersToRemove) {
            try {
                Remove-LocalGroupMember -Name "Remote Desktop Users" -Member $user -Confirm:$false
                Write-Log -Level "SUCCESS" -Message "Removed $($user.Name) from Remote Desktop Users group"
            } catch {
                # User might not be in the group, which is fine
                Write-Verbose "User $($user.Name) not in Remote Desktop Users group or already removed"
            }
        }
        
        Write-Host "RDP users removed successfully" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Prompts for yes or no response.
#>
function Prompt-Yes-No {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    try {
        do {
            $response = $(Write-Host $Message -ForegroundColor Yellow -NoNewline; Read-Host)
            if ($response -ieq 'y' -or $response -ieq 'n') {
                return $response
            } else {
                Write-Host "Please enter 'y' or 'n'." -ForegroundColor Yellow
            }
        } while ($true)
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Prompt-Yes-No: $($_.Exception.Message)"
        return "n"
    }
}

<#
.SYNOPSIS
    Prints enabled and disabled users with their group memberships.
#>
function Print-Users {
    [CmdletBinding()]
    param()
    
    try {
        $output = @()
        
        Write-Host "`n==== Enabled Users ====" -ForegroundColor Green
        $enabledUsersOutput = "==== Enabled Users ===="
        $enabledUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $enabledUsersOutput += "`nUser: $($_.Name)"
            $user = $_
            
            $groups = Get-LocalGroup | Where-Object {
                $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID")
            } | Select-Object -ExpandProperty "Name"
            
            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $enabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $enabledUsersOutput
        
        Write-Host "`n==== Disabled Users ====" -ForegroundColor Red
        $disabledUsersOutput = "==== Disabled Users ===="
        $disabledUsers = Get-LocalUser | Where-Object Enabled -eq $false | ForEach-Object {
            Write-Host "User: $($_.Name)"
            $disabledUsersOutput += "`nUser: $($_.Name)"
            
            $user = $_
            $groups = Get-LocalGroup | Where-Object {
                $user.SID -in ($_ | Get-LocalGroupMember | Select-Object -ExpandProperty "SID")
            } | Select-Object -ExpandProperty "Name"
            
            $groupString = "Groups: $($groups -join ', ')"
            Write-Host $groupString
            $disabledUsersOutput += "`n$groupString"
            [System.GC]::Collect()
        }
        $output += $disabledUsersOutput
        
        return $output
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Print-Users: $($_.Exception.Message)"
        return $null
    }
}

<#
.SYNOPSIS
    Gets a comma-separated list from user input.
#>
function Get-Comma-Separated-List {
    [CmdletBinding()]
    param(
        [string]$category,
        [string]$message
    )
    
    try {
        $userInput = $null
        if ($message -ne "") {
            $userInput = Read-Host $message
            return $userInput.Split(",") | ForEach-Object { $_.Trim() }
        } elseif ($category -ne "") {
            $userInput = Read-Host "List $category. Separate by commas if multiple. NO SPACES"
            return $userInput.Split(",") | ForEach-Object { $_.Trim() }
        }
    } catch {
        Write-Log -Level "ERROR" -Message "Error in Get-Comma-Separated-List: $($_.Exception.Message)"
        return @()
    }
}

<#
.SYNOPSIS
    Configures Windows Firewall with specified ports.
#>
function Configure-Firewall {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Configure Firewall" -ScriptBlock {
        $ready = $false
        :outer while ($true) {
            $desigPorts = Get-Comma-Separated-List -message "List needed port numbers for firewall config. Separate by commas."
            $usualPorts = @(53, 3389, 80, 445, 139, 22, 88, 67, 68, 135, 139, 389, 636, 3268, 3269, 464) | Sort-Object
            $commonScored = @(53, 3389, 80, 22)
            $commonADorDC = @(139, 88, 67, 68, 135, 139, 389, 445, 636, 3268, 3269, 464)
            
            Write-Host "All the following ports that we suggest are either common scored services, or usually needed for AD processes. We will say which is which. While this box isn't domain bound, AD ports have been left on the list in case this box gets bound later."
            
            foreach ($item in $usualPorts) {
                if ($desigPorts -notcontains $item) {
                    if ($item -in $commonScored) {
                        Write-Host "`nCommon Scored Service" -ForegroundColor Green
                    }
                    if ($item -in $commonADorDC) {
                        if ($item -eq 445) {
                            Write-Host "`nCommon Scored Service" -ForegroundColor Green -NoNewline
                            Write-Host " and" -ForegroundColor Cyan -NoNewline
                            Write-Host " Common port needed for CD/AD processes" -ForegroundColor Red
                        } else {
                            Write-Host "`nCommon port needed for DC/AD processes" -ForegroundColor Red
                        }
                    }
                    $confirmation = $(Write-Host "Need " -NoNewline) + $(Write-Host "$item" -ForegroundColor Green -NoNewline) + $(Write-Host ", " -NoNewline) + $(Write-Host "$($script:PortsObject.ports.$item.description)? " -ForegroundColor Cyan -NoNewline) + $(Write-Host "(y/n)" -ForegroundColor Yellow; Read-Host)
                    
                    while($true) {
                        if ($confirmation.toLower() -eq "y") {
                            $desigPorts = @($desigPorts) + $item
                            break
                        }
                        if ($confirmation.toLower() -eq "n") {
                            break
                        }
                    }
                }
            }
            
            Write-Host "`n==== Designated Ports ====" -ForegroundColor Cyan
            Write-Host ($desigPorts -join "`n") | Sort-Object
            
            $confirmation = ""
            while($true) {
                $confirmation = Prompt-Yes-No -Message "Are these ports correct (y/n)?"
                if ($confirmation.toLower() -eq "y") {
                    $ready = $true
                    break outer
                }
                if ($confirmation.toLower() -eq "n") {
                    $ready = $false
                    break
                }
            }
        }
        
        if ($ready -eq $true) {
            # Disable the firewall profiles temporarily
            netsh advfirewall set allprofiles state off | Out-Null
            
            # Disable all pre-existing inbound and outbound rules
            netsh advfirewall firewall set rule all dir=in new enable=no | Out-Null
            netsh advfirewall firewall set rule all dir=out new enable=no | Out-Null
            
            # Iterate through each port and create the appropriate rules
            foreach ($port in $desigPorts) {
                $description = $script:PortsObject.ports.$port.description
                
                # Inbound rules
                netsh advfirewall firewall add rule name="TCP Inbound $description" dir=in action=allow protocol=TCP localport=$port | Out-Null
                netsh advfirewall firewall add rule name="UDP Inbound $description" dir=in action=allow protocol=UDP localport=$port | Out-Null
                
                # Outbound rules
                netsh advfirewall firewall add rule name="TCP Outbound $description" dir=out action=allow protocol=TCP localport=$port | Out-Null
                netsh advfirewall firewall add rule name="UDP Outbound $description" dir=out action=allow protocol=UDP localport=$port | Out-Null
                
                Write-Log -Level "SUCCESS" -Message "Added firewall rules for port $port ($description)"
            }
            
            # Re-enable the firewall profiles
            netsh advfirewall set allprofiles state on | Out-Null
            Write-Host "Firewall configured successfully" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Firewall configuration completed"
        } else {
            Write-Log -Level "INFO" -Message "Firewall configuration skipped by user"
            throw "Operation skipped by user"
        }
    }
}

<#
.SYNOPSIS
    Disables unnecessary services and network features.
#>
function Disable-Unnecessary-Services {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Disable Unnecessary Services" -ScriptBlock {
        # Get all active network adapters
        $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
        
        if ($activeAdapters) {
            # Loop through each active adapter and disable IPv6
            foreach ($adapter in $activeAdapters) {
                try {
                    Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6
                    Write-Log -Level "SUCCESS" -Message "Disabled IPv6 on adapter: $($adapter.Name)"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not disable IPv6 on adapter $($adapter.Name): $($_.Exception.Message)"
                }
            }
        }
        
        # Get all IP-enabled adapters and disable NetBIOS over TCP/IP
        try {
            $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
            
            foreach ($adapter in $adapters) {
                try {
                    # Disable NetBIOS over TCP/IP (NetbiosOptions = 2)
                    $adapter.SetTcpipNetbios(2) | Out-Null
                    Write-Log -Level "SUCCESS" -Message "Disabled NetBIOS over TCP/IP on adapter"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not disable NetBIOS: $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Log -Level "WARNING" -Message "Could not get network adapters: $($_.Exception.Message)"
        }
        
        Write-Host "Unnecessary services disabled successfully" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Enables and configures Windows Defender with comprehensive settings.
#>
function Enable-Windows-Defender {
    [CmdletBinding()]
    param()
    
    # Check OS compatibility - Defender availability varies by OS version
    # Windows 10/11 and Server 2016+ have Windows Defender Antivirus
    # Windows 7/8 and Server 2008/2012 have Windows Defender (basic)
    # Windows Server Core may have limited Defender features
    $defenderCompatible = @("Client7", "Client8", "Client10", "Client11", "Server2008R2", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")
    
    # Track status for executive report
    $script:DefenderStatus = "Unknown"
    
    Invoke-HardeningOperation -OperationName "Enable Windows Defender" -OSCompatibility $defenderCompatible -ProgressMessage "Enabling and configuring Windows Defender with comprehensive security settings" -ScriptBlock {
        Write-Host "[INFO] Enabling Windows Defender for $($script:OSInfo.OSVersion)..." -ForegroundColor Cyan
        Write-Host "[INFO] Defender features may vary by OS version" -ForegroundColor DarkGray
        
        $operationSuccess = @{}
        $allOperationsSucceeded = $true
        
        # Start Defender Service
        Write-Host "[ACTION] Starting Windows Defender service..." -ForegroundColor White
        try {
            # Check if service exists
            $defenderService = Get-Service -Name WinDefend
            if (-not $defenderService) {
                Write-Host "  [WARNING] Windows Defender service (WinDefend) not found on this OS version" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "Windows Defender service not found on $($script:OSInfo.OSVersion)"
                $operationSuccess["ServiceStart"] = $false
                $allOperationsSucceeded = $false
            } else {
                Start-Service -Name WinDefend
                Set-Service -Name WinDefend -StartupType Automatic
                Write-Host "  [SUCCESS] Windows Defender service started and set to automatic" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Windows Defender service started and set to automatic"
                $operationSuccess["ServiceStart"] = $true
            }
        } catch {
            Write-Host "  [WARNING] Could not start Windows Defender service: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Could not start Windows Defender service: $($_.Exception.Message)" -Console
            $operationSuccess["ServiceStart"] = $false
            $allOperationsSucceeded = $false
        }
        
        # Enable Attack Surface Reduction Rules (Windows 10/11 and Server 2019/2022)
        # OS-specific: ASR rules are only available on Windows 10/11 and Server 2019/2022
        if ($script:OSInfo.OSFamily -in "Client10", "Client11", "Server2019", "Server2022") {
            Write-Host "[ACTION] Enabling Attack Surface Reduction (ASR) rules (available on $($script:OSInfo.OSVersion))..." -ForegroundColor White
            $asrSuccess = $true
            try {
                $asrRules = @(
                    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84",
                    "3B576869-A4EC-4529-8536-B80A7769E899",
                    "D4F940AB-401B-4EfC-AADC-AD5F3C50688A",
                    "D3E037E1-3EB8-44C8-A917-57927947596D",
                    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",
                    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550",
                    "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B",
                    "D1E49AAC-8F56-4280-B9BA-993A6D77406C",
                    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4",
                    "C1DB55AB-C21A-4637-BB3F-A12568109D35",
                    "01443614-CD74-433A-B99E-2ECDC07BFC25",
                    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2",
                    "26190899-1602-49E8-8B27-EB1D0A1CE869",
                    "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C",
                    "E6DB77E5-3DF2-4CF1-B95A-636979351E5B"
                )
                
                $asrEnabledCount = 0
                foreach ($ruleId in $asrRules) {
                    try {
                        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId -AttackSurfaceReductionRules_Actions Enabled | Out-Null
                        $asrEnabledCount++
                    } catch {
                        Write-Verbose "Could not enable ASR rule $ruleId (may already be enabled or not supported)"
                    }
                }
                if ($asrEnabledCount -gt 0) {
                    Write-Host "  [SUCCESS] Enabled $asrEnabledCount Attack Surface Reduction rule(s)" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Enabled $asrEnabledCount Attack Surface Reduction rule(s)"
                } else {
                    Write-Host "  [WARNING] Could not enable any ASR rules" -ForegroundColor Yellow
                    $asrSuccess = $false
                }
            } catch {
                Write-Host "  [WARNING] Could not enable all ASR rules: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "Could not enable all ASR rules: $($_.Exception.Message)"
                $asrSuccess = $false
            }
            $operationSuccess["ASRRules"] = $asrSuccess
            if (-not $asrSuccess) {
                $allOperationsSucceeded = $false
            }
        } else {
            Write-Host "[INFO] Attack Surface Reduction rules not available on $($script:OSInfo.OSVersion) (requires Windows 10/11 or Server 2019/2022)" -ForegroundColor DarkGray
            Write-Log -Level "INFO" -Message "ASR rules skipped - not available on $($script:OSInfo.OSVersion)"
        }
        
        # Remove exclusions
        try {
            $prefs = Get-MpPreference
            if ($prefs) {
                if ($prefs.AttackSurfaceReductionOnlyExclusions) {
                    foreach ($ExcludedASR in $prefs.AttackSurfaceReductionOnlyExclusions) {
                        Remove-MpPreference -AttackSurfaceReductionOnlyExclusions $ExcludedASR | Out-Null
                    }
                }
                if ($prefs.ExclusionExtension) {
                    foreach ($ExcludedExt in $prefs.ExclusionExtension) {
                        Remove-MpPreference -ExclusionExtension $ExcludedExt | Out-Null
                    }
                }
                if ($prefs.ExclusionIpAddress) {
                    foreach ($ExcludedIp in $prefs.ExclusionIpAddress) {
                        Remove-MpPreference -ExclusionIpAddress $ExcludedIp | Out-Null
                    }
                }
                if ($prefs.ExclusionPath) {
                    foreach ($ExcludedDir in $prefs.ExclusionPath) {
                        Remove-MpPreference -ExclusionPath $ExcludedDir | Out-Null
                    }
                }
                if ($prefs.ExclusionProcess) {
                    foreach ($ExcludedProc in $prefs.ExclusionProcess) {
                        Remove-MpPreference -ExclusionProcess $ExcludedProc | Out-Null
                    }
                }
                Write-Log -Level "SUCCESS" -Message "Removed Defender exclusions"
            }
        } catch {
            Write-Log -Level "WARNING" -Message "Could not remove Defender exclusions: $($_.Exception.Message)"
            $operationSuccess["RemoveExclusions"] = $false
            $allOperationsSucceeded = $false
        }
        
        # Enable Defender using PowerShell cmdlets (primary method)
        Write-Host "[ACTION] Enabling Windows Defender real-time monitoring and protection features..." -ForegroundColor White
        try {
            # Enable Real-time Monitoring
            Set-MpPreference -DisableRealtimeMonitoring $false
            $operationSuccess["RealTimeMonitoring"] = $true
            
            # Enable other protection features
            Set-MpPreference -DisableBehaviorMonitoring $false
            Set-MpPreference -DisableBlockAtFirstSeen $false
            Set-MpPreference -DisableIOAVProtection $false
            Set-MpPreference -DisableScriptScanning $false
            $operationSuccess["ProtectionFeatures"] = $true
            
            Write-Host "  [SUCCESS] Windows Defender protection features enabled via PowerShell cmdlets" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Enabled Windows Defender protection features via Set-MpPreference"
        } catch {
            Write-Host "  [WARNING] Could not enable Defender via PowerShell cmdlets: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Could not enable Defender via PowerShell cmdlets: $($_.Exception.Message)"
            $operationSuccess["ProtectionFeatures"] = $false
            $allOperationsSucceeded = $false
        }
        
        # Verify Defender is enabled
        try {
            $defenderStatus = Get-MpPreference
            if ($defenderStatus.DisableRealtimeMonitoring -eq $false) {
                $script:DefenderStatus = "Enabled"
                Write-Host "  [SUCCESS] Verified: Windows Defender is enabled" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Verified Windows Defender is enabled"
            } else {
                $script:DefenderStatus = "Disabled"
                Write-Host "  [WARNING] Windows Defender real-time monitoring appears to be disabled" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "Windows Defender real-time monitoring appears disabled"
                $allOperationsSucceeded = $false
            }
        } catch {
            Write-Host "  [WARNING] Could not verify Defender status: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Could not verify Defender status: $($_.Exception.Message)"
            $script:DefenderStatus = "Unknown"
            $allOperationsSucceeded = $false
        }
        
        # Verify service is running
        try {
            $serviceStatus = Get-Service WinDefend
            if ($serviceStatus.Status -eq "Running") {
                Write-Host "  [SUCCESS] Windows Defender service is running" -ForegroundColor Green
                $operationSuccess["ServiceRunning"] = $true
            } else {
                Write-Host "  [WARNING] Windows Defender service is not running (Status: $($serviceStatus.Status))" -ForegroundColor Yellow
                $operationSuccess["ServiceRunning"] = $false
                $allOperationsSucceeded = $false
            }
        } catch {
            Write-Host "  [WARNING] Could not check Defender service status: $($_.Exception.Message)" -ForegroundColor Yellow
            $operationSuccess["ServiceRunning"] = $false
            $allOperationsSucceeded = $false
        }
        
        # Report final status
        if ($allOperationsSucceeded) {
        Write-Host "Windows Defender enabled and configured successfully" -ForegroundColor Green
        } else {
            $failedOps = $operationSuccess.GetEnumerator() | Where-Object { $_.Value -eq $false } | ForEach-Object { $_.Key }
            Write-Host "Windows Defender configuration completed with errors. Failed operations: $($failedOps -join ', ')" -ForegroundColor Yellow
            throw "Windows Defender configuration completed with errors: $($failedOps -join ', ')"
        }
    }
}

<#
.SYNOPSIS
    Quick harden function that performs essential hardening steps.
#>
function Quick-Harden {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Quick Harden" -ScriptBlock {
        Write-Host "`n=== QUICK HARDENING STARTED ===" -ForegroundColor Green
        Write-Host "This will perform essential hardening steps automatically..." -ForegroundColor Yellow
        
        # Call initialization first
        Initialize-System
        
        # Step 1: Disable all users except current one
        Write-Host "`n1. Disabling all users except current user..." -ForegroundColor Cyan
        Disable-AllUsers
        
        # Step 2: Change current user password
        Write-Host "`n2. Changing current user password..." -ForegroundColor Cyan
        $currentSamAccountName = $script:CurrentUser.Split('\')[-1]
        Write-Host "Please set a new password for user: $currentSamAccountName" -ForegroundColor Yellow
        while ($true) {
            if (Get-Set-Password -user $currentSamAccountName) { break }
        }
        
        # Step 3: Create competition users
        Write-Host "`n3. Creating competition users..." -ForegroundColor Cyan
        if (-not (Test-Path .\users.txt)) { 
            GetCompetitionUsers 
        }
        Add-Competition-Users
        
        # Step 4: Remove RDP users
        Write-Host "`n4. Removing users from RDP group..." -ForegroundColor Cyan
        Remove-RDP-Users
        
        # Step 5: Upgrade SMB
        Write-Host "`n5. Upgrading SMB..." -ForegroundColor Cyan
        Upgrade-SMB
        
        # Step 6: Enable Windows Defender
        Write-Host "`n6. Enabling Windows Defender..." -ForegroundColor Cyan
        Enable-Windows-Defender
        
        # Step 7: Configure Firewall (interactive port selection)
        Write-Host "`n7. Configuring firewall..." -ForegroundColor Cyan
        Write-Host "Common ports: 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP), 5985/5986 (WinRM)" -ForegroundColor Yellow
        $portsInput = Read-Host "Enter ports to keep open (comma-separated, e.g., 80,443,3389)"
        $portArray = $portsInput -split ',' | ForEach-Object { 
            $port = $_.Trim()
            # Validate port number (1-65535)
            if ($port -match '^\d+$' -and [int]$port -ge 1 -and [int]$port -le 65535) {
                [int]$port
            } else {
                Write-Host "  [WARNING] Invalid port number: $port (skipping)" -ForegroundColor Yellow
                $null
            }
        } | Where-Object { $_ -ne $null }
        
        if ($portArray.Count -eq 0) {
            Write-Host "  [WARNING] No valid ports provided, using default ports: 22, 80, 443, 3389" -ForegroundColor Yellow
            $portArray = @(22, 80, 443, 3389)
        }
        
        try {
            # Disable firewall temporarily
            netsh advfirewall set allprofiles state off | Out-Null
            
            # Disable all existing rules
            netsh advfirewall firewall set rule all dir=in new enable=no | Out-Null
            netsh advfirewall firewall set rule all dir=out new enable=no | Out-Null
            
            # Add port rules
            foreach ($port in $portArray) {
                $description = switch ($port) {
                    22 { "SSH" }
                    53 { "DNS" }
                    80 { "HTTP" }
                    443 { "HTTPS" }
                    3389 { "RDP" }
                    5985 { "WinRM-HTTP" }
                    5986 { "WinRM-HTTPS" }
                    default { "Port-$port" }
                }
                
                # Inbound rules
                netsh advfirewall firewall add rule name="TCP Inbound $description" dir=in action=allow protocol=TCP localport=$port | Out-Null
                netsh advfirewall firewall add rule name="UDP Inbound $description" dir=in action=allow protocol=UDP localport=$port | Out-Null
                
                # Outbound rules
                netsh advfirewall firewall add rule name="TCP Outbound $description" dir=out action=allow protocol=TCP localport=$port | Out-Null
                netsh advfirewall firewall add rule name="UDP Outbound $description" dir=out action=allow protocol=UDP localport=$port | Out-Null
            }
            
            # Re-enable firewall
            netsh advfirewall set allprofiles state on | Out-Null
            Write-Host "Firewall configured with ports: $($portArray -join ', ')" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Quick harden firewall configured with ports: $($portArray -join ', ')"
        } catch {
            Write-Host "Firewall configuration failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Quick harden firewall configuration failed: $($_.Exception.Message)"
        }
        
        # Step 8: Disable unnecessary services
        Write-Host "`n8. Disabling unnecessary services..." -ForegroundColor Cyan
        Disable-Unnecessary-Services
        
        # Step 9: Disable users (except competition users)
        Write-Host "`n9. Disabling users (except competition users)..." -ForegroundColor Cyan
        try {
            # Read competition users from users.txt
            if (Test-Path ".\users.txt") {
                Start-Sleep -Milliseconds 500  # Ensure file is fully written
                $competitionUsers = Get-Content ".\users.txt"
                if ($competitionUsers.Count -eq 0) {
                    Write-Host "  [WARNING] users.txt is empty, skipping user disabling" -ForegroundColor Yellow
                } else {
                    # Get all LOCAL users (not AD users)
                    $localUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
                    
                    # Disable all local users NOT in competition users list
                    $disabledCount = 0
                    foreach ($user in $localUsers) {
                        if ($user.Name -notin $competitionUsers) {
                            try {
                                Disable-LocalUser -Name $user.Name
                                Write-Host "  [SUCCESS] Disabled user: $($user.Name)" -ForegroundColor Green
                                Write-Log -Level "SUCCESS" -Message "Disabled user: $($user.Name)"
                                $disabledCount++
                            } catch {
                                Write-Host "  [FAILED] Could not disable user: $($user.Name) - $($_.Exception.Message)" -ForegroundColor Red
                                Write-Log -Level "WARNING" -Message "Could not disable user: $($user.Name) - $($_.Exception.Message)"
                            }
                        }
                    }
                    Write-Host "Disabled $disabledCount user(s)" -ForegroundColor Green
                }
            } else {
                Write-Host "  [WARNING] users.txt not found, skipping user disabling" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  [WARNING] Error during user disabling: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Error during user disabling: $($_.Exception.Message)"
        }
        
        # Step 10: Set Execution Policy
        Write-Host "`n10. Setting Execution Policy to RemoteSigned..." -ForegroundColor Cyan
        try {
            Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
            Write-Host "Execution Policy set to RemoteSigned successfully" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Set Execution Policy to RemoteSigned"
        } catch {
            Write-Host "Failed to set Execution Policy: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Failed to set Execution Policy: $($_.Exception.Message)"
            throw "Failed to set Execution Policy: $($_.Exception.Message)"
        }
        
        Write-Host "`n=== QUICK HARDENING COMPLETED ===" -ForegroundColor Green
        Write-Host "Essential hardening steps have been completed successfully!" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Downloads, installs, and configures Splunk.
#>
function Download-Install-Setup-Splunk {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Version,
        
        [Parameter(Mandatory=$true)]
        [string]$IP
    )
    
    Invoke-HardeningOperation -OperationName "Configure Splunk" -ScriptBlock {
        $splunkBeta = $true
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
            
            Invoke-WebRequest -Uri $downloadURL -OutFile ./splunk.ps1
            Write-Log -Level "SUCCESS" -Message "Downloaded Splunk installation script"
            
            $splunkServer = "$($IP):9997"
            
            # Install splunk using downloaded script
            if ((Get-ChildItem ./splunk.ps1).Length -lt 6000) {
                & ./splunk.ps1 $Version $SplunkServer
            } else {
                & ./splunk.ps1 $Version $SplunkServer "member"
            }
            
            Write-Log -Level "SUCCESS" -Message "Splunk installation completed"
        } catch {
            Write-Log -Level "ERROR" -Message "Splunk installation failed: $($_.Exception.Message)"
            throw
        }
    }
}

<#
.SYNOPSIS
    Installs the EternalBlue patch for the detected OS version.
#>
function Install-EternalBluePatch {
    [CmdletBinding()]
    param()
    
    # EternalBlue patch is only for older OS versions
    $eternalBlueCompatible = @("Client7", "Client8", "Server2008", "Server2008R2", "Server2012", "Server2012R2")
    
    # Track status for executive report
    $script:EternalBlueStatus = "Unknown"
    
    Invoke-HardeningOperation -OperationName "EternalBlue Mitigated" -OSCompatibility $eternalBlueCompatible -ScriptBlock {
        if (-not (Test-Path "patchURLs.json")) {
            Write-Host "patchURLs.json not found. Please run Initialize Context first." -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "patchURLs.json not found"
            throw "Required file not found"
        }
        
        $patchURLs = Get-Content -Raw -Path "patchURLs.json" | ConvertFrom-Json
        
        # Determine patch URL based on OS version keywords
        $patchURL = switch -Regex ($script:OSInfo.OSVersion) {
            '(?i)Vista'  { $patchURLs.Vista; break }
            'Windows 7'  { $patchURLs.'Windows 7'; break }
            'Windows 8'  { $patchURLs.'Windows 8'; break }
            '2008 R2'    { $patchURLs.'2008 R2'; break }
            '2008'       { $patchURLs.'2008'; break }
            '2012 R2'    { $patchURLs.'2012 R2'; break }
            '2012'       { $patchURLs.'2012'; break }
            default { throw "Unsupported OS version for EternalBlue patch: $($script:OSInfo.OSVersion)" }
        }
        
        Write-Host "Patch URL: $patchURL" -ForegroundColor Cyan
        
        # Download the patch to a temporary location
        $path = "$env:TEMP\eternalblue_patch.msu"
        
        Write-Host "Downloading patch file to $path" -ForegroundColor Cyan
        try {
            $wc = New-Object net.webclient
            $wc.Downloadfile($patchURL, $path)
            Write-Log -Level "SUCCESS" -Message "Downloaded EternalBlue patch"
        } catch {
            Write-Log -Level "ERROR" -Message "Failed to download EternalBlue patch: $($_.Exception.Message)"
            throw
        }
        
        # Install the patch
        Write-Host "Installing patch..." -ForegroundColor Cyan
        try {
            $process = Start-Process -FilePath "wusa.exe" -ArgumentList "$path /quiet /norestart" -Wait -PassThru
            if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
                throw "Patch installation returned exit code: $($process.ExitCode)"
            }
            Write-Log -Level "SUCCESS" -Message "EternalBlue patch installed successfully"
            $script:EternalBlueStatus = "Mitigated"
        } catch {
            Write-Log -Level "ERROR" -Message "Failed to install EternalBlue patch: $($_.Exception.Message)"
            $script:EternalBlueStatus = "Failed - $($_.Exception.Message)"
            throw
        } finally {
            # Cleanup
            if (Test-Path $path) {
                Remove-Item -Path $path -Force            }
        }
        
        Write-Host "Patch for $($script:OSInfo.OSVersion) installed successfully!" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Upgrades SMB by enabling SMBv2/v3 and disabling SMBv1.
#>
function Upgrade-SMB {
    [CmdletBinding()]
    param()
    
    # SMB configuration varies by OS version
    # Get-SmbServerConfiguration is available on Windows Server 2012+ and Windows 8+
    # Older OS versions may need different approaches
    $smbUpgradeCompatible = @("Client8", "Client10", "Client11", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")
    
    Invoke-HardeningOperation -OperationName "Upgrade SMB" -OSCompatibility $smbUpgradeCompatible -ProgressMessage "Enabling SMBv2/v3 and disabling SMBv1 for improved security" -ScriptBlock {
        # Check if SMB module is available (required for Get-SmbServerConfiguration)
        if (-not (Get-Module -ListAvailable -Name SmbShare)) {
            Write-Host "[WARNING] SMB module not available. Attempting to import..." -ForegroundColor Yellow
            try {
                Import-Module SmbShare
                Write-Log -Level "SUCCESS" -Message "Imported SMB module"
            } catch {
                Write-Host "[WARNING] Could not import SMB module. SMB configuration may not work correctly." -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "SMB module not available: $($_.Exception.Message)"
            }
        }
        
        try {
            # Detect the current SMB version
            Write-Host "[INFO] Detecting current SMB configuration..." -ForegroundColor Cyan
            $smbConfig = Get-SmbServerConfiguration
            $smbv1Enabled = $smbConfig.EnableSMB1Protocol
            $smbv2Enabled = $smbConfig.EnableSMB2Protocol
            # EnableSMB3Protocol property may not exist on all OS versions, use try-catch
            $smbv3Enabled = $null
            try {
                $smbv3Enabled = $smbConfig.EnableSMB3Protocol
            } catch {
                # Property doesn't exist on this OS version
                $smbv3Enabled = $null
            }
            $restart = $false
            
            Write-Host "[INFO] Current SMB Configuration:" -ForegroundColor Cyan
            Write-Host "  SMBv1: $(if ($smbv1Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv1Enabled) { 'Red' } else { 'Green' })
            Write-Host "  SMBv2: $(if ($smbv2Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv2Enabled) { 'Green' } else { 'Yellow' })
            if ($null -ne $smbv3Enabled) {
                Write-Host "  SMBv3: $(if ($smbv3Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv3Enabled) { 'Green' } else { 'Yellow' })
            }
            
            # Enable SMBv2 (SMBv3 is enabled automatically if supported on Server 2012+ and Windows 8+)
            if ($smbv2Enabled -eq $false) {
                Write-Host "[ACTION] Enabling SMBv2..." -ForegroundColor Yellow
                try {
                    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force
                    Write-Host "[SUCCESS] SMBv2 enabled" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Enabled SMBv2/SMBv3"
                    $restart = $true
                } catch {
                    Write-Host "[FAILED] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Host "[INFO] SMBv2 already enabled" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "SMBv2 already enabled"
            }
            
            # Disable SMBv1 (vulnerable protocol)
            if ($smbv1Enabled -eq $true) {
                Write-Host "[ACTION] Disabling SMBv1 (vulnerable protocol)..." -ForegroundColor Yellow
                try {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                    Write-Host "[SUCCESS] SMBv1 disabled" -ForegroundColor Green
                    Write-Log -Level "SUCCESS" -Message "Disabled SMBv1"
                    $restart = $true
                } catch {
                    Write-Host "[FAILED] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)"
                    throw
                }
            } else {
                Write-Host "[INFO] SMBv1 already disabled" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "SMBv1 already disabled"
            }
            
            # Restart might be required after these changes
            if ($restart -eq $true) {
                Write-Host "[WARNING] System restart recommended for SMB changes to take full effect" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "System restart may be required for SMB changes"
            } else {
                Write-Host "[SUCCESS] SMB configuration is already optimal" -ForegroundColor Green
            }
        } catch {
            Write-Host "[ERROR] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "SMB upgrade failed: $($_.Exception.Message)" -Console
            throw
        }
    }
}

<#
.SYNOPSIS
    Patches Mimikatz by disabling WDigest credential storage.
#>
function Patch-Mimikatz {
    [CmdletBinding()]
    param()
    
    # WDigest registry path is available on Windows 7 and later
    # On Windows Server 2008/2008 R2, the path might need to be created
    $mimikatzCompatible = @("Client7", "Client8", "Client10", "Client11", "Server2008", "Server2008R2", "Server2012", "Server2012R2", "Server2016", "Server2019", "Server2022")
    
    Invoke-HardeningOperation -OperationName "Patch Mimikatz" -OSCompatibility $mimikatzCompatible -ProgressMessage "Disabling WDigest credential storage to prevent Mimikatz credential extraction" -ScriptBlock {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        # OS-specific note: WDigest exists on Windows 7+ and Windows Server 2008+
        Write-Host "[INFO] This patch disables WDigest credential storage (UseLogonCredential = 0)" -ForegroundColor Cyan
        Write-Host "[INFO] This prevents Mimikatz from extracting plaintext credentials from memory" -ForegroundColor Cyan
        
        # Use the helper function with CreatePathIfMissing since WDigest path might not exist on older OS versions
        Set-RegistryValue -Path $registryPath -Name "UseLogonCredential" -Value 0 -PropertyType "DWord" -OperationName "Patch Mimikatz" -CreatePathIfMissing
        
        Write-Host "Mimikatz (WDigest) patch applied successfully" -ForegroundColor Green
        Write-Host "[INFO] System restart recommended for changes to take full effect" -ForegroundColor Yellow
        Write-Log -Level "SUCCESS" -Message "Mimikatz patch (WDigest) applied - UseLogonCredential set to 0"
    }
}

<#
.SYNOPSIS
    Runs Windows Updates.
#>
function Run-Windows-Updates {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Run Windows Updates" -ProgressMessage "Checking for and installing Windows Updates (this may take a while)" -ScriptBlock {
        Write-Host "[STEP 1/4] Clearing Windows Update cache..." -ForegroundColor Cyan
        
        try {
            Write-Host "  [ACTION] Stopping Windows Update service..." -ForegroundColor White
            Stop-Service -Name wuauserv -Force
            Write-Host "  [SUCCESS] Windows Update service stopped" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Stopped Windows Update service"
        } catch {
            Write-Host "  [WARNING] Could not stop Windows Update service: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Could not stop Windows Update service: $($_.Exception.Message)"
        }
        
        try {
            if (Test-Path "C:\Windows\SoftwareDistribution") {
                Write-Host "  [ACTION] Clearing SoftwareDistribution folder..." -ForegroundColor White
                Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force
                Write-Host "  [SUCCESS] Windows Update cache cleared" -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Cleared Windows Update cache"
            } else {
                Write-Host "  [INFO] SoftwareDistribution folder not found, nothing to clear" -ForegroundColor Gray
            }
        } catch {
            Write-Host "  [WARNING] Could not clear Windows Update cache: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Could not clear Windows Update cache: $($_.Exception.Message)"
        }
        
        try {
            Write-Host "  [ACTION] Starting Windows Update service..." -ForegroundColor White
            Start-Service -Name wuauserv
            Write-Host "  [SUCCESS] Windows Update service started" -ForegroundColor Green
            Write-Log -Level "SUCCESS" -Message "Started Windows Update service"
        } catch {
            Write-Host "  [WARNING] Could not start Windows Update service: $($_.Exception.Message)" -ForegroundColor Yellow
            Write-Log -Level "WARNING" -Message "Could not start Windows Update service: $($_.Exception.Message)"
        }
        
        # Check for disk space
        Write-Host "[STEP 2/4] Checking disk space..." -ForegroundColor Cyan
        try {
            $diskSpace = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object -ExpandProperty FreeSpace
            $freeSpaceGB = [math]::Round($diskSpace / 1GB, 2)
            Write-Host "  [INFO] Free disk space: $freeSpaceGB GB" -ForegroundColor White
            
            if ($diskSpace -lt 1073741824) { # 1 GB in bytes
                Write-Host "  [ERROR] Insufficient disk space available on the system drive. Please free up disk space and try again." -ForegroundColor Red
                Write-Log -Level "ERROR" -Message "Insufficient disk space for Windows Updates" -Console
                throw "Insufficient disk space"
            } else {
                Write-Host "  [SUCCESS] Sufficient disk space available" -ForegroundColor Green
            }
        } catch {
            if ($_.Exception.Message -ne "Insufficient disk space") {
                Write-Host "  [WARNING] Could not check disk space: $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "Could not check disk space: $($_.Exception.Message)"
            } else {
                throw
            }
        }
        
        # Check for updates using COM object
        Write-Host "[STEP 3/4] Searching for available updates..." -ForegroundColor Cyan
        $script:WindowsUpdateStatus = "Unknown"
        try {
            Write-Host "  [INFO] Connecting to Windows Update service..." -ForegroundColor White
            $wuSession = New-Object -ComObject Microsoft.Update.Session
            $wuSearcher = $wuSession.CreateUpdateSearcher()
            Write-Host "  [INFO] Searching for updates (this may take several minutes)..." -ForegroundColor White
            $searchResult = $wuSearcher.Search("IsInstalled=0 and Type='Software'")            
            if ($searchResult.Updates.Count -gt 0) {
                Write-Host "  [SUCCESS] Found $($searchResult.Updates.Count) update(s) to install" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "Found $($searchResult.Updates.Count) update(s) to install" -Console
                
                $totalUpdates = $searchResult.Updates.Count
                $updateCounter = 0
                $successfulUpdates = 0
                $failedUpdates = 0
                
                Write-Host "[STEP 4/4] Installing updates..." -ForegroundColor Cyan
                Write-Host "  [INFO] This process may take a significant amount of time..." -ForegroundColor Yellow
                
                # Initialize progress bar
                Write-Progress -Activity "Installing Windows Updates" -Status "0% Complete" -PercentComplete 0
                
                # Create update collection for downloads
                $updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl                
                # Add updates that need to be downloaded
                foreach ($update in $searchResult.Updates) {
                    if ($update.IsDownloaded -eq $false) {
                        try {
                            $updatesToDownload.Add($update) | Out-Null
                        } catch {
                            Write-Host "    [WARNING] Could not add update to download collection: $($update.Title)" -ForegroundColor Yellow
                            Write-Log -Level "WARNING" -Message "Could not add update to download collection: $($update.Title)"
                        }
                    }
                }
                
                # Download updates if needed
                if ($updatesToDownload.Count -gt 0) {
                    Write-Host "  [INFO] Downloading $($updatesToDownload.Count) update(s)..." -ForegroundColor White
                    try {
                        $downloader = $wuSession.CreateUpdateDownloader()
                        $downloader.Updates = $updatesToDownload
                        $downloadResult = $downloader.Download()
                        
                        if ($downloadResult.ResultCode -eq 2) {
                            Write-Host "  [SUCCESS] Updates downloaded successfully" -ForegroundColor Green
                        } else {
                            Write-Host "  [WARNING] Download returned code: $($downloadResult.ResultCode)" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "  [WARNING] Download failed: $($_.Exception.Message)" -ForegroundColor Yellow
                    }
                }
                
                # Install updates
                foreach ($update in $searchResult.Updates) {
                    $updateCounter++
                    $percentComplete = [math]::Round(($updateCounter / $totalUpdates) * 100)
                    Write-Progress -Activity "Installing Windows Updates" -Status "$percentComplete% Complete - Update $updateCounter of $totalUpdates" -CurrentOperation "$($update.Title)" -PercentComplete $percentComplete
                    
                    # Install update
                    try {
                        $installer = $wuSession.CreateUpdateInstaller()
                        $updatesToInstall = New-Object -ComObject Microsoft.Update.UpdateColl
                        $updatesToInstall.Add($update) | Out-Null
                        $installer.Updates = $updatesToInstall
                        $installResult = $installer.Install()                        
                        if ($installResult.ResultCode -eq 2) {
                            Write-Host "    [SUCCESS] Update installed successfully" -ForegroundColor Green
                            Write-Log -Level "SUCCESS" -Message "Installed update: $($update.Title)"
                            $successfulUpdates++
                        } elseif ($installResult.ResultCode -eq 3010) {
                            Write-Host "    [SUCCESS] Update installed (restart required)" -ForegroundColor Green
                            Write-Log -Level "SUCCESS" -Message "Installed update (restart required): $($update.Title)"
                            $successfulUpdates++
                        } else {
                            Write-Host "    [WARNING] Update installation returned code $($installResult.ResultCode): $($update.Title)" -ForegroundColor Yellow
                            Write-Log -Level "WARNING" -Message "Update installation returned code $($installResult.ResultCode): $($update.Title)"
                            $failedUpdates++
                        }
                    } catch {
                        Write-Host "    [ERROR] Failed to install update: $($_.Exception.Message)" -ForegroundColor Red
                        Write-Log -Level "ERROR" -Message "Failed to install update $($update.Title): $($_.Exception.Message)"
                        $failedUpdates++
                    }
                }
                
                Write-Progress -Activity "Installing Windows Updates" -Completed
                Write-Host "  [INFO] Update installation summary:" -ForegroundColor Cyan
                Write-Host "    Successful: $successfulUpdates" -ForegroundColor Green
                Write-Host "    Failed: $failedUpdates" -ForegroundColor $(if ($failedUpdates -eq 0) { "Green" } else { "Red" })
                
                if ($failedUpdates -eq 0) {
                    $script:WindowsUpdateStatus = "Completed"
                Write-Host "[SUCCESS] Windows Updates installation process completed." -ForegroundColor Green
                Write-Log -Level "SUCCESS" -Message "Windows Updates completed: $successfulUpdates succeeded, $failedUpdates failed" -Console
            } else {
                    $script:WindowsUpdateStatus = "Completed with errors"
                    Write-Host "[WARNING] Windows Updates completed with $failedUpdates failure(s)." -ForegroundColor Yellow
                    Write-Log -Level "WARNING" -Message "Windows Updates completed with errors: $successfulUpdates succeeded, $failedUpdates failed" -Console
                }
            } else {
                $script:WindowsUpdateStatus = "Completed - No updates available"
                Write-Host "  [INFO] No updates available - system is up to date" -ForegroundColor Green
                Write-Log -Level "INFO" -Message "No updates available" -Console
            }
        } catch {
            $script:WindowsUpdateStatus = "Failed - $($_.Exception.Message)"
            Write-Host "  [ERROR] Windows Update search/installation failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Log -Level "ERROR" -Message "Windows Update search/installation failed: $($_.Exception.Message)" -Console
            Write-Host "[WARNING] Windows Update process encountered an error. You may need to run Windows Update manually." -ForegroundColor Yellow
            throw
        }
    }
}

<#
.SYNOPSIS
    Runs comprehensive Stanford hardening script.
#>
function Run-StanfordHarden {
    [CmdletBinding()]
    param()
    
    Invoke-HardeningOperation -OperationName "Run Stanford Harden" -ScriptBlock {
        Write-Host "Running Stanford hardening script..." -ForegroundColor Cyan
        Write-Host "This may take a while..." -ForegroundColor Yellow
        
        # Start the Windows Firewall service
        try {
            Invoke-Expression "net start mpssvc" | Out-Null
            Write-Log -Level "SUCCESS" -Message "Started Windows Firewall service"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not start Windows Firewall service: $($_.Exception.Message)"
        }
        
        # Set multicastbroadcastresponse to disable for all profiles
        try {
            Invoke-Expression "netsh advfirewall firewall set multicastbroadcastresponse disable" | Out-Null
            Invoke-Expression "netsh advfirewall firewall set multicastbroadcastresponse mode=disable profile=all" | Out-Null
            Write-Log -Level "SUCCESS" -Message "Disabled multicast broadcast response"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not disable multicast broadcast response: $($_.Exception.Message)"
        }
        
        # Set logging settings for Domain, Private, and Public profiles
        $firewallLoggingCommands = @(
            "netsh advfirewall set Domainprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log",
            "netsh advfirewall set Domainprofile logging maxfilesize 20000",
            "netsh advfirewall set Privateprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log",
            "netsh advfirewall set Privateprofile logging maxfilesize 20000",
            "netsh advfirewall set Publicprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log",
            "netsh advfirewall set Publicprofile logging maxfilesize 20000",
            "netsh advfirewall set Publicprofile logging droppedconnections enable",
            "netsh advfirewall set Publicprofile logging allowedconnections enable",
            "netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log",
            "netsh advfirewall set currentprofile logging maxfilesize 4096",
            "netsh advfirewall set currentprofile logging droppedconnections enable",
            "netsh advfirewall set currentprofile logging allowedconnections enable"
        )
        
        foreach ($cmd in $firewallLoggingCommands) {
            try {
                Invoke-Expression $cmd | Out-Null
            } catch {
                Write-Verbose "Firewall logging command failed: $cmd"
            }
        }
        Write-Log -Level "SUCCESS" -Message "Configured firewall logging"
        
        # Start Defender Service
        try {
            Start-Service -Name WinDefend
            Write-Log -Level "SUCCESS" -Message "Started Windows Defender service"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not start Windows Defender service: $($_.Exception.Message)"
        }
        
        # Set Defender Policies (similar to Enable-Windows-Defender but with Stanford-specific settings)
        $defenderPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        $defenderScanPath = "$defenderPath\Scan"
        $defenderRealTimeProtectionPath = "$defenderPath\Real-Time Protection"
        $defenderReportingPath = "$defenderPath\Reporting"
        $defenderSpynetPath = "$defenderPath\Spynet"
        $defenderFeaturesPath = "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features"
        
        # Create paths if needed
        $pathsToCreate = @($defenderPath, $defenderScanPath, $defenderRealTimeProtectionPath, $defenderReportingPath, $defenderSpynetPath)
        foreach ($path in $pathsToCreate) {
            if (-not (Test-Path $path)) {
                New-Item -Path $path -Force | Out-Null
            }
        }
        
        # Set Defender registry values
        $defenderRegValues = @(
            @{Path=$defenderPath; Name="DisableAntiSpyware"; Value=0; Type="DWORD"},
            @{Path=$defenderPath; Name="DisableAntiVirus"; Value=0; Type="DWORD"},
            @{Path=$defenderPath; Name="ServiceKeepAlive"; Value=1; Type="DWORD"},
            @{Path=$defenderScanPath; Name="DisableHeuristics"; Value=0; Type="DWORD"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments"; Name="ScanWithAntiVirus"; Value=3; Type="DWORD"},
            @{Path=$defenderRealTimeProtectionPath; Name="DisableRealtimeMonitoring"; Value=0; Type="DWORD"},
            @{Path=$defenderScanPath; Name="CheckForSignaturesBeforeRunningScan"; Value=1; Type="DWORD"},
            @{Path=$defenderRealTimeProtectionPath; Name="DisableBehaviorMonitoring"; Value=1; Type="DWORD"},
            @{Path=$defenderReportingPath; Name="DisableGenericRePorts"; Value=1; Type="DWORD"},
            @{Path=$defenderSpynetPath; Name="LocalSettingOverrideSpynetReporting"; Value=0; Type="DWORD"},
            @{Path=$defenderSpynetPath; Name="SubmitSamplesConsent"; Value=2; Type="DWORD"},
            @{Path=$defenderSpynetPath; Name="DisableBlockAtFirstSeen"; Value=1; Type="DWORD"},
            @{Path=$defenderSpynetPath; Name="SpynetReporting"; Value=0; Type="DWORD"}
        )
        
        foreach ($regValue in $defenderRegValues) {
            try {
                if (-not (Test-Path $regValue.Path)) {
                    New-Item -Path $regValue.Path -Force | Out-Null
                }
                New-ItemProperty -Path $regValue.Path -Name $regValue.Name -Value $regValue.Value -PropertyType $regValue.Type -Force | Out-Null
            } catch {
                Write-Verbose "Could not set Defender registry: $($regValue.Path)\$($regValue.Name)"
            }
        }
        
        # Enable Tamper Protection
        if ($script:OSInfo.OSFamily -in "Client10", "Client11", "Server2019", "Server2022") {
            try {
                if (-not (Test-Path $defenderFeaturesPath)) {
                    New-Item -Path $defenderFeaturesPath -Force | Out-Null
                }
                New-ItemProperty -Path $defenderFeaturesPath -Name "TamperProtection" -Value 5 -PropertyType DWORD -Force | Out-Null
                Write-Log -Level "SUCCESS" -Message "Enabled Tamper Protection"
            } catch {
                Write-Verbose "Could not enable Tamper Protection (may already be enabled)"
            }
        }
        
        # Start Windows Update Service and set startup type to automatic
        try {
            Set-Service -Name wuauserv -StartupType Automatic
            Start-Service -Name wuauserv
            Write-Log -Level "SUCCESS" -Message "Configured Windows Update service"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not configure Windows Update service: $($_.Exception.Message)"
        }
        
        # Delete netlogon fullsecurechannelprotection then add a new key with it enabled
        try {
            Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force -ErrorAction SilentlyContinue
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -PropertyType DWORD -Force | Out-Null
            Write-Log -Level "SUCCESS" -Message "Enabled FullSecureChannelProtection"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not configure FullSecureChannelProtection: $($_.Exception.Message)"
        }
        
        # Disable the print spooler and make it never start
        try {
            Get-Service -Name Spooler | Stop-Service -Force
            Set-Service -Name Spooler -StartupType Disabled
            Write-Log -Level "SUCCESS" -Message "Disabled Print Spooler service"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not disable Print Spooler: $($_.Exception.Message)"
        }
        
        # DISM commands to disable insecure and unnecessary features
        $dismFeatures = @("TFTP", "TelnetClient", "TelnetServer", "SMB1Protocol")
        foreach ($feature in $dismFeatures) {
            try {
                $dismCmd = "dism /online /disable-feature /featurename:$feature /NoRestart"
                Invoke-Expression "cmd /c `"$dismCmd`"" | Out-Null
                Write-Log -Level "SUCCESS" -Message "Disabled feature: $feature"
            } catch {
                Write-Verbose "Could not disable feature $feature (may not be installed)"
            }
        }
        
        # Disables editing registry remotely
        try {
            Get-Service -Name RemoteRegistry | Stop-Service -Force
            Set-Service -Name RemoteRegistry -StartupType Disabled
            Write-Log -Level "SUCCESS" -Message "Disabled Remote Registry service"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not disable Remote Registry: $($_.Exception.Message)"
        }
        
        # Remove accessibility backdoors (sticky keys, utility manager, etc.)
        $backdoorFiles = @(
            "C:\Windows\System32\sethc.exe",
            "C:\Windows\System32\Utilman.exe",
            "C:\Windows\System32\osk.exe",
            "C:\Windows\System32\Narrator.exe",
            "C:\Windows\System32\Magnify.exe"
        )
        
        foreach ($file in $backdoorFiles) {
            if (Test-Path $file) {
                try {
                    # Remove registry entries first
                    $fileName = Split-Path $file -Leaf
                    $regPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$fileName"
                    reg delete $regPath /f 2>$null | Out-Null
                    
                    # Take ownership and remove file
                    Start-Process takeown.exe -ArgumentList "/f $file" -NoNewWindow -Wait
                    Start-Process icacls.exe -ArgumentList "$file /grant administrators:F" -NoNewWindow -Wait
                    Remove-Item -Path $file -Force
                    Write-Log -Level "SUCCESS" -Message "Removed backdoor file: $fileName"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not remove backdoor file $file : $($_.Exception.Message)"
                }
            }
        }
        
        # Delete Scheduled Tasks
        try {
            Get-ScheduledTask | Unregister-ScheduledTask -Confirm:$false
            Write-Log -Level "SUCCESS" -Message "Removed scheduled tasks"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not remove all scheduled tasks: $($_.Exception.Message)"
        }
        
        # Disable Guest user
        try {
            net user Guest /active:no 2>$null | Out-Null
            Write-Log -Level "SUCCESS" -Message "Disabled Guest user"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not disable Guest user: $($_.Exception.Message)"
        }
        
        # Additional registry hardening
        $registryHardening = @(
            @{Path="HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"; Name="NoDataExecutionPrevention"; Value=0; Type="REG_DWORD"},
            @{Path="HKLM\SOFTWARE\Policies\Microsoft\Windows\System"; Name="DisableHHDEP"; Value=0; Type="REG_DWORD"},
            @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"; Name="AddPrinterDrivers"; Value=1; Type="REG_DWORD"},
            @{Path="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoAutorun"; Value=1; Type="REG_DWORD"},
            @{Path="HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"; Name="NoDriveTypeAutoRun"; Value=255; Type="REG_DWORD"},
            @{Path="HKLM\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LimitBlankPasswordUse"; Value=1; Type="REG_DWORD"},
            @{Path="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Name="AllocateCDRoms"; Value=1; Type="REG_DWORD"}
        )
        
        foreach ($reg in $registryHardening) {
            try {
                reg add $reg.Path /v $reg.Name /t $reg.Type /d $reg.Value /f 2>$null | Out-Null
            } catch {
                Write-Verbose "Could not set registry: $($reg.Path)\$($reg.Name)"
            }
        }
        Write-Log -Level "SUCCESS" -Message "Applied registry hardening"
        
        # Enable logging for EVERYTHING
        try {
            auditpol /set /category:* /success:enable /failure:enable 2>$null | Out-Null
            Write-Log -Level "SUCCESS" -Message "Enabled comprehensive auditing"
        } catch {
            Write-Log -Level "WARNING" -Message "Could not enable all auditing: $($_.Exception.Message)"
        }
        
        # Additional hardening steps with OS-specific validation
        Write-Host "[INFO] Applying additional registry hardening..." -ForegroundColor Cyan
        $additionalRegHardening = @(
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLmHash"; Value=1; Description="Disable LM hash storage"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5; Description="Require NTLMv2 authentication"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Value=0; Description="Disable WDigest credential storage"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Value=0; Description="Disable remote UAC for local accounts"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Value=1; Description="Enable LSASS Protection"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP"; Name="UserAuthentication"; Value=1; Description="Require Network Level Authentication for RDP"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="AllowTSConnections"; Value=1; Description="Allow Terminal Services connections"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="fDenyTSConnections"; Value=0; Description="Do not deny TS connections"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1; Description="Enable User Account Control"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=2; Description="UAC prompt behavior for admins"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Value=0; Description="UAC prompt behavior for users"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Value=1; Description="Prompt on secure desktop"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Value=1; Description="Enable installer detection"}
        )
        
        $regSuccessCount = 0
        $regFailureCount = 0
        
        foreach ($reg in $additionalRegHardening) {
            try {
                Write-Host "  [ACTION] Setting $($reg.Name): $($reg.Description)" -ForegroundColor Cyan
                Set-RegistryValue -Path $reg.Path -Name $reg.Name -Value $reg.Value -PropertyType "DWord" -OperationName "Stanford Harden - $($reg.Name)" -CreatePathIfMissing
                $regSuccessCount++
            } catch {
                Write-Host "  [WARNING] Could not set registry: $($reg.Path)\$($reg.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "Could not set registry: $($reg.Path)\$($reg.Name) - $($_.Exception.Message)"
                $regFailureCount++
            }
        }
        
        Write-Host "[INFO] Registry hardening: $regSuccessCount succeeded, $regFailureCount failed" -ForegroundColor $(if ($regFailureCount -eq 0) { "Green" } else { "Yellow" })
        Write-Log -Level "SUCCESS" -Message "Applied additional registry hardening ($regSuccessCount values set)"
        
        Write-Host "Stanford hardening completed successfully" -ForegroundColor Green
    }
}

<#
.SYNOPSIS
    Configures registry hardening settings with proper error handling.
#>
function Set-RegistryHardening {
    [CmdletBinding()]
    param()
    
    Write-Host "Configuring registry hardening..." -ForegroundColor Cyan
    
    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[FAILED] Must run as Administrator to modify registry" -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Registry hardening requires Administrator privileges"
        return
    }
    
    Invoke-HardeningOperation -OperationName "Set Registry Hardening" -ProgressMessage "Applying registry hardening settings" -ScriptBlock {
        Write-Host "[INFO] Applying registry hardening settings..." -ForegroundColor Cyan
        
        # Registry hardening settings
        $registryHardening = @(
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="NoLmHash"; Value=1; Description="Disable LM hash storage"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="LmCompatibilityLevel"; Value=5; Description="Require NTLMv2 authentication"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"; Name="UseLogonCredential"; Value=0; Description="Disable WDigest credential storage"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="LocalAccountTokenFilterPolicy"; Value=0; Description="Disable remote UAC for local accounts"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name="RunAsPPL"; Value=1; Description="Enable LSASS Protection"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP"; Name="UserAuthentication"; Value=1; Description="Require Network Level Authentication for RDP"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="AllowTSConnections"; Value=1; Description="Allow Terminal Services connections"},
            @{Path="HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"; Name="fDenyTSConnections"; Value=0; Description="Do not deny TS connections"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableLUA"; Value=1; Description="Enable User Account Control"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorAdmin"; Value=2; Description="UAC prompt behavior for admins"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="ConsentPromptBehaviorUser"; Value=0; Description="UAC prompt behavior for users"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="PromptOnSecureDesktop"; Value=1; Description="Prompt on secure desktop"},
            @{Path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name="EnableInstallerDetection"; Value=1; Description="Enable installer detection"}
        )
        
        $regSuccessCount = 0
        $regFailureCount = 0
        
        foreach ($reg in $registryHardening) {
            try {
                # Test registry path before trying to modify
                $registryPath = $reg.Path
                
                Write-Host "  [ACTION] Setting $($reg.Name): $($reg.Description)" -ForegroundColor Cyan
                
                # Use Set-RegistryValue helper function which handles path creation and property checking
                $result = Set-RegistryValue -Path $registryPath -Name $reg.Name -Value $reg.Value -PropertyType "DWord" -OperationName "Registry Hardening - $($reg.Name)" -CreatePathIfMissing
                
                if ($result) {
                    $regSuccessCount++
                } else {
                    $regFailureCount++
                }
            } catch {
                Write-Host "  [WARNING] Could not set registry: $($reg.Path)\$($reg.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
                Write-Log -Level "WARNING" -Message "Could not set registry: $($reg.Path)\$($reg.Name) - $($_.Exception.Message)"
                $regFailureCount++
            }
        }
        
        Write-Host "[INFO] Registry hardening: $regSuccessCount succeeded, $regFailureCount failed" -ForegroundColor $(if ($regFailureCount -eq 0) { "Green" } else { "Yellow" })
        Write-Log -Level "SUCCESS" -Message "Applied registry hardening ($regSuccessCount values set)"
        
        Write-Host "Registry hardening completed successfully" -ForegroundColor Green
    }
}

#endregion

#region Menu and Main Execution Functions

<#
.SYNOPSIS
    Displays the main menu.
#>
function Show-Main-Menu {
    [CmdletBinding()]
    param()
    
    Clear-Host
    Write-Host "`n==== Local Windows Hardening Menu ====" -ForegroundColor Green
    Write-Host "Detected OS: $($script:OSInfo.OSVersion) (Build $($script:OSInfo.BuildNumber))" -ForegroundColor Cyan
    Write-Host "Edition: $($script:OSInfo.Edition)" -ForegroundColor Cyan
    Write-Host "`nPrerequisites:" -ForegroundColor Yellow
    Write-Host "  - (A) Initialize Context BEFORE running hardening tasks" -ForegroundColor Yellow
    Write-Host "  - Configure Splunk (11) works best after Initialize Context (A)" -ForegroundColor Yellow
    Write-Host "`nSelect an option by number (or Q to quit):" -ForegroundColor Cyan
    Write-Host "  0) Print Execution Summary"
    Write-Host "  A) Initialize Context (download files, set variables)"
    Write-Host "  1) Run Full Flow (original y/n prompts)"
    Write-Host "  2) Quick Harden (essential steps only)"
    Write-Host "  3) Get Competition Users"
    Write-Host "  4) Disable Users (except current user)"
    Write-Host "  5) Enable Windows Defender"
    Write-Host "  6) Add Competition Users"
    Write-Host "  7) Remove RDP Users (harden access)"
    Write-Host "  8) Configure Firewall"
    Write-Host "  9) Disable Unnecessary Services"
    Write-Host " 10) Enable Advanced Auditing + Firewall Logging"
    Write-Host " 11) Configure Splunk"
    Write-Host " 12) Install EternalBlue Patch"
    Write-Host " 13) Upgrade SMB (enable v2/3, disable v1)"
    Write-Host " 14) Patch Mimikatz (WDigest)"
    Write-Host " 15) Run Windows Updates"
    Write-Host " 16) Run Stanford Harden"
    Write-Host " 17) Set Registry Hardening"
    Write-Host " 18) Set Execution Policy to Restricted"
}

<#
.SYNOPSIS
    Runs all hardening functions with original flow.
#>
function Run-All {
    [CmdletBinding()]
    param()
    
    Initialize-Log
    Initialize-Context
    
    $confirmation = Prompt-Yes-No -Message "Disable every user but your own? (y/n)"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Disabling users***" -ForegroundColor Magenta
        Disable-Users 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Add Competition Users' function? (y/n)"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Adding Competition Users...***" -ForegroundColor Magenta
        Add-Competition-Users 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Remove users from RDP group except $($script:UserArray[0]) and $($script:UserArray[1])' function? (y/n)"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Removing every user from RDP group except $($script:UserArray[0]) and $($script:UserArray[1])...***" -ForegroundColor Magenta
        Remove-RDP-Users 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Configure Firewall' function? (y/n)"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Configuring firewall***" -ForegroundColor Magenta
        Configure-Firewall 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Disable unnecessary services (NetBIOS over TCP/IP, IPv6, closed port services)' function? (y/n)"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Disabling unnecessary services***" -ForegroundColor Magenta
        Disable-Unnecessary-Services 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    Write-Host "`n***Enabling advanced auditing***" -ForegroundColor Magenta
    if (Test-Path ".\advancedAuditing.ps1") {
        try {
            & .\advancedAuditing.ps1
            Update-Log "Enable Advanced Auditing" "Executed successfully"
            Write-Log -Level "SUCCESS" -Message "Advanced auditing script executed"
        } catch {
            Update-Log "Enable Advanced Auditing" "Failed with error: $($_.Exception.Message)"
            Write-Log -Level "ERROR" -Message "Advanced auditing script failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host "advancedAuditing.ps1 not found, skipping..." -ForegroundColor Yellow
        Update-Log "Enable Advanced Auditing" "Skipped - file not found"
        Write-Log -Level "WARNING" -Message "advancedAuditing.ps1 not found"
    }
    
    Write-Host "Enabling Firewall logging successful and blocked connections" -ForegroundColor Green
    try {
        Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
        Write-Log -Level "SUCCESS" -Message "Enabled firewall logging"
    } catch {
        Write-Log -Level "WARNING" -Message "Could not enable firewall logging: $($_.Exception.Message)"
    }
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Configure Splunk' function? (y/n)"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Configuring Splunk***" -ForegroundColor Magenta
        $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
        $SplunkVersion = Read-Host "`nInput OS Version (7, 8, 10, 11, 2012, 2016, 2019, 2022): "
        Download-Install-Setup-Splunk -Version $SplunkVersion -IP $SplunkIP
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    Write-Host "`n***Installing EternalBlue Patch***" -ForegroundColor Magenta
    Install-EternalBluePatch
    
    Write-Host "`n***Upgrading SMB***" -ForegroundColor Magenta
    Upgrade-SMB
    
    Write-Host "`n***Patching Mimikatz***" -ForegroundColor Magenta
    Patch-Mimikatz
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Run Windows Updates' function? (y/n) This might take a while"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Running Windows Updater***" -ForegroundColor Magenta
        Run-Windows-Updates 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    $confirmation = Prompt-Yes-No -Message "Enter the 'Stanford Harden' function? (y/n) This might take a while"
    if ($confirmation.toLower() -eq "y") { 
        Write-Host "`n***Running Stanford Harden***" -ForegroundColor Magenta
        Run-StanfordHarden 
    } else { 
        Write-Host "Skipping..." -ForegroundColor Red 
    }
    
    Write-Host "***Setting Execution Policy back to Restricted***" -ForegroundColor Red
    try {
        Set-ExecutionPolicy Restricted -Scope Process -Force        Update-Log "Set Execution Policy" "Executed successfully"
        Write-Log -Level "SUCCESS" -Message "Set execution policy to Restricted"
    } catch {
        Update-Log "Set Execution Policy" "Failed with error: $($_.Exception.Message)"
        Write-Log -Level "ERROR" -Message "Could not set execution policy: $($_.Exception.Message)"
    }
    
    Write-Host "`n***Script Completed!!!***" -ForegroundColor Green
    Print-Log
}

#endregion

#region Main Script Execution

# Display OS information at startup
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Windows Hardening Script v2.0" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

# Detect operating system
try {
    $script:OSInfo = Get-OperatingSystemInfo
    $script:OSVersion = $script:OSInfo.OSVersion
    $script:OSBuild = $script:OSInfo.BuildNumber
    $script:OSEdition = $script:OSInfo.Edition
    $script:IsServer = $script:OSInfo.IsServer
    $script:IsServerCore = $script:OSInfo.IsServerCore
    
    Write-Host "`nDetected Operating System:" -ForegroundColor Yellow
    Write-Host "  OS Version: $($script:OSInfo.OSVersion)" -ForegroundColor White
    Write-Host "  Build Number: $($script:OSInfo.BuildNumber)" -ForegroundColor White
    Write-Host "  Edition: $($script:OSInfo.Edition)" -ForegroundColor White
    Write-Host "  Is Server: $($script:OSInfo.IsServer)" -ForegroundColor White
    Write-Host "  Is Server Core: $($script:OSInfo.IsServerCore)" -ForegroundColor White
    Write-Host ""
} catch {
    Write-Host "`n[ERROR] Failed to detect operating system: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "The script may not function correctly. Continue anyway? (y/n)" -ForegroundColor Yellow
    $continue = Read-Host
    if ($continue -ne "y") {
        exit 1
    }
}

# Initialize logging
Initialize-Logging

# Perform pre-flight checks
try {
    Test-Prerequisites
} catch {
    Write-Host "`n[ERROR] Pre-flight checks failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log -Level "CRITICAL" -Message "Pre-flight checks failed: $($_.Exception.Message)" -Console
    exit 1
}

# Initialize function log
Initialize-Log

# Main execution loop
while ($true) {
    Show-Main-Menu
    $choice = Read-Host "Selection"
    if ($choice -match '^(?i)q$') { break }
    
    try {
        switch ($choice) {
            '0' { Print-Log }
            'A' { Initialize-System }
            '1' { Run-All }
            '2' { Write-Host "`n***Quick Hardening (Essential Steps Only)...***" -ForegroundColor Magenta; Quick-Harden }
            '3' { Write-Host "`n***Getting Competition Users...***" -ForegroundColor Magenta; GetCompetitionUsers }
            '4' { Write-Host "`n***Disabling users (except current user)...***" -ForegroundColor Magenta; Disable-Users }
            '5' { Write-Host "`n***Enabling Windows Defender...***" -ForegroundColor Magenta; Enable-Windows-Defender }
            '6' { Write-Host "`n***Adding Competition Users...***" -ForegroundColor Magenta; Add-Competition-Users }
            '7' { Write-Host "`n***Removing users from RDP group (except first two competition users)...***" -ForegroundColor Magenta; Remove-RDP-Users }
            '8' { Write-Host "`n***Configuring firewall...***" -ForegroundColor Magenta; Configure-Firewall }
            '9' { Write-Host "`n***Disabling unnecessary services...***" -ForegroundColor Magenta; Disable-Unnecessary-Services }
            '10' { 
                Write-Host "`n***Enabling Advanced Auditing and Firewall logging...***" -ForegroundColor Magenta
                if (Test-Path ".\advancedAuditing.ps1") {
                    try {
                        & .\advancedAuditing.ps1
                        Update-Log "Enable Advanced Auditing" "Executed successfully"
                        Write-Log -Level "SUCCESS" -Message "Advanced auditing script executed"
                    } catch {
                        Update-Log "Enable Advanced Auditing" "Failed with error: $($_.Exception.Message)"
                        Write-Log -Level "ERROR" -Message "Advanced auditing script failed: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "advancedAuditing.ps1 not found, skipping..." -ForegroundColor Yellow
                    Update-Log "Enable Advanced Auditing" "Skipped - file not found"
                    Write-Log -Level "WARNING" -Message "advancedAuditing.ps1 not found"
                }
                Write-Host "Enabling Firewall logging successful and blocked connections" -ForegroundColor Green
                try {
                    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
                    Write-Log -Level "SUCCESS" -Message "Enabled firewall logging"
                } catch {
                    Write-Log -Level "WARNING" -Message "Could not enable firewall logging: $($_.Exception.Message)"
                }
            }
            '11' {
                Write-Host "`n***Configuring Splunk...***" -ForegroundColor Magenta
                $SplunkIP = Read-Host "`nInput IP address of Splunk Server"
                $SplunkVersion = Read-Host "`nInput OS Version (7, 8, 10, 11, 2012, 2016, 2019, 2022): "
                Download-Install-Setup-Splunk -Version $SplunkVersion -IP $SplunkIP
            }
            '12' { Write-Host "`n***Installing EternalBlue Patch...***" -ForegroundColor Magenta; Install-EternalBluePatch }
            '13' { Write-Host "`n***Upgrading SMB...***" -ForegroundColor Magenta; Upgrade-SMB }
            '14' { Write-Host "`n***Patching Mimikatz (WDigest)...***" -ForegroundColor Magenta; Patch-Mimikatz }
            '15' { Write-Host "`n***Running Windows Updates...***" -ForegroundColor Magenta; Run-Windows-Updates }
            '16' { Write-Host "`n***Running Stanford Harden...***" -ForegroundColor Magenta; Run-StanfordHarden }
            '17' { Write-Host "`n***Setting Registry Hardening...***" -ForegroundColor Magenta; Set-RegistryHardening }
            '18' { 
                Write-Host "`n***Setting Execution Policy back to Restricted...***" -ForegroundColor Magenta
                try {
                    Set-ExecutionPolicy Restricted -Scope Process -Force
                    Update-Log "Set Execution Policy" "Executed successfully"
                    Write-Log -Level "SUCCESS" -Message "Set execution policy to Restricted"
                } catch {
                    Update-Log "Set Execution Policy" "Failed with error: $($_.Exception.Message)"
                    Write-Log -Level "ERROR" -Message "Could not set execution policy: $($_.Exception.Message)"
                }
            }
            Default { Write-Host "Invalid selection." -ForegroundColor Yellow }
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Error Occurred..." -ForegroundColor Red
        Write-Log -Level "ERROR" -Message "Menu operation error: $($_.Exception.Message)" -Console
    }
    
    Write-Host "`nPress Enter to return to menu..." -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# Final summary
Write-Host "`n***Script Completed!!!***" -ForegroundColor Green
Print-Log

# Write errors to file if any
if ($Error.Count -gt 0) {
    try {
        $errorFile = "$env:USERPROFILE\Desktop\hard.txt"
        $Error | Out-File $errorFile -Append -Encoding utf8
        Write-Log -Level "INFO" -Message "Errors written to $errorFile"
    } catch {
        Write-Log -Level "WARNING" -Message "Could not write errors to file: $($_.Exception.Message)"
    }
}

# Final log entry
Write-Log -Level "INFO" -Message "=== Script Execution Completed ===" -Console
Write-Log -Level "INFO" -Message "Log file location: $script:LogFile" -Console

# Determine final status
Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
if ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.CriticalErrors.Count -eq 0 -and $script:OperationResults.Skipped -eq 0) {
    Write-Host "[SUCCESS] Hardening completed successfully!" -ForegroundColor Green
    Write-Host "All $($script:OperationResults.Total) operation(s) completed without errors." -ForegroundColor Green
    Write-Log -Level "SUCCESS" -Message "=== Hardening completed successfully ===" -Console
} elseif ($script:OperationResults.Failed -eq 0 -and $script:OperationResults.CriticalErrors.Count -eq 0) {
    Write-Host "[SUCCESS] Hardening completed with warnings!" -ForegroundColor Green
    Write-Host "All operations completed, but $($script:OperationResults.Skipped) operation(s) were skipped (see details above)." -ForegroundColor Yellow
    Write-Log -Level "SUCCESS" -Message "=== Hardening completed with warnings ===" -Console
} else {
    Write-Host "[WARNING] Hardening completed with errors - review the summary above" -ForegroundColor Yellow
    Write-Host "Failed Operations: $($script:OperationResults.Failed)" -ForegroundColor Red
    Write-Host "Critical Errors: $($script:OperationResults.CriticalErrors.Count)" -ForegroundColor Red
    if ($script:OperationResults.CriticalErrors.Count -gt 0) {
        Write-Host "`nCritical errors occurred. Please review the errors above before considering the system hardened." -ForegroundColor Red
    }
    Write-Log -Level "ERROR" -Message "=== Hardening completed with errors ===" -Console
}
Write-Host ("=" * 60) -ForegroundColor Cyan

#endregion
