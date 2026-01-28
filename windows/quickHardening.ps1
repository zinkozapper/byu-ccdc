#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$All,
    
    [Parameter(Mandatory=$false)]
    [switch]$Passwords,
    
    [Parameter(Mandatory=$false)]
    [switch]$RDP,
    
    [Parameter(Mandatory=$false)]
    [switch]$Firewall,
    
    [Parameter(Mandatory=$false)]
    [switch]$SMB,
    
    [Parameter(Mandatory=$false)]
    [switch]$Patches,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExecutionPolicy,
    
    [Parameter(Mandatory=$false)]
    [switch]$Services,
    
    [Parameter(Mandatory=$false)]
    [switch]$Admins,

    [Parameter(Mandatory=$false)]
    [switch]$Splunk,

    [Parameter(Mandatory=$false)]
    [switch]$WhatIf
)

$ScriptPath = $PSScriptRoot
$StartTime = Get-Date
$BaseURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows"

function Write-HardeningLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message"
}

function Invoke-HardeningScript {
    param(
        [string]$ScriptName,
        [string]$BaseURL = $BaseURL
    )
    
    $ScriptURL = "$BaseURL/$ScriptName"
    
    try {
        Write-HardeningLog "Downloading $ScriptName from $ScriptURL" "DEBUG"
        $ScriptContent = (Invoke-WebRequest -Uri $ScriptURL -UseBasicParsing).Content
        Write-HardeningLog "Executing $ScriptName" "DEBUG"
        Invoke-Expression $ScriptContent
    }
    catch {
        Write-HardeningLog "Failed to download or execute $ScriptName : $_" "ERROR"
        throw $_
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Quick Hardening Process" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-HardeningLog "Starting Quick Hardening Process" "INFO"

$ExecutedScripts = @()

if ($All -or $ExecutionPolicy) {
    Write-HardeningLog "Setting Execution Policy..." "INFO"
    Invoke-HardeningScript "restrictExecutionPolicy.ps1"
    $ExecutedScripts += "restrictExecutionPolicy.ps1"
}

if ($All -or $Services) {
    Write-HardeningLog "Disabling Unnecessary Services..." "INFO"
    Invoke-HardeningScript "disableUnnecessaryServices.ps1"
    $ExecutedScripts += "disableUnnecessaryServices.ps1"
}

if ($All -or $SMB) {
    Write-HardeningLog "Upgrading SMB..." "INFO"
    Invoke-HardeningScript "Upgrade-SMB.ps1"
    $ExecutedScripts += "Upgrade-SMB.ps1"
}

if ($All -or $Firewall) {
    Write-HardeningLog "Configuring Firewall..." "INFO"
    Invoke-HardeningScript "Configure-Firewall.ps1"
    $ExecutedScripts += "Configure-Firewall.ps1"
}

if ($All -or $Passwords) {
    Write-HardeningLog "Setting Passwords..." "INFO"
    Invoke-HardeningScript "zulu.ps1"
    $ExecutedScripts += "zulu.ps1"
}

if ($All -or $RDP) {
    Write-HardeningLog "Configuring RDP..." "INFO"
    Invoke-HardeningScript "Edit-RDP.ps1"
    $ExecutedScripts += "Edit-RDP.ps1"
}

#if ($All -or $Admins) {
#    Write-HardeningLog "Removing Unauthorized Admins..." "INFO"
#    Invoke-HardeningScript "Remove-Admins.ps1"
#    $ExecutedScripts += "Remove-Admins.ps1"
#}

#if ($All -or $Patches) {
#    Write-HardeningLog "Installing Security Patches..." "INFO"
#    Invoke-HardeningScript "installPatches.ps1"
#    $ExecutedScripts += "installPatches.ps1"
#}

if ($All -or $Splunk) {
    Write-HardeningLog "Installing Splunk..." "INFO"
    Invoke-HardeningScript "setupSplunk.ps1"
    $ExecutedScripts += "setupSplunk.ps1"
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "`n========================================" -ForegroundColor Cyan
Write-HardeningLog "Quick Hardening Process Completed" "INFO"
Write-HardeningLog "Duration: $([math]::Round($Duration.TotalSeconds, 2)) seconds" "INFO"
Write-HardeningLog "Scripts Executed: $($ExecutedScripts.Count)" "INFO"
Write-Host "========================================" -ForegroundColor Cyan
