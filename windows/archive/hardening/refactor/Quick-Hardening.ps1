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
    [switch]$WhatIf
)

$ScriptPath = $PSScriptRoot
$StartTime = Get-Date

function Write-HardeningLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message"
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Quick Hardening Process" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-HardeningLog "Starting Quick Hardening Process" "INFO"

$ExecutedScripts = @()

if ($All -or $ExecutionPolicy) {
    Write-HardeningLog "Setting Execution Policy..." "INFO"
    & "$ScriptPath\Set-ExecutionPolicy.ps1"
    $ExecutedScripts += "Set-ExecutionPolicy.ps1"
}

if ($All -or $Services) {
    Write-HardeningLog "Disabling Unnecessary Services..." "INFO"
    & "$ScriptPath\Disable-Services.ps1"
    $ExecutedScripts += "Disable-Services.ps1"
}

if ($All -or $SMB) {
    Write-HardeningLog "Upgrading SMB..." "INFO"
    & "$ScriptPath\Upgrade-SMB.ps1"
    $ExecutedScripts += "Upgrade-SMB.ps1"
}

if ($All -or $Firewall) {
    Write-HardeningLog "Configuring Firewall..." "INFO"
    & "$ScriptPath\Configure-Firewall.ps1"
    $ExecutedScripts += "Configure-Firewall.ps1"
}

if ($All -or $Passwords) {
    Write-HardeningLog "Setting Passwords..." "INFO"
    & "$ScriptPath\Set-Passwords.ps1"
    $ExecutedScripts += "Set-Passwords.ps1"
}

if ($All -or $RDP) {
    Write-HardeningLog "Configuring RDP..." "INFO"
    & "$ScriptPath\Edit-RDP.ps1"
    $ExecutedScripts += "Edit-RDP.ps1"
}

if ($All -or $Admins) {
    Write-HardeningLog "Removing Unauthorized Admins..." "INFO"
    & "$ScriptPath\Remove-Admins.ps1"
    $ExecutedScripts += "Remove-Admins.ps1"
}

if ($All -or $Patches) {
    Write-HardeningLog "Installing Security Patches..." "INFO"
    & "$ScriptPath\Install-Patches.ps1"
    $ExecutedScripts += "Install-Patches.ps1"
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "`n========================================" -ForegroundColor Cyan
Write-HardeningLog "Quick Hardening Process Completed" "INFO"
Write-HardeningLog "Duration: $([math]::Round($Duration.TotalSeconds, 2)) seconds" "INFO"
Write-HardeningLog "Scripts Executed: $($ExecutedScripts.Count)" "INFO"
Write-Host "========================================" -ForegroundColor Cyan
