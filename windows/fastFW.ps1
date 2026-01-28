#Requires -RunAsAdministrator

$IsDomainController = $false
try {
    $CS = Get-WmiObject -Class Win32_ComputerSystem
    $IsDomainController = $CS.DomainRole -in @(4,5)
} catch { }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Configuring Windows Firewall" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

param(
    [Alias('f')][string]$Ports,
    [switch]$EnableWinRM = $false,
    [switch]$BlockAllOutbound = $false,
    [Alias('h')][switch]$Help,
    [Alias('b')][string]$BackupFile,
    [switch]$Restore
)

# Defaults
$DefaultBackupPath = Join-Path -Path $PSScriptRoot -ChildPath "initfirewall.bak"

function Show-Help {
    Write-Host "Usage: fastFW.ps1 [-f <ports>] [-EnableWinRM] [-BlockAllOutbound] [-b <backup>] [-Restore] [-h]" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -f <ports>            Comma-separated list of inbound TCP ports to allow (e.g., 80,443)" -ForegroundColor Cyan
    Write-Host "  -EnableWinRM          Add WinRM ports 5985 and 5986" -ForegroundColor Cyan
    Write-Host "  -BlockAllOutbound     Set default outbound action to Block" -ForegroundColor Cyan
    Write-Host "  -b <backup>           Backup file path to use or restore from (defaults to initfirewall.bak)" -ForegroundColor Cyan
    Write-Host "  -Restore              Import firewall configuration from backup and exit" -ForegroundColor Cyan
    Write-Host "  -h, -Help             Show this help message" -ForegroundColor Cyan
}

function Restore-Firewall {
    param([string]$PathToBackup)
    $path = $PathToBackup ? $PathToBackup : $DefaultBackupPath
    if (-not (Test-Path $path)) { Write-Host "[ERROR] Backup file not found: $path" -ForegroundColor Red; exit 1 }
    try {
        Write-Host "Restoring firewall from $path..." -ForegroundColor Yellow
        netsh advfirewall import `"$path`"
        Write-Host "[SUCCESS] Firewall restored from $path" -ForegroundColor Green
        exit 0
    } catch { Write-Host "[ERROR] Failed to restore firewall: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}

function Backup-Firewall {
    param([string]$PathToBackup)
    $path = $PathToBackup ? $PathToBackup : $DefaultBackupPath
    try {
        Write-Host "Creating firewall backup at $path..." -ForegroundColor Yellow
        netsh advfirewall export `"$path`" 2>$null
        if (-not (Test-Path $path)) { throw "Export did not produce backup file" }
        Write-Host "[SUCCESS] Backup created: $path" -ForegroundColor Green
        return $path
    } catch { Write-Host "[ERROR] Failed to create firewall backup: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}

function Parse-AllowedPorts {
    param([string]$PortsParam, [bool]$IsDC)
    if ($PortsParam) {
        $arr = @($PortsParam -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })
        if ($arr.Count -eq 0) { Write-Host "[ERROR] Invalid port specification. Use comma-separated numbers." -ForegroundColor Red; exit 1 }
        return $arr
    }
    if (-not $IsDC) {
        $input = Read-Host "No ports specified. Enter comma-separated ports to allow (e.g., 80,443). Leave blank to default to 80"
        if ($input -and $input.Trim() -ne "") {
            $arr = @($input -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })
            if ($arr.Count -eq 0) { Write-Host "[ERROR] Invalid port specification. Use comma-separated numbers." -ForegroundColor Red; exit 1 }
            return $arr
        }
        Write-Host "No ports entered; defaulting to port 80." -ForegroundColor Yellow
        return @("80")
    }
    return @()
}

function Configure-Firewall {
    param([string[]]$PortsToAllow, [bool]$EnableWinRMFlag, [bool]$IsDCFlag, [bool]$BlockOutbound)
    try {
        Write-Host "[*] Disabling all old firewall rules..." -ForegroundColor Yellow
        Set-NetFirewallProfile -All -Enabled True
        Get-NetFirewallRule | Disable-NetFirewallRule
        Write-Host "[SUCCESS] All existing rules disabled" -ForegroundColor Green

        Write-Host "`n[*] Setting firewall default policies..." -ForegroundColor Yellow
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
        if ($BlockOutbound) {
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -ErrorAction SilentlyContinue
            Write-Host "[SUCCESS] Default actions set (Block Inbound, Block Outbound)" -ForegroundColor Green
        } else {
            Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction SilentlyContinue
            Write-Host "[SUCCESS] Default actions set (Block Inbound, Allow Outbound)" -ForegroundColor Green
        }

        Write-Host "`n[*] Removing old custom rules..." -ForegroundColor Yellow
        Get-NetFirewallRule | Where-Object { $_.DisplayName -like "Allow-Inbound-*" } | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Host "[SUCCESS] Old rules cleaned" -ForegroundColor Green

        Write-Host "`n[*] Adding allowed inbound ports..." -ForegroundColor Yellow
        foreach ($Port in ($PortsToAllow | Sort-Object -Unique)) {
            New-NetFirewallRule -DisplayName "Allow-Inbound-TCP-$Port" -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow -ErrorAction SilentlyContinue | Out-Null
            Write-Host "[+] TCP port $Port" -ForegroundColor Green
        }

        Write-Host "`n[SUCCESS] Firewall configuration completed" -ForegroundColor Green
    } catch { Write-Host "[ERROR] Firewall configuration failed: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}

# Entry point
if ($Help) { Show-Help; exit 0 }
if ($Restore) { Restore-Firewall -PathToBackup $BackupFile }

# Create backup
$createdBackup = Backup-Firewall -PathToBackup $BackupFile

# Determine ports
$AllowedInboundPorts = Parse-AllowedPorts -PortsParam $Ports -IsDC $IsDomainController

# Add WinRM ports if enabled
if ($EnableWinRM) {
    Write-Host "[*] WinRM testing enabled - adding ports 5985 (HTTP) and 5986 (HTTPS)" -ForegroundColor Yellow
    $AllowedInboundPorts = @($AllowedInboundPorts + @("5985", "5986")) | Select-Object -Unique
}

# Add DC required ports when applicable
if ($IsDomainController) {
    Write-Host "[*] Domain Controller detected - adding required DC ports" -ForegroundColor Yellow
    $DCRequiredPorts = @("53", "88", "135", "139", "389", "445", "464", "636", "3268", "3269")
    $AllowedInboundPorts = ($AllowedInboundPorts + $DCRequiredPorts) | Select-Object -Unique
}

Configure-Firewall -PortsToAllow $AllowedInboundPorts -EnableWinRMFlag $EnableWinRM -IsDCFlag $IsDomainController -BlockOutbound $BlockAllOutbound
Write-Host "[COMPLETED] Firewall hardening finished" -ForegroundColor Green
