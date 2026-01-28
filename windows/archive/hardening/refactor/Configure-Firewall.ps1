#Requires -RunAsAdministrator

$IsDomainController = $false
try {
    $CS = Get-WmiObject -Class Win32_ComputerSystem
    $IsDomainController = $CS.DomainRole -in @(4,5)
} catch { }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Configuring Windows Firewall" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

#This will default disable all inbound traffic on the firewall.

param(
    [Parameter(Mandatory=$false)]
    [Alias('f')]
    [string]$Ports,
    
    [Parameter(Mandatory=$false)]
    [switch]$EnableWinRM = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$BlockAllOutbound = $false
)

# Parse ports parameter if provided
$AllowedInboundPorts = @("80")
if ($Ports) {
    # Handle comma-separated ports with or without spaces (e.g., "80,443" or "80, 443")
    $AllowedInboundPorts = @($Ports -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' })
    if ($AllowedInboundPorts.Count -eq 0) {
        Write-Host "[ERROR] Invalid port specification. Use comma-separated numbers (e.g., 80,443 or 80, 443)" -ForegroundColor Red
        exit 1
    }
}

# Add WinRM ports if enabled
if ($EnableWinRM) {
    Write-Host "[*] WinRM testing enabled - adding ports 5985 (HTTP) and 5986 (HTTPS)" -ForegroundColor Yellow
    $AllowedInboundPorts = @($AllowedInboundPorts + @("5985", "5986")) | Select-Object -Unique
}

if ($IsDomainController) {
    Write-Host "[*] Domain Controller detected - adding required DC ports" -ForegroundColor Yellow
    $DCRequiredPorts = @("53", "88", "135", "139", "389", "445", "464", "636", "3268", "3269")
    $AllowedInboundPorts = ($AllowedInboundPorts + $DCRequiredPorts) | Select-Object -Unique
}

try {
    #Disable all existing rules
    Write-Host "[*] Disabling all old firewall rules..." -ForegroundColor Yellow
    Set-NetFirewallProfile -All -Enabled True
    Get-NetFirewallRule | Disable-NetFirewallRule
    
    Write-Host "[SUCCESS] All existing rules disabled" -ForegroundColor Green

    
    Write-Host "`n[*] Setting firewall default policies..." -ForegroundColor Yellow
    Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -ErrorAction SilentlyContinue
    
    if ($BlockAllOutbound) {
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
    $PortDescriptions = @{
        "22" = "SSH"
        "53" = "DNS"
        "80" = "HTTP"
        "88" = "Kerberos"
        "135" = "RPC"
        "139" = "NetBIOS"
        "389" = "LDAP"
        "443" = "HTTPS"
        "445" = "SMB"
        "464" = "Kerberos-pwd"
        "636" = "LDAPS"
        "3268" = "LDAP-GC"
        "3269" = "LDAPS-GC"
        "3389" = "RDP"
        "5985" = "WinRM-HTTP"
        "5986" = "WinRM-HTTPS"
    }
    
    foreach ($Port in ($AllowedInboundPorts | Sort-Object -Unique)) {
        $PortDesc = if ($PortDescriptions.ContainsKey($Port)) { $PortDescriptions[$Port] } else { "Port-$Port" }
        
        New-NetFirewallRule -DisplayName "Allow-Inbound-TCP-$Port" `
            -Direction Inbound -LocalPort $Port -Protocol TCP -Action Allow `
            -ErrorAction SilentlyContinue | Out-Null
        
        Write-Host "  [+] TCP port $Port ($PortDesc)" -ForegroundColor Green
    }
    
    Write-Host "`n[SUCCESS] Firewall configuration completed" -ForegroundColor Green
    
} catch {
    Write-Host "[ERROR] Firewall configuration failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "[COMPLETED] Firewall hardening finished" -ForegroundColor Green
