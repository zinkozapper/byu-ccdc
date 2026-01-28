#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Upgrading SMB Configuration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

#See if SMB is installed and if not exit the script.
try {
    if (-not (Get-Module -ListAvailable -Name SmbShare)) {
        Write-Host "[ERROR] SMB module is not available on this system" -ForegroundColor Red
        exit 1
    }
    Write-Host "[SUCCESS] SMB detected on system" -ForegroundColor Green
    
    Write-Host "[*] Detecting current SMB configuration..." -ForegroundColor Cyan
    $smbConfig = Get-SmbServerConfiguration
    $smbv1Enabled = $smbConfig.EnableSMB1Protocol
    $smbv2Enabled = $smbConfig.EnableSMB2Protocol
    $smbv3Enabled = $null
    try {
        $smbv3Enabled = $smbConfig.EnableSMB3Protocol
    } catch { }
    
    Write-Host "`n[INFO] Current SMB Configuration:" -ForegroundColor Cyan
    Write-Host "  SMBv1: $(if ($smbv1Enabled) { 'Enabled (VULNERABLE)' } else { 'Disabled' })" -ForegroundColor $(if ($smbv1Enabled) { 'Red' } else { 'Green' })
    Write-Host "  SMBv2: $(if ($smbv2Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv2Enabled) { 'Green' } else { 'Yellow' })
    if ($null -ne $smbv3Enabled) {
        Write-Host "  SMBv3: $(if ($smbv3Enabled) { 'Enabled' } else { 'Disabled' })" -ForegroundColor $(if ($smbv3Enabled) { 'Green' } else { 'Yellow' })
    }
    
    $needsRestart = $false
    
    if ($smbv2Enabled -eq $false) {
        Write-Host "`n[*] Enabling SMBv2..." -ForegroundColor Yellow
        try {
            Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction Stop
            Write-Host "[SUCCESS] SMBv2 enabled" -ForegroundColor Green
            $needsRestart = $true
        } catch {
            Write-Host "[ERROR] Failed to enable SMBv2: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[INFO] SMBv2 already enabled" -ForegroundColor Cyan
    }
    
    if ($smbv1Enabled -eq $true) {
        Write-Host "`n[*] Disabling SMBv1 (vulnerable protocol)..." -ForegroundColor Yellow
        try {
            Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop
            Write-Host "[SUCCESS] SMBv1 disabled" -ForegroundColor Green
        } catch {
            Write-Host "[ERROR] Failed to disable SMBv1: $($_.Exception.Message)" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "[INFO] SMBv1 already disabled" -ForegroundColor Cyan
    }

    
} catch {
    Write-Host "[ERROR] SMB upgrade failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n[COMPLETED] SMB upgrade finished" -ForegroundColor Green
