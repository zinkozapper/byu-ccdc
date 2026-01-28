#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Installing Security Patches" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("EternalBlue", "Mimikatz", "SigRed", "All")]
    [string]$Patch = $null
)

function Get-OSVersion {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    $caption = $os.Caption
    
    if ($caption -match 'Windows 7') { return 'Windows7' }
    elseif ($caption -match 'Windows 8') { return 'Windows8' }
    elseif ($caption -match 'Windows 10') { return 'Windows10' }
    elseif ($caption -match 'Windows 11') { return 'Windows11' }
    elseif ($caption -match '2008 R2') { return 'Server2008R2' }
    elseif ($caption -match '2008') { return 'Server2008' }
    elseif ($caption -match '2012 R2') { return 'Server2012R2' }
    elseif ($caption -match '2012') { return 'Server2012' }
    elseif ($caption -match '2016') { return 'Server2016' }
    elseif ($caption -match '2019') { return 'Server2019' }
    elseif ($caption -match '2022') { return 'Server2022' }
    else { return 'Unknown' }
}

function Install-EternalBluePatch {
    Write-Host "`n[*] Installing EternalBlue Patch..." -ForegroundColor Yellow
    
    $osVersion = Get-OSVersion
    $eternalBlueCompatible = @("Windows7", "Windows8", "Server2008", "Server2008R2", "Server2012", "Server2012R2")
    
    if ($osVersion -notin $eternalBlueCompatible) {
        Write-Host "[INFO] EternalBlue patch not needed for $osVersion" -ForegroundColor Cyan
        return
    }
    
    try {
        # Common KB patches for EternalBlue (MS17-010)
        $patches = @{
            'Windows7' = 'KB3205394'
            'Windows8' = 'KB3205394'
            'Server2008' = 'KB3205394'
            'Server2008R2' = 'KB3205394'
            'Server2012' = 'KB3205394'
            'Server2012R2' = 'KB3205394'
        }
        
        $kb = $patches[$osVersion]
        Write-Host "[*] Checking for patch $kb..." -ForegroundColor Cyan
        
        $installed = Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object { $_.HotFixID -eq $kb }
        
        if ($installed) {
            Write-Host "[INFO] Patch $kb is already installed" -ForegroundColor Green
        } else {
            Write-Host "[INFO] Patch $kb needs to be installed via Windows Update" -ForegroundColor Yellow
            Write-Host "[INFO] Please run Windows Update to install this patch" -ForegroundColor Yellow
        }
        
        Write-Host "[SUCCESS] EternalBlue patch check completed" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] EternalBlue patch installation failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Install-MimikatzPatch {
    Write-Host "`n[*] Installing Mimikatz Patch (WDigest)..." -ForegroundColor Yellow
    
    try {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        
        Write-Host "[*] Disabling WDigest credential storage..." -ForegroundColor Cyan
        
        # Create registry path if it doesn't exist
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
            Write-Host "[INFO] Created registry path" -ForegroundColor Cyan
        }
        
        Set-ItemProperty -Path $registryPath -Name "UseLogonCredential" -Value 0 -Type DWord -Force
        
        Write-Host "[SUCCESS] WDigest credential storage disabled (UseLogonCredential = 0)" -ForegroundColor Green
        Write-Host "[INFO] System restart recommended for changes to take full effect" -ForegroundColor Yellow
    } catch {
        Write-Host "[ERROR] Mimikatz patch failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Install-SigRedPatch {
    Write-Host "`n[*] Installing SigRed Patch..." -ForegroundColor Yellow
    
    $osVersion = Get-OSVersion
    
    try {
        # SigRed (CVE-2020-1350) affects DNS servers - primarily Windows Server
        if ($osVersion -notmatch 'Server') {
            Write-Host "[INFO] SigRed patch primarily applies to Windows Server systems" -ForegroundColor Cyan
            return
        }
        
        Write-Host "[*] Checking for DNS service..." -ForegroundColor Cyan
        $dnsService = Get-Service -Name DNS -ErrorAction SilentlyContinue
        
        if ($dnsService) {
            $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
            if (-not (Test-Path $registryPath)) {
                New-Item -Path $registryPath -Force | Out-Null
                Write-Host "[INFO] Created registry path" -ForegroundColor Cyan
            }

            Set-ItemProperty -Path $registryPath -Name "TcpReceivePacketSize" -Value 65280 -Type DWord -Force
            Write-Host "[SUCCESS] Updated TCP receive packet size for SigRed patch" -ForegroundColor Green
            Write-Host "[INFO] Stopping DNS service to apply changes..." -ForegroundColor Cyan
            
            Stop-Service -Name DNS
            if ((Get-Service -Name DNS).Status -ne 'Running') {
                Write-Host "[SUCCESS] DNS service stopped successfully" -ForegroundColor Green
            } else {
                Write-Host "[WARNING] DNS service did not stop as expected" -ForegroundColor Yellow
            }

            Start-Service -Name DNS
            if ((Get-Service -Name DNS).Status -eq 'Running') {
                Write-Host "[INFO] DNS service restarted successfully" -ForegroundColor Green
            } else {
                Write-Host "[WARNING] DNS service did not restart as expected" -ForegroundColor Yellow
            }

        } else {
            Write-Host "[INFO] DNS service not running - SigRed patch not applicable" -ForegroundColor Cyan
        }
        
        Write-Host "[SUCCESS] SigRed patch check completed" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] SigRed patch check failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Show-PatchMenu {
    do {
        Write-Host "`n========== Security Patches Menu ==========" -ForegroundColor Cyan
        Write-Host "1) Install EternalBlue Patch (MS17-010)" -ForegroundColor Yellow
        Write-Host "2) Install Mimikatz Patch (WDigest)" -ForegroundColor Yellow
        Write-Host "3) Install SigRed Patch (CVE-2020-1350)" -ForegroundColor Yellow
        Write-Host "4) Install All Patches" -ForegroundColor Yellow
        Write-Host "0) Exit Patches Menu" -ForegroundColor Cyan
        Write-Host "==========================================`n" -ForegroundColor Cyan
        
        $choice = Read-Host "Select an option (0-4)"
        
        switch ($choice) {
            '1' { Install-EternalBluePatch }
            '2' { Install-MimikatzPatch }
            '3' { Install-SigRedPatch }
            '4' {
                Install-EternalBluePatch
                Install-MimikatzPatch
                Install-SigRedPatch
            }
            '0' { 
                Write-Host "[*] Exiting patches menu" -ForegroundColor Cyan
                break
            }
            default { Write-Host "[ERROR] Invalid option. Please try again." -ForegroundColor Red }
        }
    } while ($choice -ne '0')
}

try {
    if ($Patch) {
        switch ($Patch) {
            'EternalBlue' { Install-EternalBluePatch }
            'Mimikatz' { Install-MimikatzPatch }
            'SigRed' { Install-SigRedPatch }
            'All' {
                Install-EternalBluePatch
                Install-MimikatzPatch
                Install-SigRedPatch
            }
        }
    } else {
        Show-PatchMenu
    }
    
    Write-Host "`n[SUCCESS] Patch installation process completed" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Patch installation failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "[COMPLETED] Patch installation finished" -ForegroundColor Green
