#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Disabling Unnecessary Services" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan


try {
    Write-Host "[*] Disabling IPv6 on active network adapters..." -ForegroundColor Yellow
    
    $activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    if ($activeAdapters) {
        foreach ($adapter in $activeAdapters) {
            try {
                Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                Write-Host "  [+] Disabled IPv6 on: $($adapter.Name)" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Could not disable IPv6 on $($adapter.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    
    Write-Host "`n[*] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
    
    try {
        $adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
        
        foreach ($adapter in $adapters) {
            try {
                $adapter.SetTcpipNetbios(2) | Out-Null
                Write-Host "  [+] Disabled NetBIOS on adapter" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Could not disable NetBIOS: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "  [!] Could not get network adapters: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    Write-Host "`n[SUCCESS] Service hardening completed" -ForegroundColor Green
    
} catch {
    Write-Host "[ERROR] Service hardening failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
