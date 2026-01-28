#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Setting Execution Policy" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

try {
    Write-Host "[*] Setting Execution Policy to Restricted..." -ForegroundColor Yellow
    
    Set-ExecutionPolicy Restricted -Scope LocalMachine -Force -ErrorAction Stop
    Write-Host "[SUCCESS] Execution Policy set to Restricted (LocalMachine scope)" -ForegroundColor Green
    
    Set-ExecutionPolicy Restricted -Scope CurrentUser -Force -ErrorAction SilentlyContinue
    Write-Host "[SUCCESS] Execution Policy set to Restricted (CurrentUser scope)" -ForegroundColor Green
    
    Set-ExecutionPolicy Restricted -Scope Process -Force -ErrorAction SilentlyContinue
    Write-Host "[SUCCESS] Execution Policy set to Restricted (Process scope)" -ForegroundColor Green
    
} catch {
    Write-Host "[ERROR] Failed to set Execution Policy: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "`n[COMPLETED] Execution Policy hardening finished" -ForegroundColor Green
