#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [string]$Version,
    [Parameter(Mandatory=$false)]
    [string]$IP

    [Parameter(Mandatory=$false, HelpMessage = "If we need to download the wordlist, this is the URL to get it from")]
    [Alias("url")]
    [string]$downloadURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/splunk/splunk.ps1"
)

if (-not $Version) {
    $Version = Read-Host "Enter Splunk version"
}

if (-not $IP) {
    $IP = Read-Host "Enter Splunk server IP"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Splunk Forwarder Setup" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if ( -not(Test-Path "./splunk.ps1")) {
        Write-Host "Downloading Splunk installation script..." -ForegroundColor Yellow
        Invoke-WebRequest -Uri $downloadURL -OutFile ./splunk.ps1
    }
    Write-Host "Downloaded Splunk installation script" -ForegroundColor Green

    $SplunkServer = "$($IP):9997"
    Write-Host "Running Splunk installer..." -ForegroundColor Yellow
    & ./splunk.ps1 $Version $SplunkServer
    Write-Host "Splunk installation completed" -ForegroundColor Green
} catch {
    Write-Host "Splunk installation failed: $($_.Exception.Message)" -ForegroundColor Red
    throw
}
