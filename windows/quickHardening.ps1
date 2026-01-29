#Requires -RunAsAdministrator

param(
    # Use skip switches: steps run by default unless skipped
    [Parameter(Mandatory=$false)]
    [switch]$SkipPasswords,
    [Parameter(Mandatory=$false)]
    [switch]$SkipRDP,
    [Parameter(Mandatory=$false)]
    [switch]$SkipFirewall,
    [Parameter(Mandatory=$false)]
    [switch]$SkipSMB,
    [Parameter(Mandatory=$false)]
    [switch]$SkipExecutionPolicy,
    [Parameter(Mandatory=$false)]
    [switch]$SkipServices,
    [Parameter(Mandatory=$false)]
    [switch]$SkipAuditing,
    [Parameter(Mandatory=$false)]
    [switch]$SkipSplunk,

    [Parameter(Mandatory=$false, HelpMessage = "Interactive prompts for each step")]
    [Alias("i")]
    [switch]$Interactive,

    [Parameter(Mandatory=$false, HelpMessage = "Base URL for fetching scripts")]
    [Alias("url")]
    [string]$BaseURL = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/",

    [Parameter(Mandatory=$false, HelpMessage = "Show this help message")]
    [Alias('h')]
    [switch]$Help
)

function Write-HardeningLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$Timestamp] [$Level] $Message"
}


$ScriptPath = $PSScriptRoot
$StartTime = Get-Date
#Add any other scripts to this array to download them at the start
$scripts = @("upgradeSMB.ps1","zulu.ps1","configureFirewall.ps1","disableUnnecessaryServices.ps1",
"hardenRDP.ps1","advancedAuditing.ps1","setupSplunk.ps1","restrictExecutionPolicy.ps1",
"removeAdmins.ps1", "applyPatches.ps1", "wordlist.txt")


Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Quick Hardening Process" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-HardeningLog "Starting Quick Hardening Process" "INFO"

#Help Menu
if ($Help) {
    Write-Host ""
    Write-Host "Usage: .\quickHardening.ps1 [-url <baseurl>] [-SkipSMB] [-SkipPasswords] [-SkipFirewall] [-SkipExecutionPolicy] [-SkipServices] [-SkipRDP] [-SkipAuditing] [-SkipSplunk] [-Interactive] [-h]" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Cyan
    Write-Host "  -url <url>             Base URL to download scripts (alias: -url)" -ForegroundColor Cyan
    Write-Host "  -Skip* flags           Skip individual steps (e.g. -SkipSMB)" -ForegroundColor Cyan
    Write-Host "  -Interactive           Prompt for each step" -ForegroundColor Cyan
    Write-Host "  -h                     Show this help and exit" -ForegroundColor Cyan
    Write-Host ""
    exit 0
}

# Download dependencies once (fail fast if missing)
foreach ($script in $scripts) {
    if (Test-Path "./$script") {
        Write-Host "$script already exists, skipping download." -ForegroundColor Yellow
        continue
    }
    $url = "$BaseURL/$script"
    $destination = "./$script"

    Write-Host "Downloading: $script..." -ForegroundColor Cyan
    
    Invoke-WebRequest -Uri $url -OutFile $destination
}

Write-Host "All downloads complete!" -ForegroundColor Green


$ExecutedScripts = @()

# Determine run flags (default: run unless skipped)
$RunSMB = -not $SkipSMB
$RunPasswords = -not $SkipPasswords
$RunExecutionPolicy = -not $SkipExecutionPolicy
$RunServices = -not $SkipServices
$RunFirewall = -not $SkipFirewall
$RunRDP = -not $SkipRDP
$RunAuditing = -not $SkipAuditing
$RunSplunk = -not $SkipSplunk



# Interactive prompts override defaults when -Interactive / -i is used
if ($Interactive) {
    Write-HardeningLog "Interactive mode: prompting for each step" "INFO"

    $ans = Read-Host "Run Upgrade SMB? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunSMB = $false } else { $RunSMB = $true }

    $ans = Read-Host "Run zulu? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunPasswords = $false } else { $RunPasswords = $true }

    $ans = Read-Host "Run Configure Firewall? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunFirewall = $false } else { $RunFirewall = $true }

    $ans = Read-Host "Run Disable Unnecessary Services? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunServices = $false } else { $RunServices = $true }

    $ans = Read-Host "Run Configure RDP? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunRDP = $false } else { $RunRDP = $true }

    $ans = Read-Host "Run Configure Advanced Auditing? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunAuditing = $false } else { $RunAuditing = $true }

    $ans = Read-Host "Run Install Splunk? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunSplunk = $false } else { $RunSplunk = $true }

    $ans = Read-Host "Run Set Execution Policy? [Y/n] (default: Y)"
    if ($ans -match '^[Nn]') { $RunExecutionPolicy = $false } else { $RunExecutionPolicy = $true }
}

# Step 1: Upgrade SMB
if ($RunSMB) { 
    Write-HardeningLog "Upgrading SMB..." "INFO"
    & "./upgradeSMB.ps1"
    $ExecutedScripts += "upgradeSMB.ps1"
}

#Step 2: Change Passwords
if ($RunPasswords) {
    Write-HardeningLog "Setting Passwords..." "INFO"
    & "./zulu.ps1 -url $BaseURL/wordlist.txt"
    $ExecutedScripts += "zulu.ps1"
}

#Step 3: Configure Firewall
if ($RunFirewall) {
    Write-HardeningLog "Configuring Firewall..." "INFO"
    & "./configureFirewall.ps1"
    $ExecutedScripts += "configureFirewall.ps1"
}

#Step 4: Disable Unnecessary Services
if ($RunServices) {
    Write-HardeningLog "Disabling Unnecessary Services..." "INFO"
    & "./disableUnnecessaryServices.ps1"
    $ExecutedScripts += "disableUnnecessaryServices.ps1"
}

#Step 5: Configure RDP
if ($RunRDP) {
    Write-HardeningLog "Configuring RDP..." "INFO"
    & "./hardenRDP.ps1"
    $ExecutedScripts += "hardenRDP.ps1"
}

#Step 6: Configure Advanced Auditing
if ($RunAuditing) {
    Write-HardeningLog "Configuring Advanced Auditing..." "INFO"
    & "./advancedAuditing.ps1"
    $ExecutedScripts += "advancedAuditing.ps1"
}

#Step 7: Install Splunk
if ($RunSplunk) {
    Write-HardeningLog "Installing Splunk..." "INFO"
    & "./setupSplunk.ps1 -url $BaseURL/../splunk/splunk.ps1"
    $ExecutedScripts += "setupSplunk.ps1"
}


#Step 8: Set Execution Policy to restricted
if ($RunExecutionPolicy) {
    Write-HardeningLog "Setting Execution Policy..." "INFO"
    & "./restrictExecutionPolicy.ps1"
    $ExecutedScripts += "restrictExecutionPolicy.ps1"
}

$EndTime = Get-Date
$Duration = $EndTime - $StartTime

Write-Host "`n========================================" -ForegroundColor Cyan
Write-HardeningLog "Quick Hardening Process Completed" "INFO"
Write-HardeningLog "Duration: $([math]::Round($Duration.TotalSeconds, 2)) seconds" "INFO"
Write-HardeningLog "Scripts Executed: $($ExecutedScripts.Count)" "INFO"
Write-Host "========================================" -ForegroundColor Cyan
