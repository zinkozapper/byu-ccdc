#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Zulu Password Generator Script for Windows
    
.DESCRIPTION
    Changes passwords for local users using a deterministic password generation algorithm
    based on a seed phrase and username. Matches functionality of zulu.sh bash script.
    
.PARAMETER Help
    Show help message
    
.PARAMETER Initial
    Perform initial setup (change Administrator password and create ccdcuser1/2)
    
.PARAMETER User
    Change password for a single user
    
.PARAMETER UsersFile
    Change passwords for newline-separated users in a file
    
.PARAMETER GenerateOnly
    Generate/print passwords only, do not change them
    
.PARAMETER PCRFile
    Output generated passwords as 'username,password' to a PCR (CSV) file
    
.EXAMPLE
    .\Set-Passwords.ps1
    Default behavior - change passwords for all auto-detected users
    
.EXAMPLE
    .\Set-Passwords.ps1 -Initial
    Perform initial setup with Administrator and ccdc users
    
.EXAMPLE
    .\Set-Passwords.ps1 -User "john"
    Change password for a single user
    
.EXAMPLE
    .\Set-Passwords.ps1 -GenerateOnly -PCRFile "passwords.csv"
    Generate passwords and save to CSV without changing them
#>

[CmdletBinding()]
param(
    [Alias("h")][switch]$Help,
    [Alias("i")][switch]$Initial,
    [Alias("u")][string]$User,
    [Alias("U")][string]$UsersFile,
    [Alias("g")][switch]$GenerateOnly,
    [Alias("p")][string]$PCRFile
)

# Script configuration
$NumWords = 5
$WordlistUrl = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/wordlist.txt"
$ExportUsersFile = "users_zulu.csv"
$LogFile = "zulu.log"
$WordlistFile = "wordlist.txt"
$ExcludedUsers = @("Administrator", "ccdcuser1", "ccdcuser2")

function Write-Usage {
    Write-Host "Usage: .\Set-Passwords.ps1 [options]" -ForegroundColor Green
    Write-Host "Default behavior asks for a seed phrase and changes passwords for all auto-detected users minus excluded users."
    Write-Host "`nOptions:" -ForegroundColor Yellow
    @(
        "  -Help, -h          Show this help message",
        "  -Initial, -i       Perform initial setup (change Administrator password and create ccdcuser1/2)",
        "  -User, -u          Change password for a single user",
        "  -UsersFile, -U     Change passwords for newline-separated users in a file",
        "  -GenerateOnly, -g  Generate/print passwords only, do not change them",
        "  -PCRFile, -p       Output generated passwords as 'username,password' to a PCR (CSV) file"
    ) | ForEach-Object { Write-Host $_ -ForegroundColor Cyan }
}

function Get-SilentInput {
    param([string]$Prompt)
    Write-Host -NoNewline $Prompt
    $secure = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    $input
}

function Get-FileFromUrl {
    param([string]$Url, [string]$OutputPath)
    try {
        Write-Host "Downloading from $Url..." -ForegroundColor Green
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        $ProgressPreference = 'Continue'
        $true
    } catch {
        Write-Host "Failed to download file from $Url`nError: $($_.Exception.Message)" -ForegroundColor Red
        $false
    }
}

function Add-LogEntry {
    param([string]$Message)
    if (-not $GenerateOnly) { Add-Content -Path $LogFile -Value $Message }
}

function Test-Prerequisites {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "Please run script as Administrator." -ForegroundColor Red
        exit 1
    }
    if (-not (Test-Path $WordlistFile)) {
        Write-Host "Downloading wordlist file..." -ForegroundColor Green
        if (-not (Get-FileFromUrl -Url $WordlistUrl -OutputPath $WordlistFile)) { exit 1 }
    }
}

function Set-UserPassword {
    param([string]$Username, [string]$PasswordPrompt, [switch]$AddToAdmins)
    $password = Get-SilentInput $PasswordPrompt
    $confirmPassword = Get-SilentInput "Confirm password: "
    if ($password -ne $confirmPassword) {
        Write-ColorText "Passwords do not match." -ForegroundColor Red
        exit 1
    }
    $securePassword = ConvertTo-SecureString -AsPlainText $password -Force
    Get-LocalUser -Name $Username | Set-LocalUser -Password $securePassword
    if ($AddToAdmins) {
        Add-LocalGroupMember -Group "Administrators" -Member $Username -ErrorAction SilentlyContinue
    }
}

function Initialize-Users {
    Write-Host "Changing Administrator password..." -ForegroundColor Green
    Set-UserPassword -Username "Administrator" -PasswordPrompt "Enter new password for Administrator: "
    Write-Host "`nCreating ccdcuser1 and ccdcuser2..."
    @("ccdcuser1", "ccdcuser2") | ForEach-Object {
        if (-not (Get-LocalUser -Name $_ -ErrorAction SilentlyContinue)) {
            New-LocalUser -Name $_ -NoPassword
        }
    }
    
    Write-Host "`nSetting passwords for CCDC users..."
    Set-UserPassword -Username "ccdcuser1" -PasswordPrompt "Enter password for ccdcuser1: " -AddToAdmins
    Set-UserPassword -Username "ccdcuser2" -PasswordPrompt "Enter password for ccdcuser2: "
}

function Scale-HashValue {
    param([Parameter(Mandatory=$true)][int]$HashValue, [Parameter(Mandatory=$true)][int]$WordlistCount)
    $TARGET_MAX = $wordlistData.Count - 1
    if ($TARGET_MAX -lt 0) { return 0 }
    return [int][Math]::Truncate(((($TARGET_MAX) * ($HashValue - 0x0000)) / (0xFFFF - 0x0000)))
}

function New-Password {
    param([string]$Username, [string]$SeedPhrase, [string[]]$WordlistData)
    
    $inputString = "$SeedPhrase$Username"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString))
    $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    
    $password = ""
    for ($i = 0; $i -lt ($NumWords * 4); $i += 4) {
        if ($i -ne 0) { $password += "-" }
        $hex = $hashString.Substring($i, 4)
        $dec = [Convert]::ToInt32($hex, 16)
        $index = Scale-HashValue -HashValue $dec -WordlistCount $WordlistData.Count
        $password += $WordlistData[$index]
    }
    $password + "1"
}

if ($Help) { Write-Usage; exit 0 }

Write-Host "Starting Zulu Password Generator Script..." -ForegroundColor Green
Add-LogEntry "Script started at $(Get-Date)"
Write-Host "The default behavior is to change passwords for all users except: $($ExcludedUsers -join ', ')."

Test-Prerequisites

if ($Initial) {
    Write-Host "Performing initial user setup..." -ForegroundColor Green
    Initialize-Users
}

Write-Host "`nPreparing to generate passwords..."

$rawUsers = if ($User) { @($User) } 
            elseif ($UsersFile) { 
                if (-not (Test-Path $UsersFile)) { Write-Host "Users file '$UsersFile' not found." -ForegroundColor Red; exit 1 }
                Get-Content $UsersFile 
            } 
            else { 
                Get-LocalUser | Where-Object { $_.Enabled } | Select-Object -ExpandProperty Name 
            }

$users = $rawUsers | Where-Object { $_ -notin $ExcludedUsers }

while ($true) {
    $seedPhrase = Get-SilentInput "Enter seed phrase: "
    $confirmSeedPhrase = Get-SilentInput "Confirm seed phrase: "
    
    if ($seedPhrase -ne $confirmSeedPhrase) {
        Write-Host "Seed phrases do not match. Please retry." -ForegroundColor Yellow
        continue
    }
    if ($seedPhrase.Length -lt 8) {
        Write-Host "Seed phrase must be at least 8 characters long. Please retry." -ForegroundColor Yellow
        continue
    }
    break
}

$wordlistData = Get-Content $WordlistFile
Write-Host "Generating passwords for $($users.Count) users..." -ForegroundColor Green

if (-not $GenerateOnly) {
    Remove-Item $ExportUsersFile -ErrorAction SilentlyContinue
    New-Item -ItemType File -Path $ExportUsersFile -Force | Out-Null
}

foreach ($username in $users) {
    $password = New-Password -Username $username -SeedPhrase $seedPhrase -WordlistData $wordlistData
    
    if (-not $GenerateOnly) {
        Write-Host "Changing password for user $username..."
        try {
            Get-LocalUser -Name $username | Set-LocalUser -Password (ConvertTo-SecureString -AsPlainText $password -Force)
            Write-Host "Successfully changed password for $username." -ForegroundColor Green
            Add-LogEntry "Successfully changed password for $username"
            Add-Content -Path $ExportUsersFile -Value $username
        } catch {
            Write-Host "Failed to change password for $username." -ForegroundColor Red
            Add-LogEntry "Failed to change password for $username"
        }
    } elseif (-not $PCRFile) {
        Write-Host "Generated password for user '$username': $password"
    }
    
    if ($PCRFile) {
        Add-Content -Path $PCRFile -Value "$username,$password"
    }
}

Write-Host "`nDone!" -ForegroundColor Green
Write-Host "PLEASE REMEMBER TO CHANGE THE ADMINISTRATOR PASSWORD IF NOT DONE EARLIER." -ForegroundColor Yellow