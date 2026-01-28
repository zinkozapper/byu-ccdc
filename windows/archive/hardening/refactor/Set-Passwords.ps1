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
    [Parameter(Mandatory=$false)]
    [Alias("h")]
    [switch]$Help,
    
    [Parameter(Mandatory=$false)]
    [Alias("i")]
    [switch]$Initial,
    
    [Parameter(Mandatory=$false)]
    [Alias("u")]
    [string]$User,
    
    [Parameter(Mandatory=$false)]
    [Alias("U")]
    [string]$UsersFile,
    
    [Parameter(Mandatory=$false)]
    [Alias("g")]
    [switch]$GenerateOnly,
    
    [Parameter(Mandatory=$false)]
    [Alias("p")]
    [string]$PCRFile
)

# Script configuration
$NumWords = 5
$WordlistUrl = "https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/hardening/wordlist.txt"
$ExportUsersFile = "users_zulu.txt"
$LogFile = "zulu.log"
$WordlistFile = "wordlist.txt"
$ExcludedUsers = @("Administrator", "ccdcuser1", "ccdcuser2")

# Helper function for colored output
function Write-ColorText {
    param(
        [string]$Text,
        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::White,
        [switch]$NoNewline
    )
    
    if ($NoNewline) {
        Write-Host -NoNewline $Text -ForegroundColor $ForegroundColor
    } else {
        Write-Host $Text -ForegroundColor $ForegroundColor
    }
}

function Write-Usage {
    Write-ColorText "Usage: .\Set-Passwords.ps1 [options]" -ForegroundColor Green
    Write-Host "Default behavior asks for a seed phrase and changes passwords for all auto-detected users minus excluded users."
    Write-Host ""
    Write-ColorText "Options:" -ForegroundColor Yellow
    Write-ColorText "  -Help, -h          Show this help message" -ForegroundColor Cyan
    Write-ColorText "  -Initial, -i       Perform initial setup (change Administrator password and create ccdcuser1/2)" -ForegroundColor Cyan
    Write-ColorText "  -User, -u          Change password for a single user" -ForegroundColor Cyan
    Write-ColorText "  -UsersFile, -U     Change passwords for newline-separated users in a file" -ForegroundColor Cyan
    Write-ColorText "  -GenerateOnly, -g  Generate/print passwords only, do not change them" -ForegroundColor Cyan
    Write-ColorText "  -PCRFile, -p       Output generated passwords as 'username,password' to a PCR (CSV) file" -ForegroundColor Cyan
}

function Get-SilentInput {
    param([string]$Prompt)
    
    Write-Host -NoNewline $Prompt
    $secure = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    return $input
}

function Get-FileFromUrl {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    
    try {
        Write-ColorText "Downloading from $Url..." -ForegroundColor Green
        
        # Try with Invoke-WebRequest
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $Url -OutFile $OutputPath -UseBasicParsing
        $ProgressPreference = 'Continue'
        
        return $true
    } catch {
        Write-ColorText "Failed to download file from $Url" -ForegroundColor Red
        Write-ColorText "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Add-LogEntry {
    param([string]$Message)
    
    if (-not $GenerateOnly) {
        Add-Content -Path $LogFile -Value $Message
    }
}

function Test-Prerequisites {
    # Check that script is running as Administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-ColorText "Please run script as Administrator." -ForegroundColor Red
        exit 1
    }
    
    # Download wordlist if not present
    if (-not (Test-Path $WordlistFile)) {
        Write-ColorText "Downloading wordlist file..." -ForegroundColor Green
        $success = Get-FileFromUrl -Url $WordlistUrl -OutputPath $WordlistFile
        
        if (-not $success) {
            exit 1
        }
    }
}

function Initialize-Users {
    Write-ColorText "Changing Administrator password..." -ForegroundColor Green
    
    # Change Administrator password interactively
    $adminPassword = Get-SilentInput "Enter new password for Administrator: "
    Write-Host ""
    $adminPasswordConfirm = Get-SilentInput "Confirm password: "
    Write-Host ""
    
    if ($adminPassword -ne $adminPasswordConfirm) {
        Write-ColorText "Passwords do not match." -ForegroundColor Red
        exit 1
    }
    
    $securePassword = ConvertTo-SecureString -AsPlainText $adminPassword -Force
    Get-LocalUser -Name "Administrator" | Set-LocalUser -Password $securePassword
    
    Write-Host ""
    Write-ColorText "Creating ccdcuser1 and ccdcuser2..." -ForegroundColor Green
    
    # Create ccdcuser1
    if (-not (Get-LocalUser -Name "ccdcuser1" -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name "ccdcuser1" -NoPassword
    }
    
    # Create ccdcuser2
    if (-not (Get-LocalUser -Name "ccdcuser2" -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name "ccdcuser2" -NoPassword
    }
    
    Write-Host ""
    Write-ColorText "Setting passwords for ccdcuser1 and ccdcuser2..." -ForegroundColor Green
    
    # Set password for ccdcuser1
    $ccdc1Password = Get-SilentInput "Enter password for ccdcuser1: "
    Write-Host ""
    $securePassword = ConvertTo-SecureString -AsPlainText $ccdc1Password -Force
    Get-LocalUser -Name "ccdcuser1" | Set-LocalUser -Password $securePassword
    
    # Set password for ccdcuser2
    $ccdc2Password = Get-SilentInput "Enter password for ccdcuser2: "
    Write-Host ""
    $securePassword = ConvertTo-SecureString -AsPlainText $ccdc2Password -Force
    Get-LocalUser -Name "ccdcuser2" | Set-LocalUser -Password $securePassword
    
    Write-Host ""
    Write-ColorText "Adding ccdcuser1 to Administrators group..." -ForegroundColor Green
    Add-LocalGroupMember -Group "Administrators" -Member "ccdcuser1" -ErrorAction SilentlyContinue
}

function Scale-HashValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$HashValue,
        
        [Parameter(Mandatory=$true)]
        [int]$WordlistCount
    )
    
    $MinHash = 0x0000
    $MaxHash = 0xFFFF
    $TARGET_MAX = $wordlistData.Count - 1
    $TARGET_MIN = 0

    if ($TARGET_MAX -lt 0) { return 0 }
    return [int][Math]::Truncate(((($TARGET_MAX - $TARGET_MIN) * ($HashValue - $MinHash)) / ($MaxHash - $MinHash)) + $TARGET_MIN)
}

function New-Password {
    param(
        [string]$Username,
        [string]$SeedPhrase,
        [string[]]$WordlistData
    )
    
    # Generate MD5 hash
    $inputString = "$SeedPhrase$Username"
    $md5 = [System.Security.Cryptography.MD5]::Create()
    $hashBytes = $md5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($inputString))
    $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-', ''
    
    # Generate password from hash
    $password = ""
    
    for ($i = 0; $i -lt ($NumWords * 4); $i += 4) {
        # Add hyphen between words
        if ($i -ne 0) {
            $password += "-"
        }
        
        # Take 4 hex chars at a time
        $hex = $hashString.Substring($i, 4)
        
        # Convert hex to decimal
        $dec = [Convert]::ToInt32($hex, 16)
        
        # Scale to wordlist size
        $index = Scale-HashValue -HashValue $dec -WordlistCount $WordlistData.Count
        
        # Get word from wordlist and append to password
        $word = $WordlistData[$index]
        $password += $word
    }
    
    # Append 1 for complexity
    $password += "1"
    
    return $password
}

# Main script execution
if ($Help) {
    Write-Usage
    exit 0
}

Write-ColorText "Starting Zulu Password Generator Script..." -ForegroundColor Green
Add-LogEntry "Script started at $(Get-Date)"
Write-Host "The default behavior is to change passwords for all users except: $($ExcludedUsers -join ', ')."

Test-Prerequisites

# Initial change if requested
if ($Initial) {
    Write-ColorText "Performing initial user setup..." -ForegroundColor Green
    Initialize-Users
}

Write-Host ""
Write-ColorText "Preparing to generate passwords..." -ForegroundColor Green

# Get usernames
$rawUsers = @()

if ($User) {
    $rawUsers = @($User)
} elseif ($UsersFile) {
    if (-not (Test-Path $UsersFile)) {
        Write-ColorText "Users file '$UsersFile' not found." -ForegroundColor Red
        exit 1
    }
    $rawUsers = Get-Content $UsersFile
} else {
    # Get all local users (excluding built-in disabled accounts)
    $rawUsers = Get-LocalUser | Where-Object { $_.Enabled -eq $true } | Select-Object -ExpandProperty Name
}

# Exclude specified users
$users = $rawUsers | Where-Object { $_ -notin $ExcludedUsers }

# Get seed phrase
$seedPhrase = ""
while ($true) {
    $seedPhrase = Get-SilentInput "Enter seed phrase: "
    Write-Host ""
    
    $confirmSeedPhrase = Get-SilentInput "Confirm seed phrase: "
    Write-Host ""
    
    if ($seedPhrase -ne $confirmSeedPhrase) {
        Write-ColorText "Seed phrases do not match. Please retry." -ForegroundColor Yellow
        continue
    }
    
    if ($seedPhrase.Length -lt 8) {
        Write-ColorText "Seed phrase must be at least 8 characters long. Please retry." -ForegroundColor Yellow
        continue
    }
    
    break
}

Write-Host ""

# Load wordlist
$wordlistData = Get-Content $WordlistFile

# Generate and set passwords
Write-ColorText "Generating passwords for $($users.Count) users..." -ForegroundColor Green

if (-not $GenerateOnly) {
    # Clear export file
    if (Test-Path $ExportUsersFile) {
        Remove-Item $ExportUsersFile
    }
    New-Item -ItemType File -Path $ExportUsersFile -Force | Out-Null
}

foreach ($username in $users) {
    # Generate password
    $password = New-Password -Username $username -SeedPhrase $seedPhrase -WordlistData $wordlistData
    
    # Set or print password
    if (-not $GenerateOnly) {
        Write-Host "Changing password for user $username..."
        
        try {
            # Change password
            $securePassword = ConvertTo-SecureString -AsPlainText $password -Force
            Get-LocalUser -Name $username | Set-LocalUser -Password $securePassword
            
            Write-ColorText "Successfully changed password for $username." -ForegroundColor Green
            Add-LogEntry "Successfully changed password for $username"
            Add-Content -Path $ExportUsersFile -Value $username
        } catch {
            Write-ColorText "Failed to change password for $username." -ForegroundColor Red
            Add-LogEntry "Failed to change password for $username"
        }
    } elseif ($GenerateOnly -and -not $PCRFile) {
        Write-Host "Generated password for user '$username': $password"
    }
    
    # If PCR file specified, append username,password
    if ($PCRFile) {
        Add-Content -Path $PCRFile -Value "$username,$password"
    }
}

Write-ColorText "Done!" -ForegroundColor Green
Write-Host ""
Write-ColorText "PLEASE REMEMBER TO CHANGE THE ADMINISTRATOR PASSWORD IF NOT DONE EARLIER." -ForegroundColor Yellow