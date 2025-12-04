$NUM_WORDS = 5
$wordlistName = "wordlist.txt"
$ccdcRepoWindowsHardeningPath = "https://raw.githubusercontent.com/zinkozapper/byu-ccdc/main/windows/hardening/"
$wordlistPath = ".\$wordlistName"

function Get-Wordlist {
    [CmdletBinding()]
    param()
    
    $downloadUri = "$ccdcRepoWindowsHardeningPath/$wordlistName"
    
    if (-not (Test-Path $wordlistPath)) {
        Write-Host "Downloading $wordlistName..." -ForegroundColor Cyan
        try {
            # Note: Using the raw file link to ensure a proper download
            Invoke-WebRequest -Uri $downloadUri -OutFile $wordlistPath              
            Write-Host "Downloaded $wordlistName successfully." -ForegroundColor Green
        } catch {
            Write-Error "Failed to download $wordlistName : $($_.Exception.Message)"
            throw "Failed to download required file: $wordlistName"
        }
    } else {
        Write-Host "File already exists: $wordlistName" -ForegroundColor Yellow
    }
}

function Scale-Value {
    param(
        [Parameter(Mandatory=$true)]
        [int]$x
    )
    $MIN = 0x0000
    $MAX = 0xFFFF
    
    $TARGET_MAX = $wordlistData.Count
    $TARGET_MIN = 0
    
    if ($TARGET_MAX -eq 0) {
        Write-Error "Wordlist data is empty, cannot scale."
        return 0
    }

    return [int](((($TARGET_MAX - $TARGET_MIN) * ($x - $MIN)) / ($MAX - $MIN)) + $TARGET_MIN)
}

# 1. Ensure the wordlist file exists by attempting to download it
Get-Wordlist

# 2. Load the Wordlist into a global variable
if (-not (Test-Path $wordlistPath)) {
    Write-Error "The wordlist file '$wordlistPath' was not found after attempt to download."
    exit 1
}

$wordlistData = (Get-Content -Path $wordlistPath -Raw) -split "`n" | Where-Object { $_ -ne "" }

if ($wordlistData.Count -eq 0) {
    Write-Error "The wordlist is empty after processing."
    exit 1
}

# 3. Get User Input
$secret = Read-Host 'Enter a base secret from the password sheet'
$user = Read-Host 'Enter a username'

# 4. Calculate MD5 Hash
$inputString = "$secret$user"
$md5 = [System.Security.Cryptography.MD5]::Create()
$inputBytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
$hashBytes = $md5.ComputeHash($inputBytes)

$hash = -join ($hashBytes | ForEach-Object { $_.ToString('x2') })

# 5. Determine Indices
$indices = @()
$hashLength = $hash.Length

for ($i = 0; $i -lt $hashLength; $i += 4) {
    if ($i + 4 -le $hashLength) {
        $hashSegment = $hash.Substring($i, 4)
        $intValue = [Convert]::ToInt32($hashSegment, 16)
        $index = Scale-Value -x $intValue
        $indices += $index
    }
}

# 6. Generate Passphrase
$passwordWords = @()

for ($i = 0; $i -lt $NUM_WORDS; $i++) {
    if ($i -lt $indices.Count) {
        $index = $indices[$i]
        
        $passwordWords += $wordlistData[$index]
    } else {
        Write-Warning "Not enough hash segments to generate $NUM_WORDS words."
        break
    }
}

$password = $passwordWords -join '.'

# 7. Print Result
Write-Host ""
Write-Host "Generated Passphrase:" -ForegroundColor Green
Write-Host $password