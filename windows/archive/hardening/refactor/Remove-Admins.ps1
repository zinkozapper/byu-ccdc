#Requires -RunAsAdministrator

# AD Detection
$IsDomainController = $false
$IsADEnvironment = $false
try {
    $CS = Get-WmiObject -Class Win32_ComputerSystem
    $IsDomainController = $CS.DomainRole -in @(4,5)
    $IsADEnvironment = $CS.PartOfDomain -eq $true
} catch { }

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Removing Unauthorized Admins" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

param(
    [Parameter(Mandatory=$false)]
    [switch]$RemoveAll = $false,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ProtectedAccounts = @("Administrator", "ccdcuser1", "ccdcuser3")
)

try {
    Write-Host "[*] Cleaning local Administrators group..." -ForegroundColor Cyan
    
    # If AD environment, also check for Domain/Enterprise Admins
    if ($IsADEnvironment) {
        Write-Host "[INFO] AD environment detected - will remove unauthorized Domain/Enterprise Admins" -ForegroundColor Cyan
        Write-Host "[INFO] Protected accounts: $($ProtectedAccounts -join ', ')" -ForegroundColor Cyan
    }
    
    $GroupName = "Administrators"
    $adminMembers = Get-LocalGroupMember -Name $GroupName -ErrorAction SilentlyContinue
    
    if ($null -eq $adminMembers -or $adminMembers.Count -eq 0) {
        Write-Host "[INFO] Administrators group is empty" -ForegroundColor Yellow
    } else {
        Write-Host "[INFO] Current admin members: $($adminMembers.Count)" -ForegroundColor Cyan
        Write-Host "`nMembers in Administrators group:" -ForegroundColor Cyan
        
        $memberList = @()
        foreach ($member in $adminMembers) {
            $username = $member.Name.Split('\')[-1]
            $domain = $member.Name.Split('\')[0]
            $isProtected = $ProtectedAccounts -contains $username
            
            # Check if this is a Domain/Enterprise Admin in AD environment
            $isDomainAdmin = $false
            if ($IsADEnvironment) {
                try {
                    $adUser = Get-ADUser -Identity $username -ErrorAction SilentlyContinue
                    if ($adUser) {
                        $adGroups = Get-ADUser -Identity $username -Properties MemberOf | Select-Object -ExpandProperty MemberOf
                        $isDomainAdmin = $adGroups | Where-Object { $_ -match "Domain Admins|Enterprise Admins" } | Measure-Object | Select-Object -ExpandProperty Count -GT 0
                    }
                } catch { }
            }
            
            $status = if ($isProtected) { "[PROTECTED]" } elseif ($isDomainAdmin -and -not $isProtected) { "[WILL-REMOVE]" } else { "[REMOVABLE]" }
            
            Write-Host "  - $username $status" -ForegroundColor $(if ($isProtected) { 'Green' } elseif ($isDomainAdmin -and -not $isProtected) { 'Red' } else { 'Yellow' })
            $memberList += @{ Member = $member; Username = $username; IsProtected = $isProtected; IsDomainAdmin = $isDomainAdmin }
        }
        
        if (-not $RemoveAll) {
            Write-Host "`n[*] Remove unauthorized admins? (yes/no)" -ForegroundColor Yellow
            $confirm = Read-Host "Proceed"
            
            if ($confirm -notmatch '^y|yes$') {
                Write-Host "[*] Cancelled admin removal" -ForegroundColor Yellow
                exit 0
            }
        }
        
        $removedCount = 0
        
        foreach ($entry in $memberList) {
            if ($entry.IsProtected) {
                Write-Host "[SKIP] Skipping $($entry.Username) (Protected Account)" -ForegroundColor Magenta
                continue
            }
            
            try {
                Remove-LocalGroupMember -Group $GroupName -Member $entry.Member -Confirm:$false -ErrorAction Stop
                if ($entry.IsDomainAdmin) {
                    Write-Host "[SUCCESS] Removed $($entry.Username) from Administrators (Unauthorized Domain Admin)" -ForegroundColor Green
                } else {
                    Write-Host "[SUCCESS] Removed $($entry.Username) from Administrators" -ForegroundColor Green
                }
                $removedCount++
            } catch {
                Write-Host "[WARNING] Could not remove $($entry.Username): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n[INFO] Removed $removedCount unauthorized admin(s)" -ForegroundColor Cyan
        Write-Host "Administrator group hardening complete" -ForegroundColor Green
    }
    
} catch {
    Write-Host "[ERROR] Failed to harden Administrators group: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "[COMPLETED] Admin cleanup finished" -ForegroundColor Green
