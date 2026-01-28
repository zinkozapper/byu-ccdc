#Requires -RunAsAdministrator

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Managing RDP User Access" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Add", "Remove", "List")]
    [string]$Action = "List",
    
    [Parameter(Mandatory=$false)]
    [string[]]$Users
)

try {
    switch ($Action) {
        "List" {
            Write-Host "[*] RDP Users currently in Remote Desktop Users group:" -ForegroundColor Cyan
            try {
                $rdpMembers = Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction SilentlyContinue
                if ($null -eq $rdpMembers -or $rdpMembers.Count -eq 0) {
                    Write-Host "  [INFO] Remote Desktop Users group is empty" -ForegroundColor Yellow
                } else {
                    foreach ($member in $rdpMembers) {
                        $username = $member.Name.Split('\')[-1]
                        Write-Host "  - $username ($($member.ObjectClass))" -ForegroundColor Green
                    }
                }
            } catch {
                Write-Host "[ERROR] Could not list RDP users: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        
        "Add" {
            Write-Host "[*] Adding users to Remote Desktop Users group..." -ForegroundColor Cyan
            
            if ($null -eq $Users -or $Users.Count -eq 0) {
                Write-Host "[*] Enter usernames to add (comma-separated):" -ForegroundColor Yellow
                $userInput = Read-Host "Users"
                $Users = $userInput -split ',' | ForEach-Object { $_.Trim() }
            }
            
            $successCount = 0
            $failedCount = 0
            
            foreach ($user in $Users) {
                try {
                    Add-LocalGroupMember -Name "Remote Desktop Users" -Member $user -ErrorAction Stop
                    Write-Host "  [SUCCESS] Added $user to Remote Desktop Users group" -ForegroundColor Green
                    $successCount++
                } catch {
                    Write-Host "  [ERROR] Could not add $user : $($_.Exception.Message)" -ForegroundColor Red
                    $failedCount++
                }
            }
            
            Write-Host "`n[INFO] Added $successCount user(s), Failed: $failedCount" -ForegroundColor Cyan
        }
        
        "Remove" {
            Write-Host "[*] Removing users from Remote Desktop Users group..." -ForegroundColor Cyan
            $ExclusionList = @("ccdcuser1", "ccdcuser2")
            
            try {
                $rdpMembers = Get-LocalGroupMember -Name "Remote Desktop Users" -ErrorAction SilentlyContinue
                
                if ($null -eq $rdpMembers -or $rdpMembers.Count -eq 0) {
                    Write-Host "  [INFO] Remote Desktop Users group is already empty" -ForegroundColor Yellow
                } else {
                    $removedCount = 0
                    
                    foreach ($member in $rdpMembers) {
                        $username = $member.Name.Split('\')[-1]
                        
                        if ($ExclusionList -contains $username) {
                            Write-Host "  [SKIP] Skipping $username (Protected Account)" -ForegroundColor Magenta
                            continue
                        }
                        
                        try {
                            Remove-LocalGroupMember -Name "Remote Desktop Users" -Member $member -Confirm:$false -ErrorAction Stop
                            Write-Host "  [SUCCESS] Removed $username from Remote Desktop Users group" -ForegroundColor Green
                            $removedCount++
                        } catch {
                            Write-Host "  [WARNING] Could not remove $username : $($_.Exception.Message)" -ForegroundColor Yellow
                        }
                    }
                    
                    Write-Host "  [INFO] Removed $removedCount user(s) from Remote Desktop Users group" -ForegroundColor Cyan
                }
                
                Write-Host "RDP group hardening complete" -ForegroundColor Green
            } catch {
                Write-Host "[ERROR] Failed to remove RDP users: $($_.Exception.Message)" -ForegroundColor Red
                exit 1
            }
        }
    }
} catch {
    Write-Host "[ERROR] RDP user management failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host "[COMPLETED] RDP user management finished" -ForegroundColor Green
