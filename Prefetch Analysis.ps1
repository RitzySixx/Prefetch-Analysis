# Define Prefetch directory
$directory = "C:\Windows\Prefetch"

Clear-Host

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

Start-Sleep -s 3

# Initialize variables
$files = Get-ChildItem -Path $directory -Recurse -ErrorAction SilentlyContinue
$hashTable = @{}
$suspiciousFiles = @{}
$multiReasons = @{}

# Check for deleted Prefetch files
$deletedPrefetch = Test-Path $directory
if (-not $deletedPrefetch) {
    Write-Host "The Prefetch folder has been deleted or is missing!" -ForegroundColor Red
    Exit
}

# Analyze Prefetch files
foreach ($file in $files) {
    try {
        $reasons = @()

        # Check for read-only files
        if ($file.IsReadOnly) {
            $reasons += "Read-only Prefetch file detected."
        }

        # Check file extension
        if ($file.Extension -ne ".pf") {
            $reasons += "Non-.pf extension executed in Prefetch."
        }

        # Validate Prefetch file signature
        $reader = [System.IO.StreamReader]::new($file.FullName)
        $buffer = New-Object char[] 3
        $null = $reader.ReadBlock($buffer, 0, 3)
        $reader.Close()

        $firstThreeChars = -join $buffer
        if ($firstThreeChars -ne "MAM") {
            $reasons += "Invalid Prefetch file signature detected."
        }

        # Hash the file
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        if ($hashTable.ContainsKey($hash.Hash)) {
            $hashTable[$hash.Hash].Add($file.Name)
            $reasons += "Duplicated Prefetch file detected."
        } else {
            $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
            $hashTable[$hash.Hash].Add($file.Name)
        }

        if ($reasons.Count -gt 0) {
            $multiReasons[$file.Name] = $reasons -join ", "
        }
    } catch {
        $multiReasons[$file.Name] = "Error analyzing file: $($_.Exception.Message)"
    }
}

# Output results
if ($multiReasons.Count) {
    Write-Host "Suspicious Prefetch Files Detected:" -ForegroundColor Yellow
    foreach ($key in $multiReasons.Keys) {
        Write-Host "File: $key" -ForegroundColor Red
        Write-Host "Reasons: $($multiReasons[$key])" -ForegroundColor Cyan
        Write-Host " "
    }
} else {
    Write-Host "No suspicious activity detected in the Prefetch folder." -ForegroundColor Green
}

# End of script
Write-Host "Analysis Complete." -ForegroundColor Blue
