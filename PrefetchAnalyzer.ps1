# Audit Eye Prefetch Analyzer
# Advanced prefetch file analysis with multi-threading and executable name extraction

# Ensure Unicode support for ASCII art banner
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$directory = "C:\Windows\Prefetch"

Clear-Host

# Display Audit Eye Banner
Write-Host ""
Write-Host "██████╗ ██╗██████╗ ██████╗ ██╗   ██╗    ██████╗ ██████╗ ███████╗███████╗███████╗████████╗ ██████╗██╗  ██╗" -ForegroundColor Magenta
Write-Host "██╔══██╗██║██╔══██╗██╔══██╗╚██╗ ██╔╝    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██║  ██║" -ForegroundColor Magenta
Write-Host "██████╔╝██║██║  ██║██║  ██║ ╚████╔╝     ██████╔╝██████╔╝█████╗  █████╗  █████╗     ██║   ██║     ███████║" -ForegroundColor Magenta
Write-Host "██╔══██╗██║██║  ██║██║  ██║  ╚██╔╝      ██╔═══╝ ██╔══██╗██╔══╝  ██╔══╝  ██╔══╝     ██║   ██║     ██╔══██║" -ForegroundColor Magenta
Write-Host "██║  ██║██║██████╔╝██████╔╝   ██║       ██║     ██║  ██║███████╗██║     ███████╗   ██║   ╚██████╗██║  ██║" -ForegroundColor Magenta
Write-Host "╚═╝  ╚═╝╚═╝╚═════╝ ╚═════╝    ╚═╝       ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝" -ForegroundColor Magenta
Write-Host ""

# Function to check for admin privileges
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

# Verify admin privileges
if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

Start-Sleep -s 3

# Check prefetch folder status
Write-Host "Checking prefetch folder status..." -ForegroundColor Cyan

# Check if prefetch directory exists
if (!(Test-Path -Path $directory -PathType Container)) {
    Write-Host "PREFETCH FOLDER IS DELETED - Directory does not exist: $directory" -ForegroundColor Red
    Write-Host "This is a critical security indicator!" -ForegroundColor Red
    Start-Sleep 5
    Exit
}

# Get directory info
$dirInfo = Get-Item -Path $directory -Force -ErrorAction SilentlyContinue

if ($dirInfo) {
    # Check if directory is hidden
    if ($dirInfo.Attributes -band [System.IO.FileAttributes]::Hidden) {
        Write-Host "WARNING: Prefetch folder is HIDDEN" -ForegroundColor Yellow
        Write-Host "Hidden directory detected: $directory" -ForegroundColor Yellow
    }

    # Check directory permissions (for read-only like behavior)
    try {
        $acl = Get-Acl -Path $directory
        $accessRules = $acl.Access

        # Check if current user has write access
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $writeAccess = $false

        foreach ($rule in $accessRules) {
            if (($rule.IdentityReference.Value -eq $currentUser -or $rule.IdentityReference.Value -eq "BUILTIN\Administrators") -and $rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Write) {
                $writeAccess = $true
                break
            }
        }

        if (!$writeAccess) {
            Write-Host "WARNING: Prefetch folder may be READ-ONLY (no write access)" -ForegroundColor Yellow
            Write-Host "Current user lacks write permissions for: $directory" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "Could not check directory permissions: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "Could not access prefetch directory information" -ForegroundColor Red
}

Write-Host ""

try {
    $prefetchValue = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" -Name EnablePrefetcher -ErrorAction Stop
    
    switch ($prefetchValue) {
        0 {
            Write-Host "Prefetch is DISABLED (value: 0)" -ForegroundColor Red
        }
        1 {
            Write-Host "Prefetch is ENABLED (value: 1 - Application launch only)" -ForegroundColor Yellow
        }
        2 {
            Write-Host "Prefetch is DISABLED for Applications (value: 2 - Boot only)" -ForegroundColor Red
        }
        3 {
            # Full mode (boot + application) → don’t print anything, stays “clean”
        }
        default {
            Write-Host "Unknown Prefetch setting (value: $prefetchValue)" -ForegroundColor Yellow
        }
    }
}
catch {
    Write-Host "Unable to check Prefetch registry setting: $($_.Exception.Message)" -ForegroundColor Red
}

# Function to decompress prefetch file (simulating LZX decompression)
function Decompress-PrefetchFile {
    param($data)
    try {
        # Read signature and decompressed size
        if ($data.Length -lt 8) { return $null }
        $signature = [BitConverter]::ToUInt32($data, 0)
        $decompressedSize = [BitConverter]::ToUInt32($data, 4)
        
        # Verify MAM signature
        if (($signature -band 0x00FFFFFF) -ne 0x004D414D) { return $null }
        
        # Skip header (8 bytes)
        $compressedData = $data[8..($data.Length - 1)]
        
        # Attempt decompression (assuming LZX-like compression, using Deflate as a fallback)
        $memoryStream = New-Object System.IO.MemoryStream(,$compressedData)
        $decompressStream = New-Object System.IO.Compression.DeflateStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
        $outputStream = New-Object System.IO.MemoryStream
        $decompressStream.CopyTo($outputStream)
        $decompressedData = $outputStream.ToArray()
        $decompressStream.Close()
        $outputStream.Close()
        $memoryStream.Close()
        
        if ($decompressedData.Length -ge $decompressedSize) {
            return $decompressedData
        }
        return $null
    } catch {
        return $null
    }
}

# Initialize collections
$hashTable = @{}
$suspiciousFiles = @{}

# Get prefetch files
$files = Get-ChildItem -Path $directory -Filter *.pf -Force -ErrorAction SilentlyContinue
$totalFiles = $files.Count
$currentFile = 0

Write-Host "Found $totalFiles prefetch files to analyze" -ForegroundColor Cyan

# Create runspace pool for parallel processing
$runspacePool = [RunspaceFactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
$runspacePool.Open()
$runspaces = @()

foreach ($file in $files) {
    $powershell = [PowerShell]::Create()
    $powershell.RunspacePool = $runspacePool
    
    [void]$powershell.AddScript({
        param($file)
        
        # Define Decompress-PrefetchFile within the runspace
        function Decompress-PrefetchFile {
            param($data)
            try {
                # Read signature and decompressed size
                if ($data.Length -lt 8) { return $null }
                $signature = [BitConverter]::ToUInt32($data, 0)
                $decompressedSize = [BitConverter]::ToUInt32($data, 4)
                
                # Verify MAM signature
                if (($signature -band 0x00FFFFFF) -ne 0x004D414D) { return $null }
                
                # Skip header (8 bytes)
                $compressedData = $data[8..($data.Length - 1)]
                
                # Attempt decompression (assuming LZX-like compression, using Deflate as a fallback)
                $memoryStream = New-Object System.IO.MemoryStream(,$compressedData)
                $decompressStream = New-Object System.IO.Compression.DeflateStream($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
                $outputStream = New-Object System.IO.MemoryStream
                $decompressStream.CopyTo($outputStream)
                $decompressedData = $outputStream.ToArray()
                $decompressStream.Close()
                $outputStream.Close()
                $memoryStream.Close()
                
                if ($decompressedData.Length -ge $decompressedSize) {
                    return $decompressedData
                }
                return $null
            } catch {
                return $null
            }
        }
        
        # Define Get-PrefetchExecutableName within the runspace
        function Get-PrefetchExecutableName {
            param($filePath, $data)
            try {
                # Check file size
                $fileInfo = Get-Item $filePath
                if ($fileInfo.Length -lt 100) { return $null }
                
                # Use provided data (decompressed or raw)
                $buffer = New-Object byte[] 64 # 32 chars * 2 bytes for Unicode
                if ($data.Length -lt (0x10 + 64)) { return $null }
                
                # Read executable name at offset 0x10
                [Array]::Copy($data, 0x10, $buffer, 0, 64)
                
                # Convert to Unicode string and trim null bytes
                $exeName = [System.Text.Encoding]::Unicode.GetString($buffer).Trim([char]0)
                
                # Validate name (allow letters, numbers, common symbols)
                if ($exeName -match '^[a-zA-Z0-9_\-\.\s\(\)@+#]*$' -and $exeName -ne '') {
                    return $exeName
                }
                return $null
            } catch {
                return $null
            }
        }
        
        $result = [PSCustomObject]@{
            FileName = $file.Name
            ExeName = ""
            Status = "Valid"
            Details = ""
        }
        
        try {
            # Check read-only status
            if ($file.IsReadOnly) {
                $result.Status = "Suspicious"
                $result.Details = "File is read-only"
            }

            # Check hidden status
            if ($file.Attributes -band [System.IO.FileAttributes]::Hidden) {
                $result.Status = "Suspicious"
                $result.Details = if ($result.Details) { $result.Details + "; Hidden prefetch file" } else { "Hidden prefetch file" }
            }

            # Read file content
            $fileContent = [System.IO.File]::ReadAllBytes($file.FullName)
            
            # Check for MAM signature and decompress if necessary
            $signature = -join ([char[]]$fileContent[0..3])
            $isCompressed = $signature -eq "MAM"
            $data = $fileContent
            
            # Handle compressed files
            if ($isCompressed) {
                $decompressedData = Decompress-PrefetchFile -data $fileContent
                if ($decompressedData) {
                    $data = $decompressedData
                }
                # Do not mark as suspicious if decompression fails; use raw data as fallback
            }

            # Extract executable name
            $exeName = Get-PrefetchExecutableName -filePath $file.FullName -data $data
            if (-not $exeName) {
                # Fallback to file name
                $baseName = ($file.Name -split "-")[0]
                $exeName = $baseName
            }
            $result.ExeName = if ($exeName) { $exeName } else { "Unknown" }
            
            # Check if executable name is invalid or unreadable
            if ($result.ExeName -eq "Unknown") {
                $result.Status = "Suspicious"
                $result.Details = if ($result.Details) { $result.Details + "; Invalid or unreadable process name" } else { "Invalid or unreadable process name" }
            }

            # Calculate hash
            $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
            $result | Add-Member -MemberType NoteProperty -Name SHA256 -Value $hash.Hash

        } catch {
            $result.Status = "Suspicious"
            $result.Details = if ($result.Details) { $result.Details + "; Error processing file: $($_.Exception.Message)" } else { "Error processing file: $($_.Exception.Message)" }
        }
        
        return $result
    }).AddArgument($file)

    $runspaces += [PSCustomObject]@{
        PowerShell = $powershell
        Handle = $powershell.BeginInvoke()
    }
    
    $currentFile++
    Write-Progress -Activity "Analyzing Prefetch Files" -Status "Processing $currentFile of $totalFiles" -PercentComplete (($currentFile / $totalFiles) * 100)
}

# Collect results
foreach ($runspace in $runspaces) {
    $result = $runspace.PowerShell.EndInvoke($runspace.Handle)
    
    # Store hash information for duplicate detection
    if ($result.SHA256) {
        if ($hashTable.ContainsKey($result.SHA256)) {
            $hashTable[$result.SHA256].Add($result.FileName)
        } else {
            $hashTable[$result.SHA256] = [System.Collections.Generic.List[string]]::new()
            $hashTable[$result.SHA256].Add($result.FileName)
        }
    }
    
    # Store suspicious files
    if ($result.Status -eq "Suspicious") {
        $suspiciousFiles[$result.FileName] = "$($result.Details) (Process: $($result.ExeName))"
    }
    
    $runspace.PowerShell.Dispose()
}

$runspacePool.Close()
$runspacePool.Dispose()

# Detect repeated hashes after all hashes are collected
$repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

if ($repeatedHashes) {
    foreach ($entry in $repeatedHashes) {
        foreach ($file in $entry.Value) {
            if (-not $suspiciousFiles.ContainsKey($file)) {
                $suspiciousFiles[$file] = "$file was modified with type or echo"
            } else {
                $suspiciousFiles[$file] += "; $file was modified with type or echo"
            }
        }
    }
}

# Display results
Write-Host ""
if ($suspiciousFiles.Count -gt 0) {
    Write-Host "Prefetch Folder is Dirty:" -ForegroundColor Red
    foreach ($key in $suspiciousFiles.Keys) {
        Write-Host "$key : $($suspiciousFiles[$key])" -ForegroundColor Yellow
    }
} else {
    Write-Host "Prefetch Folder is clean." -ForegroundColor Green
}

Write-Host "Analysis completed. Total files processed: $totalFiles" -ForegroundColor Cyan

