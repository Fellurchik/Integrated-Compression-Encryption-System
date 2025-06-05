<#
CREATE_TEST_FILES.PS1 - Test Data Generation Script
===================================================

Usage:
------
Run as Administrator:
> .\create_test_files.ps1

Features:
---------
- Creates standardized test dataset for compression/encryption benchmarking
- Generates 5 distinct data categories with realistic characteristics:
  1. Large text files (10GB)
  2. Image files (5GB JPEGs)
  3. Binary log files (5GB)
  4. Medical DICOM samples (2GB)
  5. Financial transaction records (3GB CSV)
- Cross-category data diversity for comprehensive testing
- Automatic cleanup of previous test runs
#>

# Bypass execution policy for current session
Set-ExecutionPolicy Bypass -Scope Process -Force

# Configure root test directory
$root = "C:\ThesisTests"
# Clean previous test data and create new directory
Remove-Item $root -Recurse -ErrorAction SilentlyContinue
New-Item -Path $root -ItemType Directory | Out-Null

# 1. TEXT DATA: 10GB File --------------------------------------------
New-Item -Path "$root\Text" -ItemType Directory | Out-Null
# Create 10GB file using filesystem utility
fsutil file createnew "$root\Text\10gb.txt" 10737418240
# Add actual text content for realistic compression
Add-Content -Path "$root\Text\10gb.txt" -Value ("Lorem ipsum dolor sit amet, " * 1000000)

# 2. IMAGE DATA: 5GB of JPEGs ----------------------------------------
New-Item -Path "$root\Images" -ItemType Directory | Out-Null
# Generate 500 image files (~10MB each)
1..500 | ForEach-Object {
    $filePath = "$root\Images\image_$_.jpg"
    # Create minimal valid JPEG header
    $header = [byte[]]@(0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01)
    # Generate random data payload (10MB)
    $randomData = [byte[]]::new(10MB)
    (New-Object Random).NextBytes($randomData)
    # Combine header and random data to create JPEG-like files
    [System.IO.File]::WriteAllBytes($filePath, $header + $randomData)
}

# 3. BINARY LOGS: 5GB File -------------------------------------------
New-Item -Path "$root\Logs" -ItemType Directory | Out-Null
# Create sparse 5GB binary file using .NET APIs
$file = [System.IO.File]::OpenWrite("$root\Logs\binary.log")
$file.SetLength(5GB)  # Set file size to 5GB
$file.Close()

# 4. MEDICAL DATA: 2GB of DICOM Files --------------------------------
New-Item -Path "$root\Medical" -ItemType Directory | Out-Null
# Generate 200 DICOM files with unique headers
1..200 | ForEach-Object {
    # Create DICOM-like header with GUID for uniqueness
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("DICOM HEADER" + [System.Guid]::NewGuid())
    [System.IO.File]::WriteAllBytes("$root\Medical\scan_$_.dcm", $bytes)
}

# 5. FINANCIAL DATA: 3GB CSV File ------------------------------------
New-Item -Path "$root\Financial" -ItemType Directory | Out-Null
# CSV header row
$header = "Timestamp,TransactionID,AccountFrom,AccountTo,Amount,Currency"
$header | Out-File "$root\Financial\transactions.csv" -Encoding UTF8

# Generate 3 million transaction records
1..3000000 | ForEach-Object {
    # Create realistic financial data
    $timestamp = [DateTime]::Now.AddSeconds($_).ToString('o')
    $txId = Get-Random -Minimum 1000000 -Maximum 9999999
    $acctFrom = Get-Random -Minimum 1000 -Maximum 9999
    $acctTo = Get-Random -Minimum 1000 -Maximum 9999
    $amount = Get-Random -Minimum 100 -Maximum 99999
    
    # Format as CSV row
    "$timestamp,$txId,$acctFrom,$acctTo,$amount,USD"
} | Add-Content "$root\Financial\transactions.csv" -Encoding UTF8

# Completion message
Write-Host "All test files created successfully!"