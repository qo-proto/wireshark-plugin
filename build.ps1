# Build script for QOTP Wireshark Plugin
# This script builds both the Go DLL and the C Lua module

Write-Host "Building QOTP Wireshark Decryption Plugin..." -ForegroundColor Green
Write-Host ""

# Step 1: Generate Lua mappings from Go source
Write-Host "Step 1: Generating Lua mappings from Go types..." -ForegroundColor Cyan
go run generate_mappings.go qotp_dissector.lua

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to generate mappings!" -ForegroundColor Red
    exit 1
}

Write-Host "Mappings updated in qotp_dissector.lua" -ForegroundColor Green
Write-Host ""

# Step 2: Build Go shared library
Write-Host "Step 2: Building Go shared library (qotp_crypto.dll)..." -ForegroundColor Cyan
$env:CGO_ENABLED = "1"
go build -buildmode=c-shared -o qotp_crypto.dll qotp_export.go

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Go build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "qotp_crypto.dll created" -ForegroundColor Green
Write-Host ""

# Step 3: Build C wrapper as Lua module
Write-Host "Step 3: Building C Lua module (qotp_decrypt.dll)..." -ForegroundColor Cyan
$luaInclude = "C:\Users\gian\sa\wireshark\wireshark-libs\lua-5.4.6-unicode-win64-vc14\include"
$luaLib = "C:\Users\gian\sa\wireshark\wireshark-libs\lua-5.4.6-unicode-win64-vc14\lua54.lib"
$currentDir = (Get-Location).Path

$buildCmd = "vcvars64.bat & cd /d `"$currentDir`" & cl /LD /O2 /TP qotp_decrypt.c /I`"`"$luaInclude`"`" /link `"`"$luaLib`"`" User32.lib /OUT:qotp_decrypt.dll"

cmd /c $buildCmd

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: C compilation failed!" -ForegroundColor Red
    Write-Host "Make sure vcvars64.bat is in your PATH or run from VS Developer Command Prompt" -ForegroundColor Yellow
    exit 1
}

Write-Host "qotp_decrypt.dll created" -ForegroundColor Green
Write-Host ""

# Step 4: Show deployment instructions
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Build complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Generated files:" -ForegroundColor Cyan
Write-Host "  - qotp_dissector.lua (with auto-generated mappings)"
Write-Host "  - qotp_crypto.dll"
Write-Host "  - qotp_decrypt.dll"
Write-Host ""
Write-Host "Deployment instructions:" -ForegroundColor Yellow
Write-Host "  All files will be copied to %APPDATA%\Wireshark\plugins\4.6\"
Write-Host "  (No admin privileges required!)"
Write-Host "  Restart Wireshark after deployment"
Write-Host ""

# Offer to copy files
$response = Read-Host "Copy files now? (y/n)"
if ($response -eq 'y') {
    $pluginDir = "C:\Users\$env:USERNAME\AppData\Roaming\Wireshark\plugins\4.6"
    if (!(Test-Path $pluginDir)) {
        New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    }
    
    Write-Host "Copying files to plugins folder..." -ForegroundColor Cyan
    Copy-Item qotp_decrypt.dll $pluginDir -Force
    Copy-Item qotp_crypto.dll $pluginDir -Force
    Copy-Item qotp_dissector.lua $pluginDir -Force
    
    Write-Host "Files copied successfully to $pluginDir" -ForegroundColor Green
    Write-Host "No admin privileges needed!" -ForegroundColor Green
}
