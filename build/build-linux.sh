#!/bin/bash
set -e

echo "=== Building QOTP Wireshark Plugin for Linux ==="

# Check if we're in the right directory
if [ ! -f "qotp_export.go" ]; then
    echo "Error: Must run from wireshark-plugin directory"
    exit 1
fi

# Install dependencies if needed
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y build-essential liblua5.4-dev lua5.4 golang-go

# Setup qotp and qh dependencies
if [ ! -d "qotp" ]; then
    echo "Cloning qotp dependency..."
    git clone https://github.com/tbocek/qotp.git
fi

if [ ! -d "qh" ]; then
    echo "Cloning qh dependency..."
    git clone https://github.com/qh-project/qh.git
fi

# Download Go dependencies
echo "Downloading Go dependencies..."
go mod download

# Build Go shared library
echo "Building qotp_crypto.so..."
CGO_ENABLED=1 go build -buildmode=c-shared -o qotp_crypto.so qotp_export.go

# Build C Lua module
echo "Building qotp_decrypt.so..."
gcc -shared -fPIC -O2 qotp_decrypt.c -o qotp_decrypt.so -I/usr/include/lua5.4 -llua5.4

echo ""
echo "=== Build Complete ==="
echo "Files created:"
echo "  - qotp_dissector.lua"
echo "  - qotp_crypto.so"
echo "  - qotp_decrypt.so"
echo ""
echo "To install:"
echo "  mkdir -p ~/.local/lib/wireshark/plugins/4.6"
echo "  cp qotp_dissector.lua qotp_crypto.so qotp_decrypt.so ~/.local/lib/wireshark/plugins/4.6/"
