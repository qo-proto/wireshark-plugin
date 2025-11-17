# QOTP Wireshark Plugin - User Guide

Complete guide for installing and using the QOTP Wireshark plugin to decrypt and analyze QOTP+QH protocol traffic.

## Table of Contents
- [Installation](#installation)
- [Generating Keylog Files](#generating-keylog-files)
- [Configuring Wireshark](#configuring-wireshark)
- [Analyzing Traffic](#analyzing-traffic)
- [Troubleshooting](#troubleshooting)

## Installation

### Windows

#### Option 1: Download Pre-built Release

1. Download the latest release from [GitHub Releases](https://github.com/qo-proto/wireshark-plugin/releases)
2. Extract the ZIP file containing:
   - `qotp_dissector.lua`
   - `qotp_crypto.dll`
   - `qotp_decrypt.dll`

3. Copy files to the plugin location:
   ```
   %APPDATA%\Roaming\Wireshark\plugins\4.6\
   ```
   
   > **Tip**: Press `Win+R`, type `%APPDATA%\Roaming\Wireshark\plugins` and press Enter to open the folder quickly

4. Restart Wireshark

### Verify Installation

1. Open Wireshark
2. Go to **Help → About Wireshark → Plugins**
3. Search for "qotp" - you should see `qotp_dissector.lua` listed

## Generating Keylog Files

To decrypt QOTP traffic, you need a keylog file containing the shared secrets for each connection.

### Enabling Keylog in QH Server

The QH server's `Listen()` method accepts an optional keylog writer. Pass `nil` to disable keylogging:

```go
// WITHOUT keylog (encrypted traffic)
if err := srv.Listen(addr, nil, seed); err != nil {
    // ...
}

// WITH keylog (for Wireshark debugging)
keyLogFile, err := os.OpenFile("qotp_keylog.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
if err != nil {
    log.Fatal(err)
}
defer keyLogFile.Close()

if err := srv.Listen(addr, keyLogFile, seed); err != nil {
    // ...
}
```

When enabled with a file writer, the server creates `qotp_keylog.log` with entries like:

```
QOTP_SHARED_SECRET 0000000000000001 a1b2c3d4e5f6...
QOTP_SHARED_SECRET 0000000000000002 f1e2d3c4b5a6...
```

### Keylog File Format

Each line contains:
```
QOTP_SHARED_SECRET <CONNECTION_ID_HEX> <SHARED_SECRET_HEX>
```

- **CONNECTION_ID**: 16-character hex string (8 bytes, zero-padded)
- **SHARED_SECRET**: 64-character hex string (32 bytes)

Example:
```
QOTP_SHARED_SECRET 00000000a4f8b23c 8f3a2d1c9b4e5f6a7d8c9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
QOTP_SHARED_SECRET 00000000b5e9c34d 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

### Security Warning

⚠️ **NEVER enable keylog in production!**

- Keylog files contain the shared secrets needed to decrypt all traffic
- Pass `nil` to `Listen()` in production to disable keylogging
- Only enable keylog writer during development and debugging
- Protect keylog files with appropriate file permissions
- Delete keylog files when debugging is complete

## Configuring Wireshark

### Load Keylog File

1. Open Wireshark
2. Go to **Edit → Preferences**
3. Expand **Protocols** in the left panel
4. Scroll down and select **QOTP**
5. Click the **Browse** button next to "Keylog file"
6. Select your `qotp_keylog.log` file
7. Click **OK**

### Display Filter

Filter for QOTP packets:
```
qotp
```

Common filters:
```
qotp                           # All QOTP packets
qotp.msg_type == "Data"        # Only data packets
qotp.conn_id == 0xa4f8b23c     # Specific connection
qh                             # QH protocol (decrypted)
qh.method == "GET"             # HTTP GET requests
qh.status == 200               # HTTP 200 responses
qh.path contains "/api"        # API endpoints
```

## Analyzing Traffic

### Packet Structure

A typical QOTP packet in Wireshark shows:

```
Frame 123: 1234 bytes on wire
Ethernet II
Internet Protocol Version 4
User Datagram Protocol
QOTP Protocol
    Message Type: Data
    Version: 0
    Connection ID: 0x00000000a4f8b23c
    Encrypted Data: [encrypted]
    ├─ Decrypted Data: [if keylog available]
    └─ QH Protocol
        ├─ Version: 1
        ├─ Type: Request
        ├─ Operation: GET
        ├─ Host: example.com
        ├─ Path: /api/users
        └─ Body: [if present]
```

### Message Types

- **InitSnd**: Initial handshake from client (unencrypted public keys)
- **InitRcv**: Initial handshake response from server (encrypted)
- **InitCryptoSnd**: Client handshake with encrypted data
- **InitCryptoRcv**: Server response with encrypted data
- **Data**: Regular encrypted application data

### QH Protocol Fields

When decrypted, QH protocol shows:

**Requests:**
- Version
- Type (Request)
- Method (GET, POST, PUT, PATCH, DELETE, HEAD)
- Host
- Path
- Headers (if any)
- Body (if any)

**Responses:**
- Version
- Type (Response)
- Status Code (200, 404, 500, etc.)
- Headers (if any)
- Body (if any)

### Follow Stream

To see the full conversation:

1. Right-click on a QOTP packet
2. Select **Follow → UDP Stream**
3. Wireshark displays the decrypted conversation

### Export Decrypted Data

To export decrypted packet data:

1. Select a decrypted packet
2. Right-click → **Export Packet Dissection**
3. Choose format (Plain Text, CSV, JSON, etc.)

## Troubleshooting

### Plugin Not Loading

**Check installation paths:**
```powershell
dir "%APPDATA%\Roaming\Wireshark\plugins\4.6\qotp_dissector.lua"
dir "%APPDATA%\Roaming\Wireshark\plugins\4.6\qotp_*.dll"
```

**Check Wireshark plugins:**
- Help → About Wireshark → Plugins
- Look for `qotp_dissector.lua`

### Packets Not Decrypting

**Verify keylog file is loaded:**
- Edit → Preferences → Protocols → QOTP
- Ensure "Keylog file" path is correct

**Check connection IDs match:**
- Expand QOTP protocol in packet details
- Note the Connection ID (e.g., `0x00000000a4f8b23c`)
- Verify this ID exists in your keylog file
- Connection IDs must be zero-padded to 16 hex characters

**Verify keylog format:**
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 00000000a4f8b23c 8f3a2d1c9b4e5f6a7d8c9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
```
- Must start with `CLIENT_HANDSHAKE_TRAFFIC_SECRET`
- Connection ID: exactly 16 hex chars
- Shared secret: exactly 64 hex chars
- All lowercase hex (a-f, not A-F)

**Reload capture after changing keylog:**
- Close and reopen the capture file
- Or: View → Reload

### "Multiple Lua VMs Detected" Error

This usually indicates a plugin conflict:
- Disable other Lua plugins temporarily
- Restart Wireshark
- Re-enable plugins one by one to find the conflict

### Display Shows "Encrypted Data" Only

**Possible causes:**

1. **No keylog file loaded** → Load keylog in Preferences
2. **Wrong connection ID** → Check keylog has matching connection ID
3. **Keylog from different session** → Regenerate keylog with current traffic
4. **Handshake packets missing** → Capture must include the connection setup

### Performance Issues

For large captures:
- Use display filters to reduce visible packets
- Disable decryption temporarily (remove keylog file path)
- Split large captures into smaller files

## Example Workflow

### Complete Debugging Session

1. **Start Wireshark capture:**
   - Start capture
  
2. **Start server with keylog:**
   ```bash
   cd qh/examples/server
   go run .
   ```
   Output: `QOTP keylog enabled (file: qotp_keylog.log)`

3. **Load keylog file:**
   - Edit → Preferences → Protocols → QOTP
   - Browse to `qh/examples/server/qotp_keylog.log`
   - Click OK

4. **Run client to generate traffic:**
   ```bash
   cd qh/examples/client
   go run .
   ```

5. **Stop capture in Wireshark**

6. **Analyze decrypted traffic:**
   - View decrypted QOTP packets

7. **Clean up:**
   ```bash
   rm qh/examples/server/qotp_keylog.log
   ```

## Support

- **Issues**: [GitHub Issues](https://github.com/qo-proto/wireshark-plugin/issues)
- **Documentation**: [README.md](README.md)
- **Protocol Spec**: [qh/docs/protocol-definition.md](../qh/docs/protocol-definition.md)
