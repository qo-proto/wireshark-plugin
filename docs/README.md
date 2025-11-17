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

3. Copy files to the correct locations:

   **DLL files** → Wireshark installation directory:
   ```
   C:\Program Files\Wireshark\qotp_crypto.dll
   C:\Program Files\Wireshark\qotp_decrypt.dll
   ```
   
   **Lua dissector** → User plugins directory:
   ```
   %APPDATA%\Roaming\Wireshark\plugins\4.6\qotp_dissector.lua
   ```
   
   > **Tip**: Press `Win+R`, type `%APPDATA%\Roaming\Wireshark\plugins` and press Enter to open the folder quickly

4. Restart Wireshark

#### Option 2: Build from Source

See [README.md](README.md) for build instructions.

### Linux

1. Download the Linux release tarball
2. Extract and copy files:
   ```bash
   # Copy shared libraries to Wireshark plugins directory
   mkdir -p ~/.local/lib/wireshark/plugins/4.6
   cp qotp_crypto.so qotp_decrypt.so ~/.local/lib/wireshark/plugins/4.6/
   
   # Copy Lua dissector
   cp qotp_dissector.lua ~/.local/lib/wireshark/plugins/4.6/
   ```

3. Restart Wireshark

### Verify Installation

1. Open Wireshark
2. Go to **Help → About Wireshark → Plugins**
3. Search for "qotp" - you should see `qotp_dissector.lua` listed

## Generating Keylog Files

To decrypt QOTP traffic, you need a keylog file containing the shared secrets for each connection.

### Enabling Keylog in QH Server

The QH server supports an optional `-keylog` flag to enable key logging:

```bash
# Start server WITHOUT keylog (default - encrypted traffic)
go run ./examples/server/

# Start server WITH keylog (for Wireshark debugging)
go run ./examples/server/ -keylog
```

When enabled, the server creates `qotp_keylog.log` with entries like:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0000000000000001 a1b2c3d4e5f6...
CLIENT_HANDSHAKE_TRAFFIC_SECRET 0000000000000002 f1e2d3c4b5a6...
```

### Keylog File Format

Each line contains:
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <CONNECTION_ID_HEX> <SHARED_SECRET_HEX>
```

- **CONNECTION_ID**: 16-character hex string (8 bytes, zero-padded)
- **SHARED_SECRET**: 64-character hex string (32 bytes)

Example:
```
CLIENT_HANDSHAKE_TRAFFIC_SECRET 00000000a4f8b23c 8f3a2d1c9b4e5f6a7d8c9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
CLIENT_HANDSHAKE_TRAFFIC_SECRET 00000000b5e9c34d 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

### Security Warning

⚠️ **NEVER enable keylog in production!**

- Keylog files contain the shared secrets needed to decrypt all traffic
- Only use `-keylog` flag during development and debugging
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

### Capture Filter (Optional)

To capture only QOTP traffic:
```
udp port 8090
```

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
# Windows - Check these files exist:
dir "C:\Program Files\Wireshark\qotp_*.dll"
dir "%APPDATA%\Roaming\Wireshark\plugins\4.6\qotp_dissector.lua"
```

**Check Wireshark plugins:**
- Help → About Wireshark → Plugins
- Look for `qotp_dissector.lua`

**Check console for errors:**
- Help → About Wireshark → Console
- Look for "qotp" related errors

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

## Advanced Usage

### Custom Port

To dissect QOTP on a different port:

1. Right-click a UDP packet on your custom port
2. Select **Decode As...**
3. Change "Current" to **QOTP**
4. Click OK

### Scripting

Access dissected fields in tshark:

```bash
# Extract all GET requests
tshark -r capture.pcap -Y "qh.method == GET" -T fields -e qh.path

# Count packets by QH status code
tshark -r capture.pcap -Y "qh" -T fields -e qh.status | sort | uniq -c

# Export decrypted QH bodies
tshark -r capture.pcap -Y "qh.body" -T fields -e qh.body
```

### Keylog from Client

To capture client-side traffic, modify the QH client to enable keylogging:

```go
// In your client code
keyLogFile, err := os.OpenFile("qotp_client_keylog.log", 
    os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
if err != nil {
    log.Fatal(err)
}
defer keyLogFile.Close()

// Pass keyLogFile to your client initialization
```

## Example Workflow

### Complete Debugging Session

1. **Start server with keylog:**
   ```bash
   cd qh/examples/server
   go run . -keylog
   ```
   Output: `QOTP keylog enabled (file: qotp_keylog.log)`

2. **Start Wireshark capture:**
   - Capture filter: `udp port 8090`
   - Start capture

3. **Run client to generate traffic:**
   ```bash
   cd qh/examples/client
   go run .
   ```

4. **Stop capture in Wireshark**

5. **Load keylog file:**
   - Edit → Preferences → Protocols → QOTP
   - Browse to `qh/examples/server/qotp_keylog.log`
   - Click OK

6. **Analyze decrypted traffic:**
   - Apply filter: `qh`
   - View decrypted HTTP-like requests and responses
   - Follow streams to see full conversations

7. **Clean up:**
   ```bash
   rm qh/examples/server/qotp_keylog.log
   ```

## Support

- **Issues**: [GitHub Issues](https://github.com/qo-proto/wireshark-plugin/issues)
- **Documentation**: [README.md](README.md)
- **Protocol Spec**: [qh/docs/protocol-definition.md](../qh/docs/protocol-definition.md)
