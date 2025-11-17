# QOTP Wireshark Plugin - Build Complete!

## Files Created

### DLLs:
- `qotp_crypto.dll` - Go crypto library using qotp.DecryptDataForPcap()
- `qotp_decrypt.dll` - Lua C module wrapper

### Plugin:
- `qotp_dissector.lua` - Wireshark dissector with auto-generated mappings
- `generate_mappings.go` - Auto-generates QH protocol mappings from Go types

## Automated Build & Deployment

Run the automated build script:
```powershell
.\build.ps1
```

This will:
1. Generate Lua mappings from Go types
2. Build qotp_crypto.dll (Go → C-shared library)
3. Build qotp_decrypt.dll (C Lua module)
4. Deploy all files to `%APPDATA%\Roaming\Wireshark\plugins\4.6\`

**No admin privileges required!** All files are deployed to the user's plugin directory.

## Manual Deployment (if needed)

```powershell
Copy-Item qotp_dissector.lua, qotp_crypto.dll, qotp_decrypt.dll `
  "$env:APPDATA\Roaming\Wireshark\plugins\4.6\" -Force
```

Then restart Wireshark.

## Configuration

1. **Open Wireshark**
2. **Edit → Preferences → Protocols → QOTP**
3. **Set "Keylog file"** to path of your `qotp_keylog.log` (e.g., `C:\Users\...\qh\qotp_keylog.log`)
4. **Click OK**

## Testing

1. Capture or open PCAP with UDP port 8090 traffic
2. QOTP packets should appear with protocol "QOTP"
3. Data packets show decrypted QH protocol details
4. Check console output for debug messages:
   - `=== Loaded X keys from Y lines`
   - `Looking for key: ...`
   - Connection IDs matched and decryption status

## Features

- ✅ Full QOTP protocol dissection (InitSnd, InitRcv, InitCryptoSnd, InitCryptoRcv, Data)
- ✅ ChaCha20-Poly1305 decryption using qotp package
- ✅ Automatic keylog loading and reloading
- ✅ QH protocol parsing (HTTP-like with varint encoding)
- ✅ Auto-generated protocol mappings from Go types
- ✅ No admin privileges required for installation
- ✅ Connection ID padding for consistent key lookups
- ✅ Supports both live capture and pcap file analysis

## Architecture

```
qotp_dissector.lua (Wireshark Lua plugin)
    ↓ calls
qotp_decrypt.dll (C Lua module)
    ↓ calls
qotp_crypto.dll (Go C-shared library)
    ↓ uses
qotp package DecryptDataForPcap()
```

## Key Components

- **qotp_export.go**: Minimal Go wrapper exposing DecryptDataPacket() to C
- **qotp_decrypt.c**: Lua C module with lua_decrypt_data() and lua_set_key()
- **qotp_dissector.lua**: Full dissector with automatic keylog reloading
- **generate_mappings.go**: Keeps Lua mappings in sync with Go types

## Architecture

```
Wireshark Lua VM
       ↓
qotp_dissector.lua
       ↓
qotp_decrypt.dll (C wrapper)
       ↓
qotp_crypto.dll (Go library)
```

All DLLs dynamically link to lua54.dll (no static linking = no crashes!)
