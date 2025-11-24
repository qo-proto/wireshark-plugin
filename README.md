# QOTP Wireshark Plugin

This plugin enables Wireshark to dissect and decrypt QOTP (Quick UDP Transport Protocol) traffic on port 8090.

## Architecture

The plugin consists of four components:

1. **generate_mappings.go** - Generates Lua mappings from Go types (QH methods and status codes)
2. **qotp_export.go** - Go code that exports crypto functions as a C-compatible DLL
3. **qotp_decrypt.c** - C wrapper that bridges Go functions to Lua
4. **qotp_dissector.lua** - Wireshark Lua dissector plugin

### Single Source of Truth

The QH protocol mappings (HTTP methods and status codes) are automatically generated from the Go source code (`types.go` and `status.go`) during the build process. This ensures the Lua dissector is always in sync with the Go implementation.

## Deployment Windows

1. Download the latest release from GitHub:
[https://github.com/qo-proto/wireshark-plugin/releases](https://github.com/qo-proto/wireshark-plugin/releases)

2. Unzip the Archive


3. Copy Lua and DLLs to Wiresharks Plugin directory C:\Users\<user>\AppData\Roaming\Wireshark\plugins\X.X\:

4. Restart Wireshark

## Deployment Linux
1. Download the latest release from GitHub:
[https://github.com/qo-proto/wireshark-plugin/releases](https://github.com/qo-proto/wireshark-plugin/releases)

2. Unzip the Archive 
3. Copy Lua and so's to Wiresharks Plugin directory
4. Restart Wireshark



## Usage

### Basic Dissection

1. Open Wireshark and start capturing traffic
2. The dissector will automatically decode QOTP packets showing:
   - Message type (InitSnd, InitRcv, Data, etc.)
   - Connection ID
   - Encrypted data

### Decryption with Keylog File

1. Start the Server with the keylog tag

2. In Wireshark, go to: **Edit → Preferences → Protocols → QOTP**

3. Set "Keylog file" to the path of your keylog file

4. Click OK and start the capture

5. Packets with matching connection IDs will be decrypted