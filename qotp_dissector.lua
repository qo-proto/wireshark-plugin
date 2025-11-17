-- QOTP Wireshark Dissector - Decrypts and dissects QOTP+QH protocol on UDP port 8090

print("=== QOTP Dissector Loading ===")

-- Get the directory where this script is located
local info = debug.getinfo(1, "S")
local script_path = info.source:match("@(.+)")
local script_dir = script_path and script_path:match("(.+)[/\\][^/\\]+$")

if script_dir then
    -- Add to package.cpath for Lua module loading
    package.cpath = script_dir .. "\\?.dll;" .. package.cpath
    
    -- Pre-load qotp_crypto.dll using absolute path so Windows can find it
    local qotp_crypto_path = script_dir .. "\\qotp_crypto.dll"
    package.loadlib(qotp_crypto_path, "*")
end

print("Loading qotp_decrypt module...")
local qotp_decrypt = require("qotp_decrypt")
print("qotp_decrypt loaded, running test...")
qotp_decrypt.test()
print("qotp_decrypt test complete")

-- Create protocol first (before accessing any prefs)
local qotp_proto = Proto("QOTP", "Quick UDP Transport Protocol")

-- Define fields for QOTP protocol (must be defined before using them)
local f_msg_type = ProtoField.string("qotp.msg_type", "Message Type")
local f_version = ProtoField.uint8("qotp.version", "Version", base.DEC)
local f_conn_id = ProtoField.uint64("qotp.conn_id", "Connection ID", base.HEX)
local f_encrypted = ProtoField.bytes("qotp.encrypted", "Encrypted Data")
local f_decrypted = ProtoField.bytes("qotp.decrypted", "Decrypted Data")
local f_header = ProtoField.bytes("qotp.header", "Header")

-- Define fields for QH protocol (inner protocol)
local f_qh_version = ProtoField.uint8("qh.version", "QH Version", base.DEC)
local f_qh_type = ProtoField.string("qh.type", "Type")
local f_qh_method = ProtoField.string("qh.method", "Operation")
local f_qh_status = ProtoField.uint16("qh.status", "Status Code", base.DEC)
local f_qh_host = ProtoField.string("qh.host", "Host")
local f_qh_path = ProtoField.string("qh.path", "Path")
local f_qh_body = ProtoField.bytes("qh.body", "Body")

-- Register all fields with the protocol
qotp_proto.fields = {
    f_msg_type,
    f_version,
    f_conn_id,
    f_encrypted,
    f_decrypted,
    f_header,
    f_qh_version,
    f_qh_type,
    f_qh_method,
    f_qh_status,
    f_qh_host,
    f_qh_path,
    f_qh_body
}

qotp_proto.prefs.keylog_file = Pref.string("Keylog file", "", "Path to QOTP keylog file")

local shared_secrets = {}
local keylog_last_size = -1

-- Helper function to convert buffer bytes to hex string for connection ID
-- Reads the 8-byte connection ID directly from buffer and converts to hex string
-- Always pads to 16 hex chars (8 bytes) for consistent key lookups
local function buffer_to_hex_string(buffer, offset, length)
    local hex = ""
    for i = offset + length - 1, offset, -1 do  -- Read in reverse (little-endian to big-endian)
        hex = hex .. string.format("%02x", buffer(i, 1):uint())
    end
    -- Ensure padded to 16 hex chars for 8-byte connection ID
    if #hex < 16 then
        hex = string.rep("0", 16 - #hex) .. hex
    end
    return hex
end

-- Function to load keys from keylog file (supports reloading)
local function load_keylog_file(filepath)
    if filepath == "" then return end
    
    print(string.format("=== Reloading keylog: %s", filepath))
    
    local file = io.open(filepath, "r")
    if not file then
        print("Could not open keylog: " .. filepath)
        return
    end
    
    -- Clear existing keys before reload
    shared_secrets = {}
    
    local count = 0
    local line_num = 0
    for line in file:lines() do
        line_num = line_num + 1
        if line:sub(1,1) ~= "#" and line:match("%S") then
            local conn_id_str, secret_hex
            local _, id1, sec1 = line:match("^(QOTP_SHARED_SECRET)%s+(%S+)%s+(%S+)$")
            if id1 then
                conn_id_str, secret_hex = id1, sec1
            else
                conn_id_str, secret_hex = line:match("^(%S+)%s+(%S+)$")
            end
            
            if line_num <= 2 then
                print(string.format("Line %d: conn_id='%s' secret_len=%d", line_num, conn_id_str or "nil", secret_hex and #secret_hex or 0))
            end
            
            -- Secret should be 64 hex chars (32 bytes), but accept 63-64
            if conn_id_str and secret_hex and (#secret_hex == 63 or #secret_hex == 64) then
                local id = conn_id_str:lower():gsub("^0x", "")
                if id:match("^[0-9a-f]+$") then
                    -- Ensure ID is padded to 16 hex chars (8 bytes)
                    id = string.rep("0", 16 - #id) .. id
                    -- Ensure secret is padded to 64 hex chars (32 bytes)
                    secret_hex = string.rep("0", 64 - #secret_hex) .. secret_hex
                    if qotp_decrypt.set_key(id, secret_hex) then
                        shared_secrets[id] = secret_hex
                        count = count + 1
                    end
                end
            end
        end
    end
    file:close()
    print(string.format("=== Loaded %d keys from %d lines", count, line_num))
    print("=== All loaded connection IDs:")
    for k, v in pairs(shared_secrets) do
        print(string.format("  - %s", k))
    end
end

-- Check if keylog file has changed and reload if needed
local function check_and_reload_keylog(filepath)
    print(string.format("=== check_and_reload_keylog ENTER filepath='%s'", tostring(filepath)))
    if not filepath or filepath == "" then
        print("check_and_reload_keylog: No filepath")
        return
    end
    
    local file = io.open(filepath, "r")
    if not file then
        print(string.format("check_and_reload_keylog: Cannot open %s", filepath))
        return
    end
    
    -- Get file size as proxy for changes
    local current_size = file:seek("end")
    file:close()
    
    print(string.format("check_and_reload_keylog: size=%d, last=%d, keys_loaded=%s", current_size, keylog_last_size, next(shared_secrets) and "yes" or "no"))
    
    -- Reload if: size changed OR no keys loaded
    if current_size ~= keylog_last_size or next(shared_secrets) == nil then
        print(string.format("Reloading keylog (size_changed=%s, no_keys=%s)", 
            tostring(current_size ~= keylog_last_size), 
            tostring(next(shared_secrets) == nil)))
        keylog_last_size = current_size
        load_keylog_file(filepath)
    end
end

-- BEGIN AUTO-GENERATED MAPPINGS
local qh_methods = {
    [0] = "GET",
    [1] = "POST",
    [2] = "PUT",
    [3] = "PATCH",
    [4] = "DELETE",
    [5] = "HEAD",
}

local compact_to_status = {
    [0] = 200,  -- OK
    [1] = 404,  -- Not Found
    [2] = 500,  -- Internal Server Error
    [3] = 302,  -- Found
    [4] = 400,  -- Bad Request
    [5] = 403,  -- Forbidden
    [6] = 401,  -- Unauthorized
    [7] = 301,  -- Moved Permanently
    [8] = 304,  -- Not Modified
    [9] = 503,  -- Service Unavailable
    [10] = 201,  -- Created
    [11] = 202,  -- Accepted
    [12] = 204,  -- No Content
    [13] = 206,  -- Partial Content
    [14] = 307,  -- Temporary Redirect
    [15] = 308,  -- Permanent Redirect
    [16] = 409,  -- Conflict
    [17] = 410,  -- Gone
    [18] = 412,  -- Precondition Failed
    [19] = 413,  -- Request Entity Too Large
    [20] = 414,  -- Request URI Too Long
    [21] = 415,  -- Unsupported Media Type
    [22] = 422,  -- Unprocessable Entity
    [23] = 429,  -- Too Many Requests
    [24] = 502,  -- Bad Gateway
    [25] = 504,  -- Gateway Timeout
    [26] = 505,  -- HTTP Version Not Supported
    [27] = 100,  -- Continue
    [28] = 101,  -- Switching Protocols
    [29] = 102,  -- Processing
    [30] = 103,  -- Early Hints
    [31] = 205,  -- Reset Content
    [32] = 207,  -- Multi-Status
    [33] = 208,  -- Already Reported
    [34] = 226,  -- IM Used
    [35] = 300,  -- Multiple Choices
    [36] = 303,  -- See Other
    [37] = 305,  -- Use Proxy
    [38] = 402,  -- Payment Required
    [39] = 405,  -- Method Not Allowed
    [40] = 406,  -- Not Acceptable
    [41] = 407,  -- Proxy Authentication Required
    [42] = 408,  -- Request Timeout
    [43] = 411,  -- Length Required
    [44] = 416,  -- Requested Range Not Satisfiable
    [45] = 417,  -- Expectation Failed
}
-- END AUTO-GENERATED MAPPINGS

-- Helper function to read varint from decrypted data
local function read_varint(data, offset)
    local value = 0
    local shift = 0
    local bytes_read = 0
    
    while offset + bytes_read <= #data do
        local byte = data:byte(offset + bytes_read)
        bytes_read = bytes_read + 1
        
        value = value + bit.lshift(bit.band(byte, 0x7F), shift)
        shift = shift + 7
        
        if bit.band(byte, 0x80) == 0 then
            return value, bytes_read
        end
    end
    
    return nil, 0  -- Failed to read varint
end

-- Function to parse QH protocol from decrypted data string
local function parse_qh_protocol(decrypted_data, tree, pinfo)
    -- Skip very small packets - likely handshake/control data, not QH protocol
    if #decrypted_data < 19 then
        return
    end
    
    local qh_tree = tree:add(qotp_proto, "QH Protocol")
    -- QOTP overhead: 1 byte header + 4 bytes stream ID + 3 bytes offset = 8 bytes
    local offset = 9  -- Skip QOTP overhead (8 bytes) + start at QH data (byte 9 = index 9 in 1-based Lua)
    
    -- First byte format:
    -- Request:  Version (2 bits, bits 7-6) | Method (3 bits, bits 5-3) | Reserved (3 bits, bits 2-0)
    -- Response: Version (2 bits, bits 7-6) | Compact Status (6 bits, bits 5-0)
    local first_byte = decrypted_data:byte(offset)
    local qh_version = bit.rshift(first_byte, 6)
    
    qh_tree:add(f_qh_version, qh_version):set_generated()
    
    -- Determine if it's a request or response based on port direction
    -- Request: destination port 8090 (client -> server)
    -- Response: source port 8090 (server -> client)
    local is_request = (pinfo.dst_port == 8090)
    
    local method_bits = bit.band(bit.rshift(first_byte, 3), 0x07)  -- bits 5-3
    
    offset = offset + 1
    
    if is_request then
        -- Parse Request
        qh_tree:add(f_qh_type, "Request"):set_generated()
        local method_name = qh_methods[method_bits] or string.format("Unknown(%d)", method_bits)
        qh_tree:add(f_qh_method, method_name):set_generated()
        pinfo.cols.info:append(string.format(" [%s", method_name))
        
        -- Parse host (varint length + string)
        local host_len, varint_bytes = read_varint(decrypted_data, offset)
        if host_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset + host_len <= #decrypted_data then
                local host = decrypted_data:sub(offset, offset + host_len - 1)
                qh_tree:add(f_qh_host, host):set_generated()
                offset = offset + host_len
            end
        end
        
        -- Parse path (varint length + string)
        local path_len, varint_bytes = read_varint(decrypted_data, offset)
        if path_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset + path_len <= #decrypted_data then
                local path = decrypted_data:sub(offset, offset + path_len - 1)
                qh_tree:add(f_qh_path, path):set_generated()
                pinfo.cols.info:append(string.format(" %s]", path))
                offset = offset + path_len
            else
                pinfo.cols.info:append("]")
            end
        else
            pinfo.cols.info:append("]")
        end
        
    else
        -- Parse Response
        qh_tree:add(f_qh_type, "Response"):set_generated()
        local compact_status = bit.band(first_byte, 0x3F)  -- Lower 6 bits
        local http_status = compact_to_status[compact_status] or 500
        
        qh_tree:add(f_qh_status, http_status):set_generated()
        pinfo.cols.info:append(string.format(" [Status: %d]", http_status))
    end
    
    -- Find body (after ETX marker 0x03)
    local etx_pos = decrypted_data:find("\x03", offset, true)
    if etx_pos and etx_pos < #decrypted_data then
        local body_len = #decrypted_data - etx_pos
        if body_len > 0 then
            qh_tree:add(f_qh_body, body_len .. " bytes"):set_generated()
        end
    end
end

-- Dissector function
function qotp_proto.dissector(buffer, pinfo, tree)
    if buffer:len() == 0 then return end
    
    pinfo.cols.protocol = qotp_proto.name
    local subtree = tree:add(qotp_proto, buffer(), "QOTP Protocol Data")
    
    local header_byte = buffer(0, 1):uint()
    local msg_type = bit.rshift(header_byte, 5)
    local version = bit.band(header_byte, 0x1F)
    
    -- Get message type string
    local msg_type_names = {
        [0] = "InitSnd",
        [1] = "InitRcv",
        [2] = "InitCryptoSnd", 
        [3] = "InitCryptoRcv",
        [4] = "Data"
    }
    
    local msg_type_str = msg_type_names[msg_type] or "Unknown"
    
    subtree:add(f_msg_type, buffer(0, 1), msg_type_str)
    subtree:add(f_version, buffer(0, 1), version)
    
    if msg_type ~= 0 and buffer:len() >= 9 then
        subtree:add_le(f_conn_id, buffer(1, 8))
        local conn_id_hex = buffer_to_hex_string(buffer, 1, 8)
        pinfo.cols.info = msg_type_str .. " (" .. conn_id_hex .. ")"
    else
        pinfo.cols.info = msg_type_str
    end
    
    if msg_type == 4 and buffer:len() > 9 then
        local encrypted_portion = buffer(9, buffer:len() - 9):bytes()
        subtree:add(f_encrypted, buffer(9, buffer:len() - 9))
        local conn_id_hex = buffer_to_hex_string(buffer, 1, 8)
        
        -- Auto-reload keylog on first pass through packets
        if pinfo.visited == false then
            print(string.format("Data packet: keylog_file='%s'", qotp_proto.prefs.keylog_file or "nil"))
            local status, err = pcall(check_and_reload_keylog, qotp_proto.prefs.keylog_file)
            if not status then
                print(string.format("ERROR in check_and_reload_keylog: %s", tostring(err)))
            end
            
            -- Debug: show what we're looking for
            print(string.format("Looking for key: %s (len=%d)", conn_id_hex, #conn_id_hex))
            print(string.format("Available keys: %s", next(shared_secrets) and "yes" or "no"))
            for k, v in pairs(shared_secrets) do
                print(string.format("  Have key: %s (len=%d) match=%s", k, #k, k == conn_id_hex and "YES" or "NO"))
            end
            print(string.format("Lookup result: %s", shared_secrets[conn_id_hex] and "FOUND" or "NOT FOUND"))
        end

        if shared_secrets[conn_id_hex] then
            local decrypted, used_epoch, used_sender
            for _, is_sender in ipairs({false, true}) do
                for epoch = 0, 2 do
                    decrypted = qotp_decrypt.decrypt_data(encrypted_portion:raw(), conn_id_hex, is_sender, epoch)
                    if decrypted then
                        used_epoch, used_sender = epoch, is_sender
                        break
                    end
                end
                if decrypted then break end
            end
            
            if decrypted then
                local decrypted_tvb = ByteArray.new(decrypted, true):tvb("Decrypted Data")
                subtree:add(f_decrypted, decrypted_tvb():range()):append_text(string.format(" (E:%d S:%s)", used_epoch, used_sender))
                parse_qh_protocol(decrypted, subtree, pinfo)
                pinfo.cols.info:append(" [Dec]")
            else
                subtree:add_expert_info(PI_DECRYPTION, PI_WARN, "Decryption failed")
            end
        else
            subtree:add_expert_info(PI_DECRYPTION, PI_NOTE, "No key")
        end
    elseif buffer:len() > 9 then
        subtree:add(f_encrypted, buffer(9, buffer:len() - 9))
    end
end

function qotp_proto.init()
    -- Only reset if no keys loaded yet
    if next(shared_secrets) == nil then
        print("init: No keys loaded, will load on first packet")
        keylog_last_size = -1  -- Force reload on first packet
    else
        print(string.format("init: Keys already loaded (%d), keeping them", #shared_secrets))
    end
end

-- Register the protocol on UDP port 8090
local udp_port = DissectorTable.get("udp.port")
udp_port:add(8090, qotp_proto)
