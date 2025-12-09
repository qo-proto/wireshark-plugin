-- QOTP Wireshark Dissector - Decrypts and dissects QOTP+QH protocol on UDP port 8090

print("=== QOTP Dissector Loading ===")

-- Get the directory where this script is located
local info = debug.getinfo(1, "S")
local script_path = info.source:match("@(.+)")
local script_dir = script_path and script_path:match("(.+)[/\\][^/\\]+$")

-- Detect platform
local is_windows = package.config:sub(1,1) == '\\'
local path_sep = is_windows and "\\" or "/"
local lib_ext = is_windows and ".dll" or ".so"

if script_dir then
    -- Add to package.cpath for Lua module loading
    package.cpath = script_dir .. path_sep .. "?" .. lib_ext .. ";" .. package.cpath
    
    -- Pre-load qotp_crypto library using absolute path
    local qotp_crypto_path = script_dir .. path_sep .. "qotp_crypto" .. lib_ext
    local loadlib_result, loadlib_err = package.loadlib(qotp_crypto_path, "*")
    if loadlib_result then
        -- Call the loader function to actually load the library
        local load_success, load_err = pcall(loadlib_result)
        if not load_success then
            print("Warning: Failed to pre-load qotp_crypto: " .. tostring(load_err))
        else
            print("Successfully pre-loaded qotp_crypto")
        end
    else
        print("Warning: package.loadlib failed for qotp_crypto: " .. tostring(loadlib_err))
        -- On Linux, we might need to rely on LD_LIBRARY_PATH or RPATH instead
        if not is_windows then
            print("On Linux: Make sure qotp_crypto.so is in the same directory as qotp_decrypt.so")
        end
    end
    
    print("Script directory: " .. script_dir)
    print("Package cpath: " .. package.cpath)
end

print("Loading qotp_decrypt module...")
local qotp_decrypt = require("qotp_decrypt")
print("qotp_decrypt loaded, running test...")
qotp_decrypt.test()
print("qotp_decrypt test complete")

-- Create protocol first (before accessing any prefs)
local qotp_proto = Proto("QOTP", "Quick UDP Transport Protocol")

-- Define fields for QOTP protocol (must be defined before using them)
local f_qotp_msg_type = ProtoField.string("qotp.msg_type", "Message Type")
local f_qotp_version = ProtoField.uint8("qotp.version", "Version", base.DEC)
local f_qotp_conn_id = ProtoField.uint64("qotp.conn_id", "Connection ID", base.HEX)
local f_qotp_encrypted = ProtoField.bytes("qotp.encrypted", "Encrypted Data")
local f_qotp_decrypted = ProtoField.bytes("qotp.decrypted", "Decrypted Data")
local f_qotp_header = ProtoField.bytes("qotp.header", "Header")

-- Define fields for QH protocol (inner protocol)
local f_qh_version = ProtoField.uint8("qh.version", "QH Version", base.DEC)
local f_qh_type = ProtoField.string("qh.type", "Type")
local f_qh_method = ProtoField.string("qh.method", "Operation")
local f_qh_status = ProtoField.uint16("qh.status", "Status Code", base.DEC)
local f_qh_host_length = ProtoField.uint16("qh.hostlength", "Host Length", base.DEC)
local f_qh_host = ProtoField.string("qh.host", "Host")
local f_qh_path_length = ProtoField.uint16("qh.pathlength", "Path Length", base.DEC)
local f_qh_path = ProtoField.string("qh.path", "Path")
local f_qh_header_length = ProtoField.uint16("qh.headerlength", "Header Length", base.DEC)
local f_qh_header = ProtoField.string("qh.header", "Header")
local f_qh_body_length = ProtoField.uint16("qh.bodylength", "Body Length", base.DEC)
local f_qh_body = ProtoField.string("qh.body", "Body")
local f_qh_temp_big = ProtoField.uint16("qh.tempbig", "Remaining Body Length", base.DEC)

-- Register all fields with the protocol
qotp_proto.fields = {
    f_qotp_msg_type,
    f_qotp_version,
    f_qotp_conn_id,
    f_qotp_encrypted,
    f_qotp_decrypted,
    f_qotp_header,
    f_qh_version,
    f_qh_type,
    f_qh_method,
    f_qh_status,
    f_qh_host_length,
    f_qh_host,
    f_qh_path_length,
    f_qh_path,
    f_qh_header_length,
    f_qh_header,
    f_qh_body_length,
    f_qh_body,
    f_qh_temp_big
}

qotp_proto.prefs.keylog_file = Pref.string("Keylog file", "", "Path to QOTP keylog file")

local shared_secrets = {}
local shared_secrets_id = {}  -- For QOTP_SHARED_SECRET_ID keys
local keylog_last_size = -1

-- Simple helpers to decode tiny JSON payloads (no external JSON lib available in Wireshark Lua)
local function parse_methods_json(json_str)
    if not json_str or #json_str == 0 then return nil end
    local methods = {}
    for m in string.gmatch(json_str, '"([^"]+)"') do
        methods[#methods + 1] = m
    end
    if #methods == 0 then return nil end
    local map = {}
    for i, v in ipairs(methods) do
        map[i - 1] = v  -- zero-based method codes
    end
    return map
end

local function parse_headers_json(json_str)
    if not json_str or #json_str == 0 then 
        print("DEBUG parse_headers_json: json_str is empty or nil")
        return nil 
    end
    local map = {}
    
    print(string.format("DEBUG parse_headers_json: Starting parse of %d bytes", #json_str))
    
    -- Simple parser for JSON: {"1":{"Name":"X","Value":"Y"},...}
    local i = 1
    local entry_count = 0
    while i < #json_str do
        -- Find next key: "NUMBER":
        local key_start, key_end, key_str = json_str:find('"(%d+)":', i)
        if not key_start then 
            print(string.format("DEBUG parse_headers_json: No more keys found at position %d", i))
            break 
        end
        
        local key = tonumber(key_str)
        if not key then 
            i = key_end + 1
            break 
        end
        
        -- Find the opening { of the value object
        local obj_start = json_str:find('{', key_end)
        if not obj_start then break end
        
        -- Find the matching closing }
        local depth = 1
        local obj_end = obj_start + 1
        while obj_end <= #json_str and depth > 0 do
            local c = json_str:sub(obj_end, obj_end)
            if c == '{' then depth = depth + 1
            elseif c == '}' then depth = depth - 1
            end
            obj_end = obj_end + 1
        end
        
        if depth == 0 then
            local obj_content = json_str:sub(obj_start, obj_end)
            local name_val = ""
            local value_val = ""
            
            -- Find Name value (capitalized for JSON)
            -- Pattern: "Name":"<value>"
            local name_pattern = '"Name"%s*:%s*"([^"]*)"'
            name_val = obj_content:match(name_pattern) or ""
            
            -- Find Value value (capitalized for JSON)
            -- Pattern: "Value":"<value>"
            local value_pattern = '"Value"%s*:%s*"([^"]*)"'
            value_val = obj_content:match(value_pattern) or ""
            
            map[key] = { name = name_val, value = value_val }
            entry_count = entry_count + 1
            i = obj_end
        else
            break
        end
    end
    
    print(string.format("DEBUG parse_headers_json: Parsed %d entries", entry_count))
    if next(map) == nil then 
        print("DEBUG parse_headers_json: map is empty, returning nil")
        return nil 
    end
    return map
end

local function load_qh_tables_from_go()
    local methods_map
    local req_headers_map
    local resp_headers_map

    local ok_methods, methods_json = pcall(function()
        if qotp_decrypt.get_qh_methods then
            return qotp_decrypt.get_qh_methods()
        end
    end)
    if ok_methods and methods_json then
        methods_map = parse_methods_json(methods_json)
    end

    local ok_req_headers, req_headers_json = pcall(function()
        if qotp_decrypt.get_qh_request_headers then
            return qotp_decrypt.get_qh_request_headers()
        end
    end)
    if ok_req_headers and req_headers_json then
        print(string.format("DEBUG: Request headers JSON length: %d", #req_headers_json))
        print(string.format("DEBUG: First 200 chars: %s", req_headers_json:sub(1, 200)))
        req_headers_map = parse_headers_json(req_headers_json)
        if req_headers_map then
            local count = 0
            for k, v in pairs(req_headers_map) do
                count = count + 1
                if k <= 0x05 then  -- Only print first few
                    print(string.format("DEBUG: Header 0x%02x (%d) = {name=%s, value=%s}", k, k, tostring(v.name), tostring(v.value)))
                end
            end
            print(string.format("DEBUG: Total parsed request headers: %d", count))
        else
            print("DEBUG: parse_headers_json returned nil")
        end
    end

    local ok_resp_headers, resp_headers_json = pcall(function()
        if qotp_decrypt.get_qh_response_headers then
            return qotp_decrypt.get_qh_response_headers()
        end
    end)
    if ok_resp_headers and resp_headers_json then
        resp_headers_map = parse_headers_json(resp_headers_json)
    end

    return methods_map, req_headers_map, resp_headers_map
end

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
                       -- Try matching QOTP_SHARED_SECRET or QOTP_SHARED_SECRET_ID
            local label, id1, sec1 = line:match("^(QOTP_SHARED_SECRET_ID)%s+(%S+)%s+(%S+)$")
            if label then
                conn_id_str, secret_hex, is_secret_id = id1, sec1, true
            else
                label, id1, sec1 = line:match("^(QOTP_SHARED_SECRET)%s+(%S+)%s+(%S+)$")
                if label then
                    conn_id_str, secret_hex, is_secret_id = id1, sec1, false
                else
                    -- Fallback: plain format (conn_id secret)
                    conn_id_str, secret_hex = line:match("^(%S+)%s+(%S+)$")
                    is_secret_id = false
                end
            end
            
            if line_num <= 5 then
                print(string.format("Line %d: conn_id='%s' secret_len=%d is_id=%s", 
                    line_num, conn_id_str or "nil", secret_hex and #secret_hex or 0, tostring(is_secret_id)))
            end
            
            -- Secret should be 64 hex chars (32 bytes), but accept 63-64
            if conn_id_str and secret_hex and (#secret_hex == 63 or #secret_hex == 64) then
                local id = conn_id_str:lower():gsub("^0x", "")
                if id:match("^[0-9a-f]+$") then
                    -- Ensure ID is padded to 16 hex chars (8 bytes)
                    id = string.rep("0", 16 - #id) .. id
                    -- Ensure secret is padded to 64 hex chars (32 bytes)
                    secret_hex = string.rep("0", 64 - #secret_hex) .. secret_hex
--                    if qotp_decrypt.set_key(id, secret_hex) then
                    -- Call appropriate set_key function based on secret type
                    local success
                    if is_secret_id then
                        success = qotp_decrypt.set_key_id(id, secret_hex)
                    else
                        success = qotp_decrypt.set_key(id, secret_hex)
                    end
                    
                    if success then
                        if is_secret_id then
                            shared_secrets_id[id] = secret_hex
                        else
                            shared_secrets[id] = secret_hex
                        end
                        count = count + 1
                    end
                end
            end
        end
    end
    file:close()
    print(string.format("=== Loaded %d keys from %d lines", count, line_num))
    print("=== All loaded connection IDs (SHARED_SECRET):")
    for k, v in pairs(shared_secrets) do
        print(string.format("  - %s", k))
    end
    print("=== All loaded connection IDs (SHARED_SECRET_ID):")
    for k, v in pairs(shared_secrets_id) do
        print(string.format("  - %s", k))
    end
end

-- Check if keylog file has changed and reload if needed
local function check_and_reload_keylog(filepath)
    if not filepath or filepath == "" then
        return
    end
    
    local file = io.open(filepath, "r")
    if not file then
        return
    end
    
    -- Get file size as proxy for changes
    local current_size = file:seek("end")
    file:close()
    
    -- Always reload if size changed (file was updated)
    if current_size ~= keylog_last_size then
        print(string.format("Reloading keylog (size changed: %d -> %d)", keylog_last_size, current_size))
        keylog_last_size = current_size
        load_keylog_file(filepath)
    end
end

local loaded_qh_methods, loaded_req_headers, loaded_resp_headers = load_qh_tables_from_go()
if not loaded_qh_methods then
    print("ERROR: failed to load QH method table from Go; QH decoding will be limited")
end
local qh_methods = loaded_qh_methods or {}
local qh_request_headers = loaded_req_headers or {}
local qh_response_headers = loaded_resp_headers or {}

local function decode_status(compact_status)
    if qotp_decrypt and qotp_decrypt.get_qh_status_from_compact then
        local ok, http_status = pcall(qotp_decrypt.get_qh_status_from_compact, compact_status)
        if ok and http_status then
            return http_status
        end
    end
    return 500
end

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

-- Function to parse and display QH headers using the header lookup tables
local function parse_qh_headers(header_data, headers_tree, is_request)
    if not header_data or #header_data == 0 then
        return
    end
    
    local headers_table = is_request and qh_request_headers or qh_response_headers
    local offset = 1
    
    while offset <= #header_data do
        -- Read header ID (variable length encoded)
        local header_id, varint_bytes = read_varint(header_data, offset)
        if not header_id or varint_bytes == 0 then
            break
        end
        offset = offset + varint_bytes
        
        -- Ensure header_id is a number
        header_id = tonumber(header_id) or header_id
        if not header_id then break end
        
        -- Look up header name and value in static table
        local header_entry = headers_table[header_id]
        if header_entry then
            local header_name = header_entry.name
            local header_value = header_entry.value
            
            -- Check if we got valid data from the entry
            if header_name and #header_name > 0 then
                -- Format 2 (0x41+): name-only headers with a trailing value
                if header_id >= 0x41 and offset <= #header_data then
                    -- Read the value byte/string that follows
                    local value_len, varint_bytes = read_varint(header_data, offset)
                    if value_len and varint_bytes > 0 then
                        offset = offset + varint_bytes
                        local actual_value = ""
                        if value_len > 0 and offset + value_len <= #header_data then
                            actual_value = header_data:sub(offset, offset + value_len - 1)
                            offset = offset + value_len
                        end
                        -- Display as name: value
                        headers_tree:add(f_qh_header, string.format("%s: %s [ID: 0x%02x]", header_name, actual_value, tonumber(header_id))):set_generated()
                    else
                        -- No value found, just display name
                        headers_tree:add(f_qh_header, string.format("%s [ID: 0x%02x]", header_name, tonumber(header_id))):set_generated()
                    end
                else
                    -- Format 1 (0x01-0x40): name-value pairs from static table
                    if header_value and #header_value > 0 then
                        headers_tree:add(f_qh_header, string.format("%s: %s [ID: 0x%02x]", header_name, header_value, tonumber(header_id))):set_generated()
                    else
                        -- Name-only entry (shouldn't happen in Format 1 but handle it)
                        headers_tree:add(f_qh_header, string.format("%s [ID: 0x%02x]", header_name, tonumber(header_id))):set_generated()
                    end
                end
            else
                -- Entry exists but has no name - shouldn't happen
                print(string.format("DEBUG: Header ID %d (0x%02x) entry has no name", tonumber(header_id), tonumber(header_id)))
                headers_tree:add(f_qh_header, string.format("[Header ID: 0x%02x] (no name)", tonumber(header_id))):set_generated()
            end
        else
            print(string.format("DEBUG: Header ID %d (0x%02x) not found in table. Table empty: %s", tonumber(header_id), tonumber(header_id), next(headers_table) == nil and "yes" or "no"))
            headers_tree:add(f_qh_header, string.format("[Unknown Header ID: 0x%02x]", tonumber(header_id))):set_generated()
        end
    end
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
        
    offset = offset + 1
    
    if is_request then
        local method_bits = bit.band(bit.rshift(first_byte, 3), 0x07)  -- bits 5-3
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
                qh_tree:add(f_qh_host_length, host_len):set_generated()
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
                qh_tree:add(f_qh_path_length, path_len):set_generated()
                qh_tree:add(f_qh_path, path):set_generated()
                pinfo.cols.info:append(string.format(" %s]", path))
                offset = offset + path_len
            else
                pinfo.cols.info:append("]")
            end
        else
            pinfo.cols.info:append("]")
        end

        local header_len, varint_bytes = read_varint(decrypted_data, offset)
        if header_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset + header_len <= #decrypted_data then
                local header = decrypted_data:sub(offset, offset + header_len -1)
                local header_tree = qh_tree:add(f_qh_header_length, header_len):set_generated()
                parse_qh_headers(header, header_tree, true)  -- true = is_request
                offset = offset + header_len
            end
        end

        local body_len, varint_bytes = read_varint(decrypted_data, offset)
        if body_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset < #decrypted_data then
                local available = #decrypted_data - offset + 1
                if body_len <= available then
                    local body = decrypted_data:sub(offset, offset + body_len - 1)
                    qh_tree:add(f_qh_body_length, body_len):set_generated()
                    qh_tree:add(f_qh_body, body):set_generated()
                    offset = offset + body_len
                else
                    local body = decrypted_data:sub(offset)
                    local remaining = body_len - available
                    qh_tree:add(f_qh_body_length, body_len):set_generated()
                    qh_tree:add(f_qh_body, body .. " [truncated]"):set_generated()
                    qh_tree:add(f_qh_temp_big, remaining):set_generated()
                    offset = #decrypted_data + 1
                end
            else
                qh_tree:add(f_qh_body_length, body_len):set_generated()
                qh_tree:add(f_qh_body, "No Body (truncated or missing)"):set_generated()
            end
        end


    else
        -- Parse Response
        qh_tree:add(f_qh_type, "Response"):set_generated()
        local compact_status = bit.band(first_byte, 0x3F)  -- Lower 6 bits
        local http_status = decode_status(compact_status)
        
        qh_tree:add(f_qh_status, http_status):set_generated()
        pinfo.cols.info:append(string.format(" [Status: %d]", http_status))
        
        -- Parse headers (varint length + header data)
        local header_len, varint_bytes = read_varint(decrypted_data, offset)
        if header_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset + header_len <= #decrypted_data then
                local header = decrypted_data:sub(offset, offset + header_len - 1)
                local header_tree = qh_tree:add(f_qh_header_length, header_len):set_generated()
                parse_qh_headers(header, header_tree, false)  -- false = is_response
                offset = offset + header_len
            end
        end
        
        -- Parse body (varint length + body data)
        local body_len, varint_bytes = read_varint(decrypted_data, offset)
        if body_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset < #decrypted_data then
                local available = #decrypted_data - offset + 1
                if body_len <= available then
                    local body = decrypted_data:sub(offset, offset + body_len - 1)
                    qh_tree:add(f_qh_body_length, body_len):set_generated()
                    qh_tree:add(f_qh_body, body):set_generated()
                    offset = offset + body_len
                else
                    local body = decrypted_data:sub(offset)
                    local remaining = body_len - available
                    qh_tree:add(f_qh_body_length, body_len):set_generated()
                    qh_tree:add(f_qh_body, body .. " [truncated]"):set_generated()
                    qh_tree:add(f_qh_temp_big, remaining):set_generated()
                    
                    -- On first pass, set up reassembly state for this connection
                    if not pinfo.visited then
                        body_reassembly_state[conn_id_hex] = {
                            remaining_body_length = remaining,
                            last_packet = pinfo.number
                        }
                    end
                    
                    offset = #decrypted_data + 1
                end
            else
                qh_tree:add(f_qh_body_length, body_len):set_generated()
                qh_tree:add(f_qh_body, "No Body (truncated or missing)"):set_generated()
            end
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
    
    subtree:add(f_qotp_msg_type, buffer(0, 1), msg_type_str)
    subtree:add(f_qotp_version, buffer(0, 1), version)
    
    -- Auto-reload keylog on first pass through ALL packets
    if pinfo.visited == false then
        local status, err = pcall(check_and_reload_keylog, qotp_proto.prefs.keylog_file)
        if not status then
            print(string.format("ERROR in check_and_reload_keylog: %s", tostring(err)))
        end
    end
    
    if msg_type ~= 0 and buffer:len() >= 9 then
        subtree:add_le(f_qotp_conn_id, buffer(1, 8))
        local conn_id_hex = buffer_to_hex_string(buffer, 1, 8)
        pinfo.cols.info = msg_type_str .. " (" .. conn_id_hex .. ")"
    else
        pinfo.cols.info = msg_type_str
    end
    
    -- Decrypt all packet types with encrypted data (InitRcv=1, InitCryptoSnd=2, InitCryptoRcv=3, Data=4)
    -- InitSnd (0) has no encrypted data, only public keys
    if msg_type >= 1 and msg_type <= 4 and buffer:len() > 9 then
        subtree:add(f_qotp_encrypted, buffer(9, buffer:len() - 9))
        local conn_id_hex = buffer_to_hex_string(buffer, 1, 8)
        
        -- Debug info on first pass
        if pinfo.visited == false then
            print(string.format("%s packet: keylog_file='%s'", msg_type_str, qotp_proto.prefs.keylog_file or "nil"))
            
            -- Debug: show what we're looking for
            print(string.format("Looking for key: %s (len=%d) msg_type=%d (%s)", conn_id_hex, #conn_id_hex, msg_type, msg_type_str))
            print(string.format("Available keys (PFS): %s", next(shared_secrets) and "yes" or "no"))
            print(string.format("Available keys (ID): %s", next(shared_secrets_id) and "yes" or "no"))
            for k, v in pairs(shared_secrets) do
                print(string.format("  Have PFS key: %s (len=%d) match=%s", k, #k, k == conn_id_hex and "YES" or "NO"))
            end
            for k, v in pairs(shared_secrets_id) do
                print(string.format("  Have ID key: %s (len=%d) match=%s", k, #k, k == conn_id_hex and "YES" or "NO"))
            end
            -- Check if we have at least one key (PFS or ID)
            local has_pfs = shared_secrets[conn_id_hex] ~= nil
            local has_id = shared_secrets_id[conn_id_hex] ~= nil
            print(string.format("Keys for this connection: PFS=%s, ID=%s", has_pfs and "YES" or "NO", has_id and "YES" or "NO"))
        end

        -- We need at least one key type to attempt decryption (Go will use the right one)
        if shared_secrets[conn_id_hex] or shared_secrets_id[conn_id_hex] then
            -- Pass full packet data (header + conn_id + encrypted portion) to decrypt function
            local full_packet = buffer(0, buffer:len()):bytes()
            if pinfo.visited == false then
                print(string.format("Attempting decrypt: packet_len=%d", buffer:len()))
            end
            
            local decrypted, used_epoch, used_sender
            local epoch = 0  -- Only try epoch 0
            
            for _, is_sender in ipairs({false, true}) do
                decrypted = qotp_decrypt.decrypt_data(full_packet:raw(), conn_id_hex, is_sender, epoch)
                if pinfo.visited == false then
                    print(string.format("  Try: is_sender=%s epoch=%d result=%s", 
                        tostring(is_sender), epoch, decrypted and "SUCCESS" or "FAILED"))
                end
                if decrypted then
                    used_epoch, used_sender = epoch, is_sender
                    break
                end
            end
            
            if decrypted then
                local decrypted_tvb = ByteArray.new(decrypted, true):tvb("Decrypted Data")
                subtree:add(f_qotp_decrypted, decrypted_tvb():range()):append_text(string.format(" (E:%d S:%s)", used_epoch, used_sender))
                parse_qh_protocol(decrypted, subtree, pinfo)
                pinfo.cols.info:append(" [Dec]")
            else
                subtree:add_expert_info(PI_DECRYPTION,PI_WARN, "Decryption failed for secret: " .. (shared_secrets[conn_id_hex]))
                subtree:add_expert_info(PI_DECRYPTION,PI_NOTE,"Decryption failed for secret_id: " .. (shared_secrets_id[conn_id_hex]))
                subtree:add_expert_info(PI_DECRYPTION, PI_WARN, "Decryption failed for connection: " .. conn_id_hex)
                local has_pfs = shared_secrets[conn_id_hex] ~= nil
                local has_id = shared_secrets_id[conn_id_hex] ~= nil
                subtree:add_expert_info(PI_DECRYPTION, PI_NOTE, string.format("Available keys: PFS=%s, ID=%s", has_pfs and "YES" or "NO", has_id and "YES" or "NO"))
            end
        else
            -- Show what keys are missing
            subtree:add_expert_info(PI_DECRYPTION, PI_WARN, "No keys found for connection ID: " .. conn_id_hex)
            
            -- Show available keys
            local pfs_list = {}
            local id_list = {}
            for k, _ in pairs(shared_secrets) do
                table.insert(pfs_list, k)
            end
            for k, _ in pairs(shared_secrets_id) do
                table.insert(id_list, k)
            end
            if #pfs_list > 0 then
                subtree:add_expert_info(PI_DECRYPTION, PI_NOTE, "Available PFS keys (" .. #pfs_list .. "): " .. table.concat(pfs_list, ", "))
            end
            if #id_list > 0 then
                subtree:add_expert_info(PI_DECRYPTION, PI_NOTE, "Available ID keys (" .. #id_list .. "): " .. table.concat(id_list, ", "))
            end
            if #pfs_list == 0 and #id_list == 0 then
                subtree:add_expert_info(PI_DECRYPTION, PI_NOTE, "No keys loaded from keylog file")
            end
        end
    elseif buffer:len() > 9 then
        subtree:add(f_qotp_encrypted, buffer(9, buffer:len() - 9))
    end
end

function qotp_proto.init()
    -- Only reset if no keys loaded yet
    if next(shared_secrets) == nil and next(shared_secrets_id) == nil then
        print("init: No keys loaded, will load on first packet")
        keylog_last_size = -1  -- Force reload on first packet
    else
        local pfs_count = 0
        local id_count = 0
        for _ in pairs(shared_secrets) do pfs_count = pfs_count + 1 end
        for _ in pairs(shared_secrets_id) do id_count = id_count + 1 end
        print(string.format("init: Keys already loaded (PFS: %d, ID: %d), keeping them", pfs_count, id_count))
    end
end

-- Register the protocol on UDP port 8090
local udp_port = DissectorTable.get("udp.port")
udp_port:add(8090, qotp_proto)
