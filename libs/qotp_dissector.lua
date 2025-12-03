-- QOTP Wireshark Dissector - Decrypts and dissects QOTP+QH protocol on UDP port 8090

print("=== QOTP Dissector Loading ===")

-- Detect platform
local is_windows = package.config:sub(1, 1) == '\\'
local is_macos = (io.popen("uname -s"):read("*l") or ""):match("Darwin") ~= nil

-- Get the directory where this script is located
local info = debug.getinfo(1, "S")
local script_path = info.source:match("@(.+)")
local script_dir = script_path and script_path:match("(.+)[/\\][^/\\]+$")

if script_dir then
    if is_windows then
        -- Windows: Load DLL
        package.cpath = script_dir .. "\\?.dll;" .. package.cpath
        -- Pre-load qotp_crypto.dll using absolute path
        local qotp_crypto_path = script_dir .. "\\qotp_crypto.dll"
        package.loadlib(qotp_crypto_path, "*")
    elseif is_macos then
        -- macOS: Load .so (Lua uses .so on macOS, not .dylib)
        package.cpath = script_dir .. "/?.so;" .. package.cpath
        -- Pre-load libqotp_crypto.dylib using absolute path
        local qotp_crypto_path = script_dir .. "/libqotp_crypto.dylib"
        package.loadlib(qotp_crypto_path, "*")
    else
        -- Linux: Load SO
        package.cpath = script_dir .. "/?.so;" .. package.cpath
        -- Pre-load libqotp_crypto.so using absolute path
        local qotp_crypto_path = script_dir .. "/libqotp_crypto.so"
        package.loadlib(qotp_crypto_path, "*")
    end
end

print("Loading qotp_decrypt module...")
local qotp_decrypt = require("qotp_decrypt")
print("Module version: " .. qotp_decrypt.get_version())
qotp_decrypt.test()
print("qotp_decrypt test complete")

-- Create protocol first (before accessing any prefs)
local qotp_proto = Proto("QOTP", "Quick UDP Transport Protocol")

-- Define fields for QOTP protocol
local f_msg_type = ProtoField.string("qotp.msg_type", "Message Type")
local f_version = ProtoField.uint8("qotp.version", "Version", base.DEC)
local f_conn_id = ProtoField.uint64("qotp.conn_id", "Connection ID", base.HEX)
local f_encrypted = ProtoField.bytes("qotp.encrypted", "Encrypted Data")
local f_decrypted = ProtoField.bytes("qotp.decrypted", "Decrypted Data")

-- Define fields for QH protocol (inner protocol)
local f_qh_version = ProtoField.uint8("qh.version", "QH Version", base.DEC)
local f_qh_type = ProtoField.string("qh.type", "Type")
local f_qh_method = ProtoField.string("qh.method", "Operation")
local f_qh_status = ProtoField.uint16("qh.status", "Status Code", base.DEC)
local f_qh_host = ProtoField.string("qh.host", "Host")
local f_qh_path = ProtoField.string("qh.path", "Path")
local f_qh_body = ProtoField.bytes("qh.body", "Body")

-- Register all fields
qotp_proto.fields = {
    f_msg_type, f_version, f_conn_id, f_encrypted, f_decrypted,
    f_qh_version, f_qh_type, f_qh_method, f_qh_status, f_qh_host, f_qh_path, f_qh_body
}

qotp_proto.prefs.keylog_file = Pref.string("Keylog file", "", "Path to QOTP keylog file")

local shared_secrets = {}
local shared_secrets_id = {}
local keylog_last_size = -1

-- Helper to convert buffer bytes to hex string (little-endian to big-endian)
local function buffer_to_hex_string(buffer, offset, length)
    local hex = ""
    for i = offset + length - 1, offset, -1 do
        hex = hex .. string.format("%02x", buffer(i, 1):uint())
    end
    if #hex < 16 then
        hex = string.rep("0", 16 - #hex) .. hex
    end
    return hex
end

-- Load keys from keylog file
-- Format: QOTP_SHARED_SECRET <conn_id_hex> <secret_hex>
--         QOTP_SHARED_SECRET_ID <conn_id_hex> <secret_id_hex>
local function load_keylog_file(filepath)
    if filepath == "" then return end

    print(string.format("=== Loading keylog: %s", filepath))

    local file = io.open(filepath, "r")
    if not file then
        print("Could not open keylog: " .. filepath)
        return
    end

    shared_secrets = {}
    shared_secrets_id = {}

    local count_pfs = 0
    local count_id = 0
    local line_num = 0

    for line in file:lines() do
        line_num = line_num + 1
        if line:sub(1, 1) ~= "#" and line:match("%S") then
            -- Try QOTP_SHARED_SECRET_ID format
            local label, conn_id_str, secret_hex = line:match("^(QOTP_SHARED_SECRET_ID)%s+(%S+)%s+(%S+)$")
            if label then
                local id = conn_id_str:lower():gsub("^0x", "")
                if id:match("^[0-9a-f]+$") and (#secret_hex == 63 or #secret_hex == 64) then
                    id = string.rep("0", 16 - #id) .. id
                    secret_hex = string.rep("0", 64 - #secret_hex) .. secret_hex
                    if qotp_decrypt.set_key_id then
                        qotp_decrypt.set_key_id(id, secret_hex)
                    end
                    shared_secrets_id[id] = secret_hex
                    count_id = count_id + 1
                end
            else
                -- Try QOTP_SHARED_SECRET or plain format
                label, conn_id_str, secret_hex = line:match("^(QOTP_SHARED_SECRET)%s+(%S+)%s+(%S+)$")
                if not label then
                    conn_id_str, secret_hex = line:match("^(%S+)%s+(%S+)$")
                end

                if conn_id_str and secret_hex and (#secret_hex == 63 or #secret_hex == 64) then
                    local id = conn_id_str:lower():gsub("^0x", "")
                    if id:match("^[0-9a-f]+$") then
                        id = string.rep("0", 16 - #id) .. id
                        secret_hex = string.rep("0", 64 - #secret_hex) .. secret_hex
                        if qotp_decrypt.set_key(id, secret_hex) then
                            shared_secrets[id] = secret_hex
                            count_pfs = count_pfs + 1
                        end
                    end
                end
            end
        end
    end
    file:close()
    print(string.format("=== Loaded %d PFS keys and %d ID keys from %d lines", count_pfs, count_id, line_num))
end

-- Check if keylog file changed and reload
local function check_and_reload_keylog(filepath)
    if not filepath or filepath == "" then return end

    local file = io.open(filepath, "r")
    if not file then return end

    local current_size = file:seek("end")
    file:close()

    if current_size ~= keylog_last_size or next(shared_secrets) == nil then
        keylog_last_size = current_size
        load_keylog_file(filepath)
    end
end

-- QH protocol mappings
local qh_methods = {
    [0] = "GET",
    [1] = "POST",
    [2] = "PUT",
    [3] = "PATCH",
    [4] = "DELETE",
    [5] = "HEAD",
}

local compact_to_status = {
    [0] = 200,
    [1] = 404,
    [2] = 500,
    [3] = 302,
    [4] = 400,
    [5] = 403,
    [6] = 401,
    [7] = 301,
    [8] = 304,
    [9] = 503,
    [10] = 201,
    [11] = 202,
    [12] = 204,
    [13] = 206,
    [14] = 307,
    [15] = 308,
    [16] = 409,
    [17] = 410,
    [18] = 412,
    [19] = 413,
    [20] = 414,
    [21] = 415,
    [22] = 422,
    [23] = 429,
    [24] = 502,
    [25] = 504,
    [26] = 505,
    [27] = 100,
    [28] = 101,
    [29] = 102,
    [30] = 103,
    [31] = 205,
    [32] = 207,
    [33] = 208,
    [34] = 226,
    [35] = 300,
    [36] = 303,
    [37] = 305,
    [38] = 402,
    [39] = 405,
    [40] = 406,
    [41] = 407,
    [42] = 408,
    [43] = 411,
    [44] = 416,
    [45] = 417,
}

-- Read varint
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

    return nil, 0
end

-- Parse QH protocol
local function parse_qh_protocol(decrypted_data, tree, pinfo)
    if #decrypted_data < 19 then return end

    local qh_tree = tree:add(qotp_proto, "QH Protocol")
    local offset = 9 -- Skip QOTP overhead

    local first_byte = decrypted_data:byte(offset)
    local qh_version = bit.rshift(first_byte, 6)
    qh_tree:add(f_qh_version, qh_version):set_generated()

    local is_request = (pinfo.dst_port == 8090)
    local method_bits = bit.band(bit.rshift(first_byte, 3), 0x07)
    offset = offset + 1

    if is_request then
        qh_tree:add(f_qh_type, "Request"):set_generated()
        local method_name = qh_methods[method_bits] or string.format("Unknown(%d)", method_bits)
        qh_tree:add(f_qh_method, method_name):set_generated()
        pinfo.cols.info:append(string.format(" [%s", method_name))

        local host_len, varint_bytes = read_varint(decrypted_data, offset)
        if host_len and varint_bytes > 0 then
            offset = offset + varint_bytes
            if offset + host_len <= #decrypted_data then
                local host = decrypted_data:sub(offset, offset + host_len - 1)
                qh_tree:add(f_qh_host, host):set_generated()
                offset = offset + host_len
            end
        end

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
        qh_tree:add(f_qh_type, "Response"):set_generated()
        local compact_status = bit.band(first_byte, 0x3F)
        local http_status = compact_to_status[compact_status] or 500
        qh_tree:add(f_qh_status, http_status):set_generated()
        pinfo.cols.info:append(string.format(" [Status: %d]", http_status))
    end

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

    -- Decrypt Data packets
    if msg_type == 4 and buffer:len() > 9 then
        local full_packet = buffer(0, buffer:len()):bytes()
        subtree:add(f_encrypted, buffer(9, buffer:len() - 9))
        local conn_id_hex = buffer_to_hex_string(buffer, 1, 8)

        if pinfo.visited == false then
            pcall(check_and_reload_keylog, qotp_proto.prefs.keylog_file)
        end

        if shared_secrets[conn_id_hex] then
            local decrypted, used_epoch, used_sender
            for _, is_sender in ipairs({ false, true }) do
                for epoch = 0, 2 do
                    decrypted = qotp_decrypt.decrypt_data(full_packet:raw(), conn_id_hex, is_sender, epoch)
                    if decrypted then
                        used_epoch, used_sender = epoch, is_sender
                        break
                    end
                end
                if decrypted then break end
            end

            if decrypted then
                local decrypted_tvb = ByteArray.new(decrypted, true):tvb("Decrypted Data")
                subtree:add(f_decrypted, decrypted_tvb():range()):append_text(
                    string.format(" (E:%d S:%s)", used_epoch, used_sender))
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
    if next(shared_secrets) == nil then
        keylog_last_size = -1
    end
end

-- Register on UDP port 8090
local udp_port = DissectorTable.get("udp.port")
udp_port:add(8090, qotp_proto)

print("=== QOTP Dissector Loaded ===")
