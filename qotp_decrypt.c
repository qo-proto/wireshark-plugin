// qotp_decrypt.dll - Lua bridge to qotp_crypto.dll for Wireshark

#include <stdlib.h>
#include "lua.hpp"
#include <windows.h>

#define VERSION "1.0.0"

typedef int (*SetKeyFunc)(unsigned long long, const char*);
typedef int (*DecryptFunc)(const char*, int, unsigned long long, int, unsigned long long, char*, int);
typedef char* (*GetVersionFunc)();

static HMODULE dll = NULL;
static SetKeyFunc set_key = NULL;
static DecryptFunc decrypt = NULL;
static GetVersionFunc get_version = NULL;

static int load_dll() {
    if (dll) return 1;
    
    if (!(dll = LoadLibraryA("qotp_crypto.dll"))) {
        MessageBox(0, "Failed to load qotp_crypto.dll", "Error", MB_ICONERROR);
        return 0;
    }
    
    set_key = (SetKeyFunc)GetProcAddress(dll, "SetSharedSecretHex");
    decrypt = (DecryptFunc)GetProcAddress(dll, "DecryptDataPacket");
    get_version = (GetVersionFunc)GetProcAddress(dll, "GetVersion");
    
    if (!set_key || !decrypt) {
        MessageBox(0, "Failed to load functions", "Error", MB_ICONERROR);
        FreeLibrary(dll);
        dll = NULL;
        return 0;
    }
    return 1;
}

static int lua_decrypt_data(lua_State* L) {
    if (!load_dll()) {
        lua_pushnil(L);
        return 1;
    }
    
    size_t len;
    const char* encrypted = luaL_checklstring(L, 1, &len);
    
    unsigned long long conn_id;
    if (lua_type(L, 2) == LUA_TSTRING) {
        if (sscanf(luaL_checkstring(L, 2), "%llx", &conn_id) != 1) {
            lua_pushnil(L);
            return 1;
        }
    } else {
        conn_id = luaL_checkinteger(L, 2);
    }
    
    char* output = (char*)malloc(65536);
    if (!output) {
        lua_pushnil(L);
        return 1;
    }
    
    int result = decrypt(encrypted, (int)len, conn_id, lua_toboolean(L, 3), 
                        luaL_checkinteger(L, 4), output, 65536);
    
    if (result < 0) {
        free(output);
        lua_pushnil(L);
        return 1;
    }
    
    lua_pushlstring(L, output, result);
    free(output);
    return 1;
}

static int lua_set_key(lua_State* L) {
    if (!load_dll()) {
        lua_pushboolean(L, 0);
        return 1;
    }
    
    unsigned long long conn_id;
    if (lua_type(L, 1) == LUA_TSTRING) {
        if (sscanf(luaL_checkstring(L, 1), "%llx", &conn_id) != 1) {
            lua_pushboolean(L, 0);
            return 1;
        }
    } else {
        conn_id = luaL_checkinteger(L, 1);
    }
    
    lua_pushboolean(L, set_key(conn_id, luaL_checkstring(L, 2)) == 0);
    return 1;
}


static int lua_get_version(lua_State* L) {
    load_dll();
    lua_pushfstring(L, "v%s (Go: %s)", VERSION, get_version ? get_version() : "?");
    return 1;
}

static int lua_test(lua_State* L) {
    load_dll();
    return 0;
}

static const luaL_Reg funcs[] = {
    {"decrypt_data", lua_decrypt_data},
    {"set_key", lua_set_key},
    {"get_version", lua_get_version},
    {"test", lua_test},
    {NULL, NULL}
};

extern "C" __declspec(dllexport)
int luaopen_qotp_decrypt(lua_State* L) {
    luaL_newlib(L, funcs);
    return 1;
}
