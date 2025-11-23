// qotp_decrypt - Lua bridge to qotp_crypto for Wireshark

#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include "lua.hpp"
#include <windows.h>
#define SHARED_LIB_EXT ".dll"
#define LOAD_LIBRARY(name) LoadLibraryA(name)
#define GET_PROC_ADDRESS(handle, name) GetProcAddress(handle, name)
#define SHOW_ERROR(msg) MessageBox(0, msg, "Error", MB_ICONERROR)
typedef HMODULE LibHandle;
#else
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#include <dlfcn.h>
#define SHARED_LIB_EXT ".so"
#define LOAD_LIBRARY(name) dlopen(name, RTLD_LAZY)
#define GET_PROC_ADDRESS(handle, name) dlsym(handle, name)
#define SHOW_ERROR(msg) fprintf(stderr, "%s\n", msg)
typedef void* LibHandle;
#endif

#define VERSION "1.0.0"

typedef int (*SetKeyFunc)(unsigned long long, const char*);
typedef int (*DecryptFunc)(const char*, int, unsigned long long, int, unsigned long long, char*, int);
typedef char* (*GetVersionFunc)();

static LibHandle dll = NULL;
static SetKeyFunc set_key = NULL;
static DecryptFunc decrypt = NULL;
static GetVersionFunc get_version = NULL;

static int load_dll() {
    if (dll) return 1;
    
#ifdef _WIN32
    // Get the path to the current DLL and construct path to qotp_crypto.dll
    char dllPath[MAX_PATH];
    HMODULE hModule;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&load_dll, &hModule)) {
        GetModuleFileNameA(hModule, dllPath, MAX_PATH);
        char* lastSlash = strrchr(dllPath, '\\');
        if (lastSlash) {
            strcpy(lastSlash + 1, "qotp_crypto.dll");
            dll = LOAD_LIBRARY(dllPath);
        }
    }
    if (!dll) {
        dll = LOAD_LIBRARY("qotp_crypto.dll");
    }
#else
    dll = LOAD_LIBRARY("qotp_crypto" SHARED_LIB_EXT);
#endif
    
    if (!dll) {
        SHOW_ERROR("Failed to load qotp_crypto" SHARED_LIB_EXT);
        return 0;
    }
    
    set_key = (SetKeyFunc)GET_PROC_ADDRESS(dll, "SetSharedSecretHex");
    decrypt = (DecryptFunc)GET_PROC_ADDRESS(dll, "DecryptDataPacket");
    get_version = (GetVersionFunc)GET_PROC_ADDRESS(dll, "GetVersion");
    
    if (!set_key || !decrypt) {
        SHOW_ERROR("Failed to load functions");
#ifdef _WIN32
        FreeLibrary(dll);
#else
        dlclose(dll);
#endif
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

#ifdef _WIN32
extern "C" __declspec(dllexport)
#else
extern
#endif
int luaopen_qotp_decrypt(lua_State* L) {
    luaL_newlib(L, funcs);
    return 1;
}
