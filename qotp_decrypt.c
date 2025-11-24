// qotp_decrypt - Lua bridge to qotp_crypto for Wireshark

#ifndef _WIN32
#define _GNU_SOURCE  // For dladdr on Linux
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
#ifdef _WIN32
#include <windows.h>
#define SHARED_LIB_EXT ".dll"
#define LOAD_LIBRARY(name) LoadLibraryA(name)
#define GET_PROC_ADDRESS(handle, name) GetProcAddress(handle, name)
#define SHOW_ERROR(msg) MessageBox(0, msg, "Error", MB_ICONERROR)
typedef HMODULE LibHandle;
#else
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
    // On Linux, try to load from the same directory as this module
    Dl_info info;
    if (dladdr((void*)load_dll, &info) && info.dli_fname) {
        // Get directory of current module
        char path[4096];
        const char* lastSlash = strrchr(info.dli_fname, '/');
        if (lastSlash) {
            size_t dirLen = lastSlash - info.dli_fname + 1;
            if (dirLen < sizeof(path) - 20) {  // Leave room for filename
                memcpy(path, info.dli_fname, dirLen);
                strcpy(path + dirLen, "qotp_crypto.so");
                dll = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
                if (dll) {
                    printf("[qotp_decrypt] Loaded qotp_crypto.so from: %s\n", path);
                }
            }
        }
    }
    // Fallback: try relative and absolute paths
    if (!dll) {
        dll = dlopen("./qotp_crypto.so", RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!dll) {
        dll = dlopen("qotp_crypto.so", RTLD_LAZY | RTLD_GLOBAL);
    }
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
        printf("[qotp_decrypt.c] Failed to load DLL\n");
        lua_pushnil(L);
        return 1;
    }
    
    size_t len;
    const char* encrypted = luaL_checklstring(L, 1, &len);
    
    unsigned long long conn_id;
    const char* conn_id_str = NULL;
    if (lua_type(L, 2) == LUA_TSTRING) {
        conn_id_str = luaL_checkstring(L, 2);
        if (sscanf(conn_id_str, "%llx", &conn_id) != 1) {
            printf("[qotp_decrypt.c] Failed to parse conn_id from hex string: %s\n", conn_id_str);
            lua_pushnil(L);
            return 1;
        }
        printf("[qotp_decrypt.c] Parsed conn_id: %s -> %llu (0x%llx)\n", conn_id_str, conn_id, conn_id);
    } else {
        conn_id = luaL_checkinteger(L, 2);
        printf("[qotp_decrypt.c] Got conn_id as integer: %llu (0x%llx)\n", conn_id, conn_id);
    }
    
    char* output = (char*)malloc(65536);
    if (!output) {
        printf("[qotp_decrypt.c] malloc failed\n");
        lua_pushnil(L);
        return 1;
    }
    
    int is_sender = lua_toboolean(L, 3);
    int epoch = luaL_checkinteger(L, 4);
    printf("[qotp_decrypt.c] Calling decrypt: len=%d, conn_id=%llu, is_sender=%d, epoch=%d\n", 
           (int)len, conn_id, is_sender, epoch);
    
    int result = decrypt(encrypted, (int)len, conn_id, is_sender, epoch, output, 65536);
    
    printf("[qotp_decrypt.c] Decrypt result: %d\n", result);
    
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
    const char* conn_id_str = NULL;
    if (lua_type(L, 1) == LUA_TSTRING) {
        conn_id_str = luaL_checkstring(L, 1);
        if (sscanf(conn_id_str, "%llx", &conn_id) != 1) {
            printf("[qotp_decrypt.c] set_key: Failed to parse conn_id from hex string: %s\n", conn_id_str);
            lua_pushboolean(L, 0);
            return 1;
        }
        printf("[qotp_decrypt.c] set_key: %s -> %llu (0x%llx)\n", conn_id_str, conn_id, conn_id);
    } else {
        conn_id = luaL_checkinteger(L, 1);
        printf("[qotp_decrypt.c] set_key: Got conn_id as integer: %llu (0x%llx)\n", conn_id, conn_id);
    }
    
    const char* secret = luaL_checkstring(L, 2);
    printf("[qotp_decrypt.c] set_key: secret_len=%d\n", (int)strlen(secret));
    int result = set_key(conn_id, secret);
    printf("[qotp_decrypt.c] set_key: result=%d\n", result);
    
    lua_pushboolean(L, result == 0);
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
