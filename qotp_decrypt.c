// qotp_decrypt - Lua bridge to qotp_crypto library for Wireshark
// Cross-platform: Windows DLL and Linux SO

#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
    #include <windows.h>
    #define EXPORT __declspec(dllexport)
    #define LIB_HANDLE HMODULE
    #define LOAD_LIB(name) LoadLibraryA(name)
    #define GET_FUNC(lib, name) GetProcAddress(lib, name)
    #define CLOSE_LIB(lib) FreeLibrary(lib)
    #define LIB_NAME "qotp_crypto.dll"
    #define SHOW_ERROR(msg) MessageBox(0, msg, "Error", MB_ICONERROR)
#else
    #include <dlfcn.h>
    #define EXPORT __attribute__((visibility("default")))
    #define LIB_HANDLE void*
    #define LOAD_LIB(name) dlopen(name, RTLD_LAZY)
    #define GET_FUNC(lib, name) dlsym(lib, name)
    #define CLOSE_LIB(lib) dlclose(lib)
    #define LIB_NAME "./libqotp_crypto.so"
    #define SHOW_ERROR(msg) fprintf(stderr, "%s: %s\n", msg, dlerror())
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
}
#endif

#define VERSION "1.0.0"

typedef int (*SetKeyFunc)(unsigned long long, const char*);
typedef int (*SetKeyIdFunc)(unsigned long long, const char*);
typedef int (*DecryptFunc)(const char*, int, unsigned long long, int, unsigned long long, char*, int);
typedef char* (*GetVersionFunc)();

static LIB_HANDLE dll = NULL;
static SetKeyFunc set_key = NULL;
static SetKeyIdFunc set_key_id = NULL;
static DecryptFunc decrypt = NULL;
static GetVersionFunc get_version = NULL;

static int load_dll() {
    if (dll) return 1;
    
    dll = LOAD_LIB(LIB_NAME);
    if (!dll) {
        SHOW_ERROR("Failed to load crypto library");
        return 0;
    }
    
    set_key = (SetKeyFunc)GET_FUNC(dll, "SetSharedSecretHex");
    set_key_id = (SetKeyIdFunc)GET_FUNC(dll, "SetSharedSecretIdHex");
    decrypt = (DecryptFunc)GET_FUNC(dll, "DecryptDataPacket");
    get_version = (GetVersionFunc)GET_FUNC(dll, "GetVersion");
    
    if (!set_key || !decrypt) {
        SHOW_ERROR("Failed to load functions");
        CLOSE_LIB(dll);
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

static int lua_set_key_id(lua_State* L) {
    if (!load_dll()) {
        lua_pushboolean(L, 0);
        return 1;
    }
    
    if (!set_key_id) {
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
    
    lua_pushboolean(L, set_key_id(conn_id, luaL_checkstring(L, 2)) == 0);
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
    {"set_key_id", lua_set_key_id},
    {"get_version", lua_get_version},
    {"test", lua_test},
    {NULL, NULL}
};

#ifdef __cplusplus
extern "C" {
#endif

EXPORT
int luaopen_qotp_decrypt(lua_State* L) {
    luaL_newlib(L, funcs);
    return 1;
}

#ifdef __cplusplus
}
#endif