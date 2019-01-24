#pragma once

#include <windows.h>

//#define ENABLE_DEBUG
//#define DEBUG_CONSOLE

// Check windows
#if _WIN32 || _WIN64
#if _WIN64
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

// Check GCC
#if __GNUC__
#if __x86_64__ || __ppc64__
#define ENVIRONMENT64
#else
#define ENVIRONMENT32
#endif
#endif

#ifdef ENABLE_DEBUG
#define DEBUG_PRINT(a) OutputDebugStringA(a)
#else
#define DEBUG_PRINT(a) OutputDebugStringA("")
#endif
#define UNC_MAX_PATH 32768
#define W_UNC_MAX_PATH_BYTES UNC_MAX_PATH+1 * sizeof(wchar_t)
#define ENVAR_DLL_PATH_32 L"LIB_32"
#define ENVAR_DLL_PATH_64 L"LIB_64"

void utils_general_DBG_printfW(const wchar_t* format, ...);
void utils_general_DBG_printfA(const char* format, ...);

BOOL utils_general_hook_ntdll_function(const char* src_function_name, void* dest_function_address, void** ptrampoline_address);

unsigned int utils_general_adler32(unsigned char *buf, unsigned int len, unsigned int seed);
BOOL utils_general_GetEnvar(const wchar_t* key, wchar_t** value);
BOOL utils_general_get_profile_path(wchar_t** output_path);
BOOL utils_inject_self_method_remotethread(HANDLE hProcess, HANDLE hThread, BOOL dont_resume);