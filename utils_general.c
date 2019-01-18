#include <windows.h>
#include <stdio.h>
#include <userenv.h>

#include "ntdll.h"

#include "utils_general.h"

// Quick and dirty hashing
unsigned int utils_general_adler32(unsigned char *buf, unsigned int len, unsigned int seed) {
    unsigned int s1 = seed & 0xffff;
    unsigned int s2 = (seed >> 16) & 0xffff;
    unsigned int n;

    for (n = 0; n < len; n++) {
        s1 = (s1 + buf[n]) % 65521;
        s2 = (s2 + s1) % 65521;
    }
    return (s2 << 16) + s1;
}

// Debug Print Functions for Windows
void utils_general_DBG_printfW(const wchar_t* format, ...) {
#ifdef ENABLE_DEBUG

	wchar_t s[8192];
	va_list args;
	ZeroMemory(s, 8192 * sizeof(s[0]));
	va_start(args, format);
	wvsprintfW(s, format, args);
	va_end(args);
	s[8191] = 0;
	OutputDebugStringW(s);
#endif
}

void utils_general_DBG_printfA (const char* format, ...){
#ifdef ENABLE_DEBUG
    char s[8192];
    va_list args;
    ZeroMemory(s, 8192 * sizeof(s[0]));
    va_start(args, format);
    vsnprintf(s, 8191, format, args);
    va_end(args);
    s[8191] = 0;
    OutputDebugStringA(s);
#endif
}

BOOL utils_general_hook_ntdll_function(const char* src_function_name, void* dest_function_address, void** ptrampoline_address){
    // Initial guard - we need these ntdll functions bound and working before we attempt anything else.
    if (!ntdll_NtAllocateVirtualMemory || !ntdll_NtProtectVirtualMemory) {
        DEBUG_PRINT("[Hook Inline] Error: ntdll dynamic functions are not bound.");
        return FALSE;
    }

    // Resolve the function address we're targeting.
    FARPROC target_function_address = GetProcAddress(GetModuleHandleA("ntdll.dll"), src_function_name);
    if (!target_function_address) { return FALSE; }

#ifdef ENVIRONMENT32

    unsigned char Opcode[5] = {
            0xE9, // JMP
            0x00, 0x00, 0x00, 0x00 // address, use 4 bytes for x86 process
    };
    size_t stolen_bytes_size = 15;
    // Write our trampoline logic.
    *(ULONG*)(Opcode + 1) = ((ULONG)dest_function_address - ((ULONG)target_function_address + sizeof(Opcode)));
#else

    unsigned char Opcode[16] = {
		0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0xE0,0x90,0x90,0x90,0x90
	};
	SIZE_T stolen_bytes_size = 21;
	// Write our trampoline logic.
	*(ULONGLONG*)(Opcode + 2) = (ULONGLONG)dest_function_address;
#endif

    // Universal Initializers
    size_t   hook_size = sizeof(Opcode);
    DWORD old_access_protection = 0;
    PVOID pvFunctionAddress = (PVOID)target_function_address; // used for virtual memory operations
    PVOID pvTrampolineMemory = NULL;

    // Change the page protection to write to our target location.
    if (ntdll_NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pvFunctionAddress, (PSIZE_T)&hook_size, PAGE_EXECUTE_READWRITE, (PULONG)&old_access_protection)) { return FALSE; }

    // We need space for our trampoline, ask the process nicely for some memory to do that :3
    if (ntdll_NtAllocateVirtualMemory(GetCurrentProcess(), &pvTrampolineMemory, 0, (PSIZE_T)&stolen_bytes_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
        ntdll_NtProtectVirtualMemory(GetCurrentProcess(), (PVOID*)&pvFunctionAddress, (PSIZE_T)&hook_size, old_access_protection, (PULONG)&old_access_protection);
        return FALSE;
    };

    // Copy the stolen bytes from target address to our trampoline.
    RtlCopyMemory(pvTrampolineMemory, (void*)target_function_address, stolen_bytes_size);

    // assign our trampoline address to the address of the memory we allocated and inserted the bytes into
    *ptrampoline_address = pvTrampolineMemory;

    // Insert our own bytes at the start of the target function prologue (in memory).
    RtlCopyMemory((void*)target_function_address, Opcode, sizeof(Opcode));

    // Re-protect the memory of the function we hooked and the trampoline function.
    ntdll_NtProtectVirtualMemory(GetCurrentProcess(), &pvFunctionAddress, (PSIZE_T)&hook_size, old_access_protection, (PULONG)&old_access_protection);
    ntdll_NtProtectVirtualMemory(GetCurrentProcess(), &pvTrampolineMemory, (PSIZE_T)&hook_size, PAGE_EXECUTE, (PULONG)&old_access_protection);

    return TRUE;
}

BOOL utils_general_GetEnvar(const wchar_t* key, wchar_t** value) {

if(!value){return FALSE;}

DWORD bufferSize = GetEnvironmentVariableW(key, NULL, 0);
if (!bufferSize) { return FALSE; }
size_t wval_sz = (bufferSize+1)*2;
*value = malloc(wval_sz);
GetEnvironmentVariableW(key, *value, wval_sz);
return TRUE;
}

// Retrieves the profile root (HOME directory) of the calling user.
BOOL utils_general_get_profile_path(wchar_t** output_path) {
    DEBUG_PRINT("WAT1");
HANDLE hnd = GetCurrentProcess();
    DEBUG_PRINT("WAT2");
HANDLE token = INVALID_HANDLE_VALUE;



// Fail if we can't get the process token.
if (!OpenProcessToken(hnd, TOKEN_QUERY, &token)) {
    DEBUG_PRINT("FAILED TO OPEN PROCESS TOKEN");
    return FALSE;
}
DWORD tmp_sz = UNC_MAX_PATH*2;
    void* tmp_path = calloc(1,tmp_sz);
    memset(tmp_path,0x00,sizeof(tmp_path));
if(!GetUserProfileDirectoryW(token,tmp_path, &tmp_sz)){
    DEBUG_PRINT("GetUserProfileDirectoryW FAILED");
    free(tmp_path);
    return FALSE;
}
CloseHandle(token);
utils_general_DBG_printfW(L"Profile Path: %s",tmp_path);
wchar_t* profile_path_start = wcsstr(tmp_path,L"\\Users");
if(!profile_path_start){free(tmp_path);return FALSE;}

unsigned int profile_size_bytes = (wcslen(profile_path_start))*2; // Avoiding the trailing slash.

*output_path = malloc(profile_size_bytes+2);
memcpy(*output_path,profile_path_start,profile_size_bytes);
free(tmp_path);
utils_general_DBG_printfW(L"Profile Path2: %s",*output_path);
return TRUE;
}