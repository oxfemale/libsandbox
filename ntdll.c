#include <windows.h>
#include <winternl.h>
#include "utils_general.h"

#include "ntdll.h"


pNtCreateFile ntdll_NtCreateFile = NULL;
pNtOpenFile ntdll_NtOpenFile = NULL;
pNtQueryAttributesFile ntdll_NtQueryAttributesFile = NULL;
pNtQueryDirectoryFileEx ntdll_NtQueryDirectoryFileEx = NULL;
pNtQueryFullAttributesFile ntdll_NtQueryFullAttributesFile = NULL;
pNtOpenDirectoryObject ntdll_NtOpenDirectoryObject = NULL;
pNtCreateUserProcess ntdll_NtCreateUserProcess = NULL;
pNtOpenSymbolicLinkObject ntdll_NtOpenSymbolicLinkObject = NULL;
pNtQueryDirectoryFile ntdll_NtQueryDirectoryFile = NULL;
pRtlFreeUnicodeString ntdll_RtlFreeUnicodeString = NULL;
pRtlInitUnicodeString ntdll_RtlInitUnicodeString = NULL;
pNtQueryInformationFile ntdll_NtQueryInformationFile = NULL;
pRtlDosPathNameToNtPathName_U ntdll_RtlDosPathNameToNtPathName_U = NULL;
pNtAllocateVirtualMemory ntdll_NtAllocateVirtualMemory = NULL;
pNtProtectVirtualMemory ntdll_NtProtectVirtualMemory = NULL;
pNtWriteVirtualMemory ntdll_NtWriteVirtualMemory = NULL;
pRtlCopyUnicodeString ntdll_RtlCopyUnicodeString = NULL;
pRtlGetCurrentDirectory_U ntdll_RtlGetCurrentDirectory_U = NULL;
pRtlSetCurrentDirectory_U ntdll_RtlSetCurrentDirectory_U = NULL;

struct dyn_ntdll_entry {
    const char*  ntdll_function_name;
    void**       function_ptr;
};


static struct dyn_ntdll_entry ntdll_entries[] = {
        {"NtAllocateVirtualMemory",      (void**)&ntdll_NtAllocateVirtualMemory},
        {"NtCreateFile",                 (void**)&ntdll_NtCreateFile},
        {"NtCreateUserProcess",          (void**)&ntdll_NtCreateUserProcess},
        {"NtOpenFile",                   (void**)&ntdll_NtOpenFile},
        {"NtOpenDirectoryObject",        (void**)&ntdll_NtOpenDirectoryObject},
        {"NtOpenSymbolicLinkObject",     (void**)&ntdll_NtOpenSymbolicLinkObject},
        {"NtProtectVirtualMemory",       (void**)&ntdll_NtProtectVirtualMemory},
        {"NtQueryAttributesFile",        (void**)&ntdll_NtQueryAttributesFile},
        {"NtQueryDirectoryFile",         (void**)&ntdll_NtQueryDirectoryFile},
        {"NtQueryDirectoryFileEx",       (void**)&ntdll_NtQueryDirectoryFileEx},
        {"NtQueryFullAttributesFile",    (void**)&ntdll_NtQueryFullAttributesFile},
        {"NtQueryInformationFile",       (void**)&ntdll_NtQueryInformationFile},
        {"NtWriteVirtualMemory",         (void**)&ntdll_NtWriteVirtualMemory},
        {"RtlCopyUnicodeString",         (void**)&ntdll_RtlCopyUnicodeString},
        {"RtlDosPathNameToNtPathName_U", (void**)&ntdll_RtlDosPathNameToNtPathName_U},
        {"RtlFreeUnicodeString",         (void**)&ntdll_RtlFreeUnicodeString},
        {"RtlInitUnicodeString",         (void**)&ntdll_RtlInitUnicodeString},
        {"RtlSetCurrentDirectory_U",     (void**)&ntdll_RtlSetCurrentDirectory_U},
        {"RtlGetCurrentDirectory_U",     (void**)&ntdll_RtlGetCurrentDirectory_U},
};

// Entry-Point: Run this before using any of these.
BOOL DynLoad(const char* library_name, const char* function_name, void** function_ptr) {
    *function_ptr = (void*)GetProcAddress(LoadLibraryA(library_name), function_name);
    if (!*function_ptr) {
        OutputDebugStringA("[DynLoad] Failed to Load Function");
        return FALSE;
    }
    return TRUE;
}




BOOL init_ntdll() {
    unsigned int num_entries = sizeof(ntdll_entries) / sizeof(struct dyn_ntdll_entry);
    for (unsigned int i = 0; i < num_entries; i++) {
        if (!DynLoad("ntdll.dll", ntdll_entries[i].ntdll_function_name, ntdll_entries[i].function_ptr)) { return FALSE; }
        utils_general_DBG_printfA("[ntdll] %s Address: %p", ntdll_entries[i].ntdll_function_name, ntdll_entries[i].function_ptr);
    }
    return TRUE;
}