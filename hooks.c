#include <windows.h>

#include "utils_general.h"
#include "ntdll.h"
#include "hfs.h"
#include "hproc.h"

#include "hooks.h"

struct nthook_entry {
	const char* ntdll_function_name;
	void*       replacement_function_address;
	void**      trampoline_address;
};

static struct nthook_entry ntdll_hooks[] = {
		{"NtCreateFile"              ,(void*)hfs_NtCreateFile,               (void**)&ntdll_NtCreateFile},
		{"NtOpenFile"                ,(void*)hfs_NtOpenFile,                 (void**)&ntdll_NtOpenFile},
		{"NtOpenDirectoryObject"     ,(void*)hfs_NtOpenDirectoryObject,      (void**)&ntdll_NtOpenDirectoryObject},
		{"NtQueryAttributesFile"     ,(void*)hfs_NtQueryAttributesFile,      (void**)&ntdll_NtQueryAttributesFile },
		{"NtQueryDirectoryFile"      ,(void*)hfs_NtQueryDirectoryFile,       (void**)&ntdll_NtQueryDirectoryFile  },
		{"NtQueryDirectoryFileEx"    ,(void*)hfs_NtQueryDirectoryFileEx,     (void**)&ntdll_NtQueryDirectoryFileEx},
		{"NtQueryFullAttributesFile" ,(void*)hfs_NtQueryFullAttributesFile,  (void**)&ntdll_NtQueryFullAttributesFile},
		{"NtOpenSymbolicLinkObject"  ,(void*)hfs_NtOpenSymbolicLinkObject,   (void**)&ntdll_NtOpenSymbolicLinkObject},
		//{"RtlSetCurrentDirectory_U"  ,(void*)hfs_RtlSetCurrentDirectory_U,   (void**)&ntdll_RtlSetCurrentDirectory_U},
		//{"RtlGetCurrentDirectory_U"  ,(void*)hfs_RtlGetCurrentDirectory_U,   (void**)&ntdll_RtlGetCurrentDirectory_U},
		{"NtCreateUserProcess"       ,(void*)hproc_NtCreateUserProcess,         (void**)&ntdll_NtCreateUserProcess},
};


BOOL install_hooks() {
	int num_hooks = sizeof(ntdll_hooks) / sizeof(struct nthook_entry);
	utils_general_DBG_printfA("[ntdll::hooks] - Installing %d Hooks\n", num_hooks);
	for (int i = 0; i < num_hooks; i++) {
		if (!utils_general_hook_ntdll_function(ntdll_hooks[i].ntdll_function_name, ntdll_hooks[i].replacement_function_address, ntdll_hooks[i].trampoline_address)) {

			utils_general_DBG_printfA("Failed to hook %s", ntdll_hooks[i].ntdll_function_name);
			return FALSE;
		}
	}
	return TRUE;
}
