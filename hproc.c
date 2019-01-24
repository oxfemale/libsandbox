#include <windows.h>
#include "ntdll.h"
#include "utils_general.h"

#include "hproc.h"

// Ntdll Process Intercept Hooks
NTSTATUS NTAPI hproc_NtCreateUserProcess(PHANDLE ProcessHandle, PHANDLE ThreadHandle, ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess, POBJECT_ATTRIBUTES ProcessObjectAttributes, POBJECT_ATTRIBUTES ThreadObjectAttributes, ULONG ulProcessFlags, ULONG ulThreadFlags, PRTL_USER_PROCESS_PARAMETERS RtlUserProcessParameters, void* PsCreateInfo, void* PsAttributeList) {
	DEBUG_PRINT("NtCreateUserPROCESS FORK!!!");
	// Something like, start suspended, get pid, inject library, resume process.
	BOOL dont_resume = FALSE;
	if (ulProcessFlags & CREATE_SUSPENDED) {
		dont_resume = TRUE;
	}
	else {
		ulProcessFlags |= CREATE_SUSPENDED;
	}
	NTSTATUS result = ntdll_NtCreateUserProcess(ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes, ulProcessFlags, ulThreadFlags, RtlUserProcessParameters, PsCreateInfo, PsAttributeList);
	if (!utils_inject_self_method_remotethread(*ProcessHandle, *ThreadHandle, dont_resume)) {
		DEBUG_PRINT("Inject Child Process Fail :(");
	}
	return result;
}