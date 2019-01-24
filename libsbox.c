#include <windows.h>
#include "ntdll.h"
#include "hooks.h"
#include "utils_fs.h"


BOOL init_library() {
	if (!init_fsutils()) { return FALSE; }
	if (!init_ntdll()) { return FALSE; }
	if (!install_hooks()) { return FALSE; }

	return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		return init_library();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	default:
		break;
	}
	return TRUE;
}