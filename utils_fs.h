#pragma once
#include <windows.h>

BOOL utils_fs_resolve_path(void* root_handle, const wchar_t* stem_name, unsigned int stem_length_bytes, wchar_t** output_path);
BOOL utils_fs_generate_sandbox_path(const wchar_t* input_path, wchar_t** sandbox_path);
BOOL path_exists(const wchar_t* input_path, BOOL *is_directory);
BOOL use_sandbox_path(const wchar_t* input_path, const wchar_t* sandbox_path, DWORD DesiredAccess, DWORD FileOptions, DWORD FileDisposition);


BOOL init_fsutils();