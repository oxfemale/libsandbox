#pragma once
#include <windows.h>

unsigned int wstr_size_in_bytes(const wchar_t* instr);
wchar_t *repl_wcs(const wchar_t *str, const wchar_t *from, const wchar_t *to);