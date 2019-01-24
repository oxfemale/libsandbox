#include <windows.h>
#include <wchar.h>
#include <stdlib.h>
#include <stddef.h>

#include "utils_str.h"


#if (__STDC_VERSION__ >= 199901L)
#include <stdint.h>
#endif


unsigned int wstr_size_in_bytes(const wchar_t* instr) {
	return (wcslen(instr) + 1) * 2;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Description :
// wcsstr case-insensitive version (scans "haystack" for "needle").
// Parameters :
// _in_ PWCHAR *haystack : PWCHAR string to be scanned.
// _in_ PWCHAR *needle : PWCHAR string to find.
// Return value :
// PWCHAR : NULL if not found, otherwise "needle" first occurence pointer in "haystack".
// Notes : http://www.codeproject.com/Articles/383185/SSE-accelerated-case-insensitive-substring-search
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PWCHAR wcsistr(PWCHAR wcs1, PWCHAR wcs2)
{
	const wchar_t *s1, *s2;
	const wchar_t l = towlower(*wcs2);
	const wchar_t u = towupper(*wcs2);
	if (!*wcs2)
		return wcs1;
	for (; *wcs1; ++wcs1)
	{
		if (*wcs1 == l || *wcs1 == u)
		{
			s1 = wcs1 + 1;
			s2 = wcs2 + 1;
			while (*s1 && *s2 && towlower(*s1) == towlower(*s2))
				++s1, ++s2;
			if (!*s2)
				return wcs1;
		}
	}
	return NULL;
}

wchar_t *repl_wcs(const wchar_t *str, const wchar_t *from, const wchar_t *to) {

	/* Adjust each of the below values to suit your needs. */

	/* Increment positions cache size initially by this number. */
	size_t cache_sz_inc = 16;
	/* Thereafter, each time capacity needs to be increased,
	 * multiply the increment by this factor. */
	const size_t cache_sz_inc_factor = 3;
	/* But never increment capacity by more than this number. */
	const size_t cache_sz_inc_max = 1048576;

	wchar_t *pret, *ret = NULL;
	const wchar_t *pstr2, *pstr = str;
	size_t i, count = 0;
#if (__STDC_VERSION__ >= 199901L)
	uintptr_t *pos_cache_tmp, *pos_cache = NULL;
#else
	ptrdiff_t *pos_cache_tmp, *pos_cache = NULL;
#endif
	size_t cache_sz = 0;
	size_t cpylen, orglen, retlen, tolen, fromlen = wcslen(from);

	/* Find all matches and cache their positions. */
	while ((pstr2 = wcsistr((PWCHAR)pstr, (PWCHAR)from)) != NULL) {
		count++;

		/* Increase the cache size when necessary. */
		if (cache_sz < count) {
			cache_sz += cache_sz_inc;
			pos_cache_tmp = realloc(pos_cache, sizeof(*pos_cache) * cache_sz);
			if (pos_cache_tmp == NULL) {
				goto end_repl_wcs;
			}
			else pos_cache = pos_cache_tmp;
			cache_sz_inc *= cache_sz_inc_factor;
			if (cache_sz_inc > cache_sz_inc_max) {
				cache_sz_inc = cache_sz_inc_max;
			}
		}

		pos_cache[count - 1] = pstr2 - str;
		pstr = pstr2 + fromlen;
	}

	orglen = pstr - str + wcslen(pstr);

	/* Allocate memory for the post-replacement string. */
	if (count > 0) {
		tolen = wcslen(to);
		retlen = orglen + (tolen - fromlen) * count;
	}
	else	retlen = orglen;
	ret = malloc((retlen + 1) * sizeof(wchar_t));
	if (ret == NULL) {
		goto end_repl_wcs;
	}

	if (count == 0) {
		/* If no matches, then just duplicate the string. */
		wcscpy(ret, str);
	}
	else {
		/* Otherwise, duplicate the string whilst performing
		 * the replacements using the position cache. */
		pret = ret;
		wmemcpy(pret, str, pos_cache[0]);
		pret += pos_cache[0];
		for (i = 0; i < count; i++) {
			wmemcpy(pret, to, tolen);
			pret += tolen;
			pstr = str + pos_cache[i] + fromlen;
			cpylen = (i == count - 1 ? orglen : pos_cache[i + 1]) - pos_cache[i] - fromlen;
			wmemcpy(pret, pstr, cpylen);
			pret += cpylen;
		}
		ret[retlen] = L'\0';
	}

end_repl_wcs:
	/* Free the cache and return the post-replacement string,
	 * which will be NULL in the event of an error. */
	free(pos_cache);
	return ret;
}