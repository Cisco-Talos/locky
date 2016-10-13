/*
*
*  http://stackoverflow.com/questions/27303062/strstr-function-like-that-ignores-upper-or-lower-case
*
*/

#define _CRT_SECURE_NO_WARNINGS
#include "strings.h"

char *stristr(const char *str, const char *strSearch) {
	char *sors, *subs, *res = NULL;
	if ((sors = _strdup(str)) != NULL) {
		if ((subs = _strdup(strSearch)) != NULL) {
			res = strstr(_strlwr(sors), _strlwr(subs));
			if (res != NULL)
				res = (char*)(str + (res - sors));
			free(subs);
		}
		free(sors);
	}
	return res;
}
wchar_t *wcsistr(const wchar_t *str, const wchar_t *strSearch) {
	wchar_t *sors, *subs, *res = NULL;
	if ((sors = _wcsdup(str)) != NULL) {
		if ((subs = _wcsdup(strSearch)) != NULL) {
			res = wcsstr(_wcslwr(sors), _wcslwr(subs));
			if (res != NULL)
				res = (wchar_t *)(str + (res - sors));
			free(subs);
		}
		free(sors);
	}
	return res;
}