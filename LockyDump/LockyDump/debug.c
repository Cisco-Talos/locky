/*
*
*  Authors: Michael Chourdakis
*  http://www.codeproject.com/Articles/1045674/Load-EXE-as-DLL-Mission-Possible
*  This code is licenced under CPOL: http://www.codeproject.com/info/cpol10.aspx
*
*	Filename: debug.c
*	Last revision: 10/12/2016
*/

#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include "debug.h"
#include <stdio.h>
#pragma comment(lib,"Dbghelp.lib")
typedef BOOL (WINAPI *LookupPrivilegeValue_t)(LPCSTR, LPCSTR, PLUID);
typedef BOOL (WINAPI *AdjustTokenPrivileges_t)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES,PDWORD);
typedef BOOL (WINAPI *OpenProcessToken_t)(HANDLE, DWORD, PHANDLE);

BOOL SetPrivilege(
	HANDLE hProcess,          // Process handle
	LPCSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	HANDLE hToken = 0;
	HMODULE Advapi32 = LoadLibraryA("Advapi32.dll");
	OpenProcessToken_t pOpenProcessToken = (OpenProcessToken_t)GetProcAddress(Advapi32, "OpenProcessToken");
	LookupPrivilegeValue_t pLookupPrivilegeValue = (LookupPrivilegeValue_t) GetProcAddress(Advapi32, "LookupPrivilegeValueA");
	AdjustTokenPrivileges_t pAdjustTokenPrivileges = (AdjustTokenPrivileges_t) GetProcAddress(Advapi32, "AdjustTokenPrivileges");
	
	if (!(pLookupPrivilegeValue && pAdjustTokenPrivileges && pOpenProcessToken))
	{
		return FALSE;
	}

	if (!pOpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken))
	{
		return FALSE;
	}

	if (!pLookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!pAdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}

	return TRUE;
}

void ParseIAT(HINSTANCE h)
{
	// Find the IAT size
	DWORD ulsize = 0;
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(h, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulsize);
	if (!pImportDesc)
		return;

	// Loop names
	for (; pImportDesc->Name; pImportDesc++)
	{
		PSTR pszModName = (PSTR)((PBYTE)h + pImportDesc->Name);
		if (!pszModName)
			break;

		HINSTANCE hImportDLL = LoadLibraryA(pszModName);
		if (!hImportDLL)
		{
			// ... (error)
		}

		// Get caller's import address table (IAT) for the callee's functions
		PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)
			((PBYTE)h + pImportDesc->FirstThunk);

		// Replace current function address with new function address
		for (; pThunk->u1.Function; pThunk++)
		{
			FARPROC pfnNew = 0;
			size_t rva = 0;
#ifdef _WIN64
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
#else
			if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
#endif
			{
				// Ordinal
#ifdef _WIN64
				size_t ord = IMAGE_ORDINAL64(pThunk->u1.Ordinal);
#else
				size_t ord = IMAGE_ORDINAL32(pThunk->u1.Ordinal);
#endif

				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn)
				{
					// ... (error)
				}
				rva = (size_t)pThunk;

				char fe[100] = { 0 };
				sprintf(fe, "#%u", ord);
				pfnNew = GetProcAddress(hImportDLL, (LPCSTR)ord);
				if (!pfnNew)
				{
					// ... (error)
				}
			}
			else
			{
				// Get the address of the function address
				PROC* ppfn = (PROC*)&pThunk->u1.Function;
				if (!ppfn)
				{
					// ... (error)
				}
				rva = (size_t)pThunk;
				PSTR fName = (PSTR)h;
				fName += pThunk->u1.Function;
				fName += 2;
				if (!fName)
					break;
				pfnNew = GetProcAddress(hImportDLL, fName);
				if (!pfnNew)
				{
					// ... (error)
				}
			}

			// Patch it now...
			HANDLE hp = GetCurrentProcess();
			if (!WriteProcessMemory(hp, (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL) && (ERROR_NOACCESS == GetLastError()))
			{
				DWORD dwOldProtect;
				if (VirtualProtect((LPVOID)rva, sizeof(pfnNew), PAGE_WRITECOPY, &dwOldProtect))
				{
					if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID*)rva, &pfnNew, sizeof(pfnNew), NULL))
					{
						// ... (error)
					}
					if (!VirtualProtect((LPVOID)rva, sizeof(pfnNew), dwOldProtect, &dwOldProtect))
					{
						// ... (error)
					}
				}
			}
		}
	}
}
