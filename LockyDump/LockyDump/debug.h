/*
*  Copyright (C) 2016 Cisco Talos Security Intelligence and Research Group
*
*  Authors: Matthew Molyett
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License version 2 as
*  published by the Free Software Foundation.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
*  MA 02110-1301, USA.
*
*	Filename: debug.h
*	Last revision: 10/12/2016
*/
#ifndef _LOCKY_DUMP_DEBUG_H
#define _LOCKY_DUMP_DEBUG_H

#pragma warning(disable : 4091)

#include <Dbghelp.h>
void ParseIAT(HINSTANCE h);
typedef BOOL(WINAPI *DllMainFunc)(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved);

typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0
} PROCESSINFOCLASS;
typedef ULONG(NTAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef struct _PROCESS_BASIC_INFORMATION {
	PVOID Reserved1;
	PVOID PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

BOOL SetPrivilege(
	HANDLE hProcess,          // access token handle
	LPCSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
);
//Breakpoint occurred because there was an INT3 in the code
#define BREAKPOINT_EXCEPTION 0x80000003   

//Single step during debugging
#define DEBUG_EXCEPTION 0x80000004   
//#define STATUS_INVALID_HANDLE            ((NTSTATUS)0xC0000008L)    // winnt

#endif // !_LOCKY_DUMP_DEBUG_H