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
*	Filename: LockyDump.h
*	Last revision: 10/12/2016
*/
#pragma once
#ifndef _LOCKY_DUMP_H
#define _LOCKY_DUMP_H
#include <stdio.h>
#include <Windows.h>

#pragma pack(1)
typedef struct _LockyConfigHeader {
	DWORD affilID;
	DWORD DGASeed;
	DWORD Delay;
	BYTE PersistSvchost;
	BYTE PersistRegistry;
	BYTE IgnoreRussian;
} LOCKY_CONFIG_HEADER;

typedef struct _LockyConfigClassic {
	LOCKY_CONFIG_HEADER Header;
	CHAR C2Servers[128];
} LOCKY_CONFIG_CLASSIC;

typedef struct _LockyConfig {
	LOCKY_CONFIG_HEADER Header;
	CHAR CallbackPath[48];
	CHAR C2Servers[4096];
	DWORD RsaKeyID;
	DWORD RsaKeySizeBytes;
	PUBLICKEYSTRUC RsaKeyStruct;
	RSAPUBKEY RsaKeyHdr;
	BYTE RsaKeyData[1080];
	CHAR RansomNote[0x1000];
	CHAR HtmlRansom[0x3000];
} LOCKY_CONFIG;

#define RVA(base, offset) (PVOID)((ULONG_PTR)(base) + (ULONG_PTR)(offset))
#define MAX(a,b) ( ((a) > (b))?(a):(b) )
#define VALID_HANDLE(handle) (((ULONG_PTR)(handle) != (ULONG_PTR)0 && (ULONG_PTR)(handle) != (ULONG_PTR)-1))

BOOLEAN dump_config_values(LOCKY_CONFIG_HEADER* ConfigStart, BOOLEAN bVerbose);
DWORD run_exe(LPSTR exe_path, BOOLEAN bVerbose);
int main(int argc, char** argv);
#endif // !_LOCKY_DUMP_H