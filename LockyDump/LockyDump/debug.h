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

//Breakpoint occurred because there was an INT3 in the code
#define BREAKPOINT_EXCEPTION 0x80000003   

//Single step during debugging
#define DEBUG_EXCEPTION 0x80000004   

#endif // !_LOCKY_DUMP_DEBUG_H