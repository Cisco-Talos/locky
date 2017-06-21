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
*	Filename: Locky_Dump_main.c
*	Last revision: 10/12/2016
*/
#include "LockyDump.h"
#include "debug.h"
#include "strings.h"

#define WRITE_FILE_CALLED 0x2
#define MOVE_FILE_CALLED 0x4
#define VSSAPI_LOADED 0x10
#define DNSAPI_LOADED 0x11
#define SENSAPI_LOADED 0x12
#define CSCAPI_LOADED 0x13
#define PROC_ENDED 0x20

#define ACTION_DEBUGGING 0x1
#define ACTION_DROP 0x2
#define ACTION_VERBOSE 0x4

#define DUMP_FILE_NAME "DUMPED_IMAGE.DLL"

#define HIDE_DEBUGGER if (VALID_HANDLE(NtQueryInformationProcess))\
			{\
			ntstatus = NtQueryInformationProcess(DebugProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &pbi_len);\
			if (ERROR_SUCCESS == ntstatus)\
			{\
				BYTE PebStub[3] = { 0 };\
				if (ReadProcessMemory(DebugProcess, pbi.PebBaseAddress, PebStub, sizeof(PebStub), &ByteCount))\
				{\
					PebStub[2] = 0;\
					WriteProcessMemory(DebugProcess, pbi.PebBaseAddress, PebStub, sizeof(PebStub), &ByteCount);\
				}\
			}\
			}

void dump_mapped_binary(HANDLE hTarProcess, PVOID ModuleBase, BOOLEAN bVerbose)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;
	BYTE Page[0x400] = { 0 };
	BYTE HeaderPage[0x400] = { 0 };
	PVOID ReadPointer;
	DWORD read, i, BytesWritten, BytesRead = 0;

	HANDLE OutFile = CreateFileA(DUMP_FILE_NAME, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (OutFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create " DUMP_FILE_NAME " \n");
		return;
	}

	ReadPointer = ModuleBase;
	if (!ReadProcessMemory(hTarProcess, ReadPointer, HeaderPage, sizeof(HeaderPage), &BytesRead))
	{
		printf("Failed to read at %p + 0x%X \n", ModuleBase, (ULONG_PTR)ReadPointer - (ULONG_PTR)ModuleBase);
		return;
	}
	DosHeader = RVA(HeaderPage, 0);
	NtHeader = RVA(HeaderPage, DosHeader->e_lfanew);

	// We don't have relocations so...
	NtHeader->OptionalHeader.ImageBase = (DWORD)ModuleBase;

	if (!WriteFile(OutFile, HeaderPage, sizeof(HeaderPage), &BytesWritten, NULL))
	{
		printf("Failed to write memory from %p + 0x%X \n", ModuleBase, (ULONG_PTR)ReadPointer - (ULONG_PTR)ModuleBase);
	}

	pSectionHeader = IMAGE_FIRST_SECTION(NtHeader);
	for (i = 0; i < NtHeader->FileHeader.NumberOfSections; ++i)
	{
		if (pSectionHeader[i].SizeOfRawData)
		{
			DWORD jump = SetFilePointer(OutFile, pSectionHeader[i].PointerToRawData, NULL, SEEK_SET);
			if (bVerbose & ACTION_DEBUGGING) printf("Jumped File Pointer to %X\n", jump);
			for (read = 0; read < pSectionHeader[i].SizeOfRawData; read += sizeof(Page))
			{
				ReadPointer = RVA(ModuleBase, pSectionHeader[i].VirtualAddress + read);
				if (!ReadProcessMemory(hTarProcess, ReadPointer, Page, sizeof(Page), &BytesRead))
				{
					printf("Failed to read at %p + 0x%X \n", ModuleBase, (ULONG_PTR)ReadPointer - (ULONG_PTR)ModuleBase);
					return;
				}
				if (bVerbose & ACTION_DEBUGGING) printf("Read %d bytes of memory from %p + 0x%X \n", BytesRead, ModuleBase, (ULONG_PTR)ReadPointer - (ULONG_PTR)ModuleBase);
				if (!WriteFile(OutFile, Page, sizeof(Page), &BytesWritten, NULL))
				{
					printf("Failed to write memory from %p + 0x%X \n", ModuleBase, (ULONG_PTR)ReadPointer - (ULONG_PTR)ModuleBase);
				}
			}
		}
	}
	CloseHandle(OutFile);
}

PVOID search_module_for_config(HANDLE hTarProcess, PVOID ModuleAddr, BOOLEAN bVerbose)
{
	HANDLE LockyProcess = hTarProcess;
	CHAR Page[0x1000] = { 0 };
	SHORT ModuleSearch = 0;
	DWORD SavedBytes = 0, ByteCount = 0;
	if (ReadProcessMemory(LockyProcess, ModuleAddr, &ModuleSearch, sizeof(ModuleSearch), &ByteCount))
	{
		if (ModuleSearch == IMAGE_DOS_SIGNATURE && ReadProcessMemory(LockyProcess, ModuleAddr, &Page, sizeof(Page), &ByteCount))
		{
			HMODULE ModuleBase = (HMODULE)&Page;
			PIMAGE_DOS_HEADER DosHeader;
			PIMAGE_NT_HEADERS NtHeader;
			PIMAGE_SECTION_HEADER ImageHeader;
			DWORD i, index;
			LOCKY_CONFIG ConfigSpace;

			DosHeader = RVA(ModuleBase, 0);
			NtHeader = RVA(ModuleBase, DosHeader->e_lfanew);

			if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
				// Not a valid PE module
				ModuleAddr = RVA(ModuleAddr, 0x1000);
				return ModuleAddr;
			}
			if (bVerbose & ACTION_DEBUGGING) printf("PE header at %p\n", (PVOID)ModuleAddr);

			ImageHeader = IMAGE_FIRST_SECTION(NtHeader);
			for (index = 0; index < NtHeader->FileHeader.NumberOfSections; index++)
			{
				// .rdata is used by 
				if (strcmp(ImageHeader->Name, ".rdata") == 0)
				{
					for (i = ImageHeader->VirtualAddress; i < ImageHeader->VirtualAddress + MAX(ImageHeader->SizeOfRawData, ImageHeader->Misc.VirtualSize); i += 4)
					{
						DWORD Offset = i;
						//DWORD Offset = ConfigOffsets[i];
						PVOID ConfigCandidate;
						//if (bVerbose & ACTION_DEBUGGING) printf("Reading data at (offset %p) %p\n", (PVOID)Offset, RVA(ModuleAddr, Offset));
						if (!ReadProcessMemory(LockyProcess, RVA(ModuleAddr, Offset), &ConfigCandidate, sizeof(ConfigCandidate), &ByteCount))
						{
							if (bVerbose & ACTION_DEBUGGING) printf("Unabled to read offset %p : %d\n", (PVOID)Offset, GetLastError());
							continue;
						}
						if (!ConfigCandidate) { continue; }
						//if (bVerbose & ACTION_DEBUGGING) printf("Candidate offset %p contains %p\n", (PVOID)Offset, ConfigCandidate);
						fflush(stdout);

						if ((ConfigCandidate) && ((ULONG_PTR)ConfigCandidate) <= 0x15)
						{
							//if (bVerbose & ACTION_DEBUGGING) printf("Possible raw locky configuration\n");
							//if (bVerbose & ACTION_DEBUGGING) printf("Reading %d from %p\n", sizeof(LOCKY_CONFIG_CLASSIC), RVA(ModuleAddr, Offset));
							if (ReadProcessMemory(LockyProcess, RVA(ModuleAddr, Offset), &ConfigSpace, sizeof(LOCKY_CONFIG_CLASSIC), &ByteCount))
							{
								LOCKY_CONFIG_CLASSIC* pConfigClassic = (LOCKY_CONFIG_CLASSIC*)&ConfigSpace;
								if (bVerbose & ACTION_DEBUGGING) printf("%d bytes read\n", ByteCount);
								if (1 || pConfigClassic->C2Servers[0])
								{
									if (dump_config_values(&pConfigClassic->Header, bVerbose))
									{
										if (bVerbose & ACTION_DROP)
										{
											dump_mapped_binary(LockyProcess, ModuleAddr, bVerbose);
										}
										return 0;
									}
								}
								continue;
							}
						}
					}
				}
				if (strcmp(ImageHeader->Name, ".data") == 0)
				{
					for (i = ImageHeader->VirtualAddress; i < ImageHeader->VirtualAddress + MAX(ImageHeader->SizeOfRawData, ImageHeader->Misc.VirtualSize); i += 4)
					{
						DWORD Offset = i;
						//DWORD Offset = ConfigOffsets[i];
						PVOID ConfigCandidate;
						//if (bVerbose & ACTION_DEBUGGING) printf("Reading data at (offset %p) %p\n", (PVOID)Offset, RVA(ModuleAddr, Offset));
						if (!ReadProcessMemory(LockyProcess, RVA(ModuleAddr, Offset), &ConfigCandidate, sizeof(ConfigCandidate), &ByteCount))
						{
							if (bVerbose & ACTION_DEBUGGING) printf("Unabled to read offset %p : %d\n", (PVOID)Offset, GetLastError());
							continue;
						}
						if (!ConfigCandidate) { continue; }
						//if (bVerbose & ACTION_DEBUGGING) printf("Candidate offset %p contains %p\n", (PVOID)Offset, ConfigCandidate);
						fflush(stdout);

						if ((0xFFF & (ULONG_PTR)ConfigCandidate) || !(ConfigCandidate))
						{
							// This is only a possible config if it points to the start of a page!
							continue;
						}
						if (((ULONG_PTR)ConfigCandidate > (ULONG_PTR)ModuleAddr) &&
							((ULONG_PTR)ConfigCandidate < (ULONG_PTR)RVA(ModuleAddr, NtHeader->OptionalHeader.SizeOfImage)))
						{
							// This pointer will not point into the module itself
							if (bVerbose & ACTION_DEBUGGING) printf("%p is inside of image range %p - %p\n", ConfigCandidate,
								(PVOID)ModuleAddr,
								(PVOID)RVA(ModuleAddr, NtHeader->OptionalHeader.SizeOfImage)
							);
							continue;
						}

						if (bVerbose & ACTION_DEBUGGING) printf("Reading %d from %p (Offset %p)\n", sizeof(ConfigSpace), ConfigCandidate, (PVOID)Offset);
						if (ReadProcessMemory(LockyProcess, ConfigCandidate, &ConfigSpace, sizeof(ConfigSpace), &ByteCount))
						{
							if (bVerbose & ACTION_DEBUGGING) printf("%d bytes read\n", ByteCount);
							if (ConfigSpace.CallbackPath[0] || ConfigSpace.HtmlRansom[0])
							{
								if (dump_config_values(&ConfigSpace.Header, bVerbose))
								{
									if (bVerbose & ACTION_DROP)
									{
										dump_mapped_binary(LockyProcess, ModuleAddr, bVerbose);
									}
									return 0;
								}
							}
							continue;
						}
						if (GetLastError() == ERROR_PARTIAL_COPY)
						{
							if (ReadProcessMemory(LockyProcess, ConfigCandidate, &ConfigSpace, 0x1000, &ByteCount))
							{
								if (bVerbose & ACTION_DEBUGGING) printf("%d bytes read\n", ByteCount);
								if (ConfigSpace.CallbackPath[0] || ConfigSpace.HtmlRansom[0])
								{
									if (dump_config_values(&ConfigSpace.Header, bVerbose))
									{
										if (bVerbose & ACTION_DROP)
										{
											dump_mapped_binary(LockyProcess, ModuleAddr, bVerbose);
										}
										return 0;
									}
								}
								continue;
							}
						}
					}
				}
				ImageHeader++;
			}
			ModuleAddr = RVA(ModuleAddr, NtHeader->OptionalHeader.SizeOfImage);
			ModuleAddr = (PVOID)((ULONG_PTR)ModuleAddr & 0xFFFFF000);
			return ModuleAddr;
		}
	}
	ModuleAddr = RVA(ModuleAddr, 0x1000);
	return ModuleAddr;
}

DWORD run_exe(LPSTR exe_path, BOOLEAN bVerbose)
{
	STARTUPINFOA StartupInfo = { 0 };
	PROCESS_INFORMATION ProcessInfo = { 0 };
	PROCESS_BASIC_INFORMATION pbi = { 0 };
	HMODULE k32 = LoadLibraryA("kernel32.dll");
	FARPROC pSleep = GetProcAddress(k32, "Sleep");
	FARPROC pWriteFile = GetProcAddress(k32, "WriteFile");
	FARPROC pMoveFile = GetProcAddress(k32, "MoveFileExW");
	DWORD flags = DETACHED_PROCESS | DEBUG_PROCESS;
	DWORD SavedBytes = 0, ByteCount = 0;
	CHAR Break = 0xCC;
	BOOLEAN LockyActive = 0;
	DWORD DebugCount = 0;
	DWORD pbi_len = 0;
	NTSTATUS ntstatus;
	DWORD LockyProcessID = 0;
	HANDLE LockyProcess = 0;
	HANDLE DebugProcess = 0;
	LPSTR CommandLine = GetCommandLineA();
	HMODULE ntd = LoadLibraryA("Ntdll.dll");
	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntd, "NtQueryInformationProcess");
	DEBUG_EVENT DebugEvent;
	DWORD dwContinueStatus = DBG_CONTINUE; // exception continuation 

	StartupInfo.cb = sizeof(StartupInfo);

	if (!pWriteFile || !pMoveFile || !pSleep)
	{
		return GetLastError();
	}
	if (bVerbose & ACTION_DEBUGGING) printf("Running %s\n", CommandLine);
	CommandLine = strstr(CommandLine, exe_path);
	if (bVerbose & ACTION_DEBUGGING) printf("Starting %s\n", CommandLine);

	if (!SetPrivilege(GetCurrentProcess(), "SeDebugPrivilege", TRUE))
	{
		if (bVerbose & ACTION_DEBUGGING) printf("SetPrivilege SeDebugPrivilege failed! %d\n", GetLastError());
	}

	if (!CreateProcessA(NULL, CommandLine, NULL, NULL, FALSE, flags, NULL, NULL, &StartupInfo, &ProcessInfo))
	{
		return GetLastError();
	}
	if (bVerbose & ACTION_DEBUGGING) printf("Created %d\n", ProcessInfo.dwProcessId);

	CloseHandle(ProcessInfo.hProcess);
	CloseHandle(ProcessInfo.hThread);

	while (!LockyActive)
	{ // Debuggering!!
		LPVOID Reader;
		LPVOID Pointer;
		CRITICAL_SECTION CS = { 0 };
		InitializeCriticalSection(&CS);

		continue_search:
		if (LockyActive) // True if we have paused and scanned for the locky module
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Unable to locate configuration, resuming execution\n");
			LockyActive = FALSE;
			ContinueDebugEvent(DebugEvent.dwProcessId,
				DebugEvent.dwThreadId,
				dwContinueStatus);
		}
		if (!WaitForDebugEvent(&DebugEvent, 60 * 1000 * 2))
		{
			if (bVerbose & ACTION_DEBUGGING) printf("WaitForDebugEvent failed! %d\n", GetLastError());
			if (!DebugCount)
			{
				if (bVerbose & ACTION_DEBUGGING) printf("Debug wait failed and no processes are being debugged.\n");
				break;
			}
		}

		EnterCriticalSection(&CS);
		DebugProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);

		if (!VALID_HANDLE(DebugProcess))
		{
			printf("Failed to open process %d. Error %d\n", DebugEvent.dwProcessId, GetLastError());
			if (!DebugCount) break;
		}
		switch (DebugEvent.dwDebugEventCode)
		{
		case OUTPUT_DEBUG_STRING_EVENT:
			//if (bVerbose & ACTION_DEBUGGING) printf("DebugString:%s", DebugEvent.u.DebugString.lpDebugStringData);
			break;
		case LOAD_DLL_DEBUG_EVENT:
			Reader = malloc(0x100);
			if (ReadProcessMemory(DebugProcess, DebugEvent.u.LoadDll.lpImageName, &Pointer, sizeof(Pointer), &ByteCount) &&
				Pointer && ByteCount == sizeof(Pointer) &&
				ReadProcessMemory(DebugProcess, Pointer, Reader, 0x100, &ByteCount) && ByteCount && ((char*)Reader)[0])
			{
				if (DebugEvent.u.LoadDll.fUnicode)
				{
					if (bVerbose & ACTION_DEBUGGING) printf("Dll %p %S\n", DebugEvent.u.LoadDll.lpBaseOfDll, (LPWSTR)Reader);
				}
				else
				{
					if (bVerbose & ACTION_DEBUGGING) printf("Dll %p %s\n", DebugEvent.u.LoadDll.lpBaseOfDll, (LPSTR)Reader);
				}

				if (stristr(Reader, "vssapi.dll") ||
					wcsistr(Reader, L"vssapi.dll"))
				{
					LockyProcessID = DebugEvent.dwProcessId;
					LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
					LockyActive = VSSAPI_LOADED;
				}

				if (stristr(Reader, "dnsapi.dll") ||
					wcsistr(Reader, L"dnsapi.dll"))
				{
					LockyProcessID = DebugEvent.dwProcessId;
					LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
					LockyActive = DNSAPI_LOADED;
				}
				if (stristr(Reader, "sensapi.dll") ||
					wcsistr(Reader, L"sensapi.dll"))
				{
					LockyProcessID = DebugEvent.dwProcessId;
					LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
					LockyActive = SENSAPI_LOADED;
				}
				if (stristr(Reader, "cscapi.dll") ||
					wcsistr(Reader, L"cscapi.dll") ||
					stristr(Reader, "cscdll.dll") ||
					wcsistr(Reader, L"cscdll.dll"))
				{
					LockyProcessID = DebugEvent.dwProcessId;
					LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
					LockyActive = CSCAPI_LOADED;
				}
			}
			else
			{
				if (bVerbose & ACTION_DEBUGGING) printf("Dll %p %d\n", DebugEvent.u.LoadDll.lpBaseOfDll, GetLastError());
			}
			free(Reader);
			CloseHandle(DebugEvent.u.LoadDll.hFile);
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			if (bVerbose & ACTION_DEBUGGING) printf("Process %d ended with %d\n", DebugEvent.dwProcessId, DebugEvent.u.ExitProcess.dwExitCode);
			DebugCount -= 1;
			if ((0xc0000000 & DebugEvent.u.ExitProcess.dwExitCode) == 0xc0000000)
			{
				if (bVerbose & ACTION_DEBUGGING) printf("Process ended with NtStatus Error %p\n", (PVOID)DebugEvent.u.ExitProcess.dwExitCode);
				return 0x2;
			}
			LockyProcessID = DebugEvent.dwProcessId;
			LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
			LockyActive = PROC_ENDED;
			//if(!DebugCount) return 0x440;
			break;
		case CREATE_PROCESS_DEBUG_EVENT:
			DebugCount += 1;
			if (bVerbose & ACTION_DEBUGGING) printf("Process %d loaded at %p\n", DebugEvent.dwProcessId, DebugEvent.u.CreateProcessInfo.lpBaseOfImage);

			HIDE_DEBUGGER;

			CloseHandle(DebugEvent.u.CreateProcessInfo.hFile);
			CloseHandle(DebugEvent.u.CreateProcessInfo.hThread);
			CloseHandle(DebugEvent.u.CreateProcessInfo.hProcess);
			break;
		case CREATE_THREAD_DEBUG_EVENT:
			HIDE_DEBUGGER;
			CloseHandle(DebugEvent.u.CreateThread.hThread);
			break;
		case EXCEPTION_DEBUG_EVENT:
			switch (DebugEvent.u.Exception.ExceptionRecord.ExceptionCode)
			{
			case STATUS_INVALID_HANDLE:
				dwContinueStatus = DBG_EXCEPTION_HANDLED;
				break;
			case DEBUG_EXCEPTION:
				WriteProcessMemory(DebugProcess, pSleep, &Break, sizeof(Break), &ByteCount);
				FlushInstructionCache(DebugProcess, pSleep, ByteCount);
				dwContinueStatus = DBG_EXCEPTION_HANDLED;
				break;
			case BREAKPOINT_EXCEPTION:
				if (DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == pSleep)
				{
					CONTEXT lcContext = { 0 };
					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, DebugEvent.dwThreadId);
					INT SleepTime = 0;
					lcContext.ContextFlags = CONTEXT_ALL;

					GetThreadContext(hThread, &lcContext);
					lcContext.Eip = (DWORD)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress;
					lcContext.EFlags |= 0x100; // Set trap flag, which raises "single-step" exception
					SetThreadContext(hThread, &lcContext);
					CloseHandle(hThread);

					ReadProcessMemory(DebugProcess, RVA(lcContext.Esp, 4), &SleepTime, sizeof(SleepTime), &ByteCount);
					if (SleepTime > 10)
					{
						if (bVerbose & ACTION_DEBUGGING) printf("Sleep hit: %d\n", SleepTime);
						SleepTime = 1;
						WriteProcessMemory(DebugProcess, RVA(lcContext.Esp, 4), &SleepTime, sizeof(SleepTime), &ByteCount);
					}

					WriteProcessMemory(DebugProcess, pSleep, &SavedBytes, sizeof(1), &ByteCount);
					FlushInstructionCache(DebugProcess, pSleep, ByteCount);
					dwContinueStatus = DBG_EXCEPTION_HANDLED;
					break;
				}
				if (!SavedBytes)
				{
					if (!ReadProcessMemory(DebugProcess, pSleep, &SavedBytes, sizeof(1), &ByteCount))
					{
						printf("Failed to ReadProcessMemory - %d bytes\n", ByteCount);
						return GetLastError();
					}

					if (!WriteProcessMemory(DebugProcess, pSleep, &Break, sizeof(Break), &ByteCount))
					{
						printf("Failed to WriteProcessMemory\n");
						return GetLastError();
					}

					/*if (!WriteProcessMemory(DebugProcess, pWriteFile, &Break, sizeof(Break), &ByteCount))
					{
						printf("Failed to WriteProcessMemory\n");
						return GetLastError();
					}*/

					if (!WriteProcessMemory(DebugProcess, pMoveFile, &Break, sizeof(Break), &ByteCount))
					{
						printf("Failed to WriteProcessMemory\n");
						return GetLastError();
					}
				}
				else
				{
					if (bVerbose & ACTION_DEBUGGING) printf("Exception (%s chance) %p %p\n",
						(DebugEvent.u.Exception.dwFirstChance) ? "first" : "second",
						(LPVOID)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress,
						(LPVOID)DebugEvent.u.Exception.ExceptionRecord.ExceptionCode);
					fflush(stdout);
					
					LockyProcessID = DebugEvent.dwProcessId;
					LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
					if ((LPVOID)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == pWriteFile)
					{
						LockyActive = WRITE_FILE_CALLED;
					}
					if ((LPVOID)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress == pMoveFile)
					{
						LockyActive = MOVE_FILE_CALLED;
					}
					break;
				}

				dwContinueStatus = DBG_EXCEPTION_HANDLED;
				break;
			default:
				if (bVerbose & ACTION_DEBUGGING) printf("Exception (%s chance) %p %p\n",
					(DebugEvent.u.Exception.dwFirstChance) ? "first" : "second",
					(LPVOID)DebugEvent.u.Exception.ExceptionRecord.ExceptionAddress,
					(LPVOID)DebugEvent.u.Exception.ExceptionRecord.ExceptionCode);

				if (!DebugEvent.u.Exception.dwFirstChance)
				{
					LockyProcessID = DebugEvent.dwProcessId;
					LockyProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DebugEvent.dwProcessId);
					TerminateProcess(LockyProcess, DebugEvent.u.Exception.ExceptionRecord.ExceptionCode);
					return ERROR_UNIDENTIFIED_ERROR;
				}
				dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
				break;
			}
			break;
		default:
			//printf("dwDebugEventCode %d\n", DebugEvent.dwDebugEventCode)
			;
		}

		LeaveCriticalSection(&CS);

		fflush(stdout);

		if (!LockyActive)
		{
			ContinueDebugEvent(DebugEvent.dwProcessId,
				DebugEvent.dwThreadId,
				dwContinueStatus);
		}
		CloseHandle(DebugProcess);
	}

	if (LockyActive)
	{
		CHAR Page[0x1000] = { 0 };
		PVOID ModuleAddr = (PVOID)0x1000;

		if (bVerbose & ACTION_DEBUGGING) printf("Searching Locky process %d\n", LockyProcessID);

		while (!((ULONG_PTR)ModuleAddr & 0x80000000))
		{
			ModuleAddr = search_module_for_config(LockyProcess, ModuleAddr, bVerbose);
			if (0 == ModuleAddr)
			{
				return 0;
			}
		}

		if (bVerbose & ACTION_DEBUGGING) printf("Failed to locate config %d\n", LockyProcessID);
		goto continue_search;
	}

	if (bVerbose & ACTION_DEBUGGING) printf("No config found\n");
	return (0xB00);
}

void dump_exports(HMODULE ModuleBase)
{
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_DATA_DIRECTORY DataDirectory;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	DWORD i;

	DosHeader = RVA(ModuleBase, 0);
	NtHeader = RVA(ModuleBase, DosHeader->e_lfanew);

	DataDirectory = &NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (DataDirectory->VirtualAddress)
	{
		ExportDirectory = RVA(ModuleBase, DataDirectory->VirtualAddress);

		printf("   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
		printf("   Exported name:\n%s\nExports:\n", (PCHAR)(RVA(ModuleBase, ExportDirectory->Name)));
		for (i = 0; i < ExportDirectory->NumberOfNames; ++i)
		{
			fflush(stdout);
			PDWORD NamesRVA = RVA(ModuleBase, ExportDirectory->AddressOfNames);
			printf("     %s\n", (PCHAR)(RVA(ModuleBase, NamesRVA[i])));
		}
		printf("   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n");
	}
}
BOOLEAN dump_config_values(LOCKY_CONFIG_HEADER* ConfigStart, BOOLEAN bVerbose)
{
	__try {
		DWORD b;
		BOOLEAN offline_only = FALSE;
		BOOLEAN Extended = FALSE;
		LOCKY_CONFIG_CLASSIC* ConfigClassic = (LOCKY_CONFIG_CLASSIC*)ConfigStart;
		LOCKY_CONFIG* ConfigExtended = (LOCKY_CONFIG*)ConfigStart;

		if (ConfigStart->affilID > 0xFFF)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Affiliate ID %X\n", ConfigStart->affilID);
			return FALSE;
		}
		if (ConfigStart->Delay > 0xFFFF)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Delay %d seconds\n", ConfigStart->Delay);
			return FALSE;
		}
		if (ConfigStart->PersistSvchost & 0xFFFFFFFE)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Persist Svchost %X\n", ConfigStart->PersistSvchost);
			return FALSE;
		}

		if (ConfigStart->PersistRegistry & 0xFFFFFFFE)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Persist Registry %X\n", ConfigStart->PersistRegistry);
			return FALSE;
		}

		if (ConfigStart->IgnoreRussian & 0xFFFFFFFE)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Ignore Russian %X\n", ConfigStart->IgnoreRussian);
			return FALSE;
		}

		if (ConfigStart->DGASeed == 0)
		{
			offline_only = TRUE;
			Extended = TRUE;
			if (bVerbose & ACTION_DEBUGGING) printf("DGA Seed is 0. Offline only\n");

			if (!ConfigExtended->RsaKeyID || ConfigExtended->RsaKeyID > 0xFFFFF)
			{
				if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Rsa Key ID is not valid %X\n", ConfigExtended->RsaKeyID);
				return FALSE;
			}
			if (!ConfigExtended->RsaKeySizeBytes || ConfigExtended->RsaKeySizeBytes > 0x400)
			{
				if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Rsa Key Size is not valid %X\n", ConfigExtended->RsaKeySizeBytes);
				return FALSE;
			}
		}
		else if (!ConfigClassic->C2Servers[0])
		{
			if (bVerbose & ACTION_DEBUGGING) printf("DGA Seed is set but no online data.\n");
			return FALSE;
		}

		if (!offline_only && ConfigExtended->CallbackPath[0] == '/')
		{
			Extended = TRUE;

		}
		else if (!offline_only && ConfigExtended->CallbackPath[0])
		{
			if (ConfigExtended->CallbackPath[0] < '0' || ConfigExtended->CallbackPath[0] > '9')
			{
				if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Config Classic C2Servers is not valid %X\n", ConfigClassic->C2Servers[0]);
				return FALSE;
			}
			Extended = FALSE;
		}

		if (Extended && ConfigExtended->RsaKeyID && !ConfigExtended->RsaKeySizeBytes)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Invalid RsaKeySizeBytes with RsaKeyID present\n");
			return FALSE;
		}
		if (Extended && !ConfigExtended->RsaKeyID && ConfigExtended->RsaKeySizeBytes)
		{
			if (bVerbose & ACTION_DEBUGGING) printf("Invalid Configuration: Invalid RsaKeyID with RsaKeySizeBytes present\n");
			return FALSE;
		}

		printf("affilID: %X\n", ConfigStart->affilID);
		printf("Seed: %d\n", ConfigStart->DGASeed);
		printf("Delay: %d\n", ConfigStart->Delay);
		printf("Persist Svchost: %X\n", ConfigStart->PersistSvchost);
		printf("Persist Registry: %X\n", ConfigStart->PersistRegistry);
		printf("Ignore Russian Machines: %X\n", ConfigStart->IgnoreRussian);

		fflush(stdout);
		if (Extended && (!offline_only && ConfigExtended->CallbackPath[0]))
		{
			printf("CallbackPath: %s\n", ConfigExtended->CallbackPath);
		}
		else
		{
			printf("CallbackPath: <none>\n");
		}

		fflush(stdout);
		if (Extended && (!offline_only && ConfigExtended->C2Servers[0]))
		{
			printf("C2Servers: %s\n", ConfigExtended->C2Servers);
		}
		else if (!Extended && (!offline_only && ConfigClassic->C2Servers[0]))
		{
			printf("C2Servers: %s\n", ConfigClassic->C2Servers);
		}
		else
		{
			printf("C2Servers: <none>\n");
		}

		if (!Extended) return TRUE;

		printf("RsaKeyID: %X\n", ConfigExtended->RsaKeyID);
		printf("RsaKeySizeBytes: %X\n", ConfigExtended->RsaKeySizeBytes);
		if (ConfigExtended->RsaKeySizeBytes)
		{
			printf("Key Alg: %X\n", ConfigExtended->RsaKeyStruct.aiKeyAlg);
			printf("Key: %s\n", (PCHAR) &(ConfigExtended->RsaKeyHdr.magic));
			printf("Key Bits: %d\n", ConfigExtended->RsaKeyHdr.bitlen);
			printf("Key Exponent: %x\n", ConfigExtended->RsaKeyHdr.pubexp);
			printf("Key Bytes:");
			for (b = 0; b < ConfigExtended->RsaKeyHdr.bitlen / 8; ++b)
			{
				if (b % 8 == 0)
				{
					printf("\n\t");
				}
				printf("%02X ", ConfigExtended->RsaKeyData[b]);
			}
			printf("\n");
		}
		if (!(bVerbose & ACTION_VERBOSE)) return TRUE;

		if (ConfigExtended->RansomNote[0])
		{
			printf("RansomNote: %s\n", ConfigExtended->RansomNote);
		}
		if (ConfigExtended->HtmlRansom[0])
		{
			printf("HtmlRansom: %s\n", ConfigExtended->HtmlRansom);
		}

		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
}


void CallEntrypoint(HMODULE TargetModule, PIMAGE_NT_HEADERS NtHeader)
{
	((DllMainFunc)(RVA(TargetModule, NtHeader->OptionalHeader.AddressOfEntryPoint)))(TargetModule, DLL_PROCESS_ATTACH, 0);
	return;
}
int main(int argc, char** argv)
{
	HMODULE TargetModule;
	HANDLE TargetFile;
	PBYTE Page1, Page1Loaded;
	DWORD Read = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS);
	PIMAGE_DOS_HEADER DosHeader;
	PIMAGE_NT_HEADERS NtHeader;

	BOOLEAN NotChanged;
	BOOLEAN ExeFile = 0;
	BOOLEAN bVerbose = 0;
	DWORD ret = 0;
	if (argc < 2)
	{
		printf("Usage: LockyDump <module to dump>\n");
		return ERROR_BAD_ARGUMENTS;
	}

	bVerbose |= (0 != GetEnvironmentVariable("LOCKY_DUMP_VERBOSE", NULL, 0)) ? ACTION_VERBOSE : 0;
	bVerbose |= 0 != GetEnvironmentVariable("LOCKY_DUMP_SAVE", NULL, 0) ? ACTION_DROP : 0;
	bVerbose |= 0 != GetEnvironmentVariable("LOCKY_DUMP_DIAG", NULL, 0) ? ACTION_DEBUGGING : 0;
	printf("Verbose: %X\n", bVerbose);

	Page1 = malloc(0x400);
	Page1Loaded = malloc(0x400);

	TargetFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (TargetFile == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open file");
		return GetLastError();
	}

	// Skip popup boxes if LoadLibrary fails
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX);
	TargetModule = LoadLibraryA(argv[1]);
	if (!TargetModule)
	{
		printf("Failed to load module\n");
		return GetLastError();
	}
	DosHeader = RVA(TargetModule, 0);
	NtHeader = RVA(TargetModule, DosHeader->e_lfanew);
	if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL ||
		0x10000000 == NtHeader->OptionalHeader.ImageBase)
	{
		printf("Loaded: %p\n", TargetModule);
		if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL) printf("The file is a DLL\n");
		else if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			// Locky sample found that is a PE but has a DLL ImageBase
			// It doesn't run as a stand alone EXE
			printf("The file is a PE EXE\n");
			printf("Requested Image Base: %p\n", (PVOID)NtHeader->OptionalHeader.ImageBase);
			ParseIAT(TargetModule);
			// The Entrypoint changes the calling function's frame so it has to be called by an intermediate function
			CallEntrypoint(TargetModule, NtHeader);
		}
		if (!ReadProcessMemory(GetCurrentProcess(), TargetModule, Page1Loaded, Read, &Read) || !Read)
		{
			printf("Failed to copy header from loaded module\n");
			return GetLastError();
		}
		if (!ReadFile(TargetFile, Page1, Read, &Read, NULL) || !Read)
		{
			printf("Failed to copy header from target file\n");
			return GetLastError();
		}

		NotChanged = (memcmp(Page1, Page1Loaded, Read) == 0);

		printf("Read %d bytes\n", Read);
		printf("The headers are %s\n", (NotChanged) ? "the same" : "different");

		if (NotChanged)
		{
			return ERROR_NOT_FOUND;
		}

		dump_exports(TargetModule);

		if (bVerbose & ACTION_DROP)
		{
			dump_mapped_binary(GetCurrentProcess(), TargetModule, bVerbose);
		}

		if (search_module_for_config(GetCurrentProcess(), TargetModule, bVerbose))
		{
			return ERROR_SUCCESS;
		}
		return ERROR_NOT_FOUND;
	}
	else if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
	{
		printf("The file is a PE EXE\n");

		CloseHandle(TargetFile);
		FreeLibrary(TargetModule);

		ret = run_exe(argv[1], bVerbose);
		return ret;
	}

	return ERROR_BAD_EXE_FORMAT;
}
