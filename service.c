#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include "defs.h"
#include "ntcruft.h"
#include "wind.h"

static void *patch_iat(HMODULE hostexe, char *dll, char *func, void *to)
{
	PIMAGE_DOS_HEADER mz = (void*)hostexe;
	PIMAGE_IMPORT_DESCRIPTOR imports;

	imports = RVA2PTR(mz, ((PIMAGE_NT_HEADERS)RVA2PTR(mz, mz->e_lfanew))->
		OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (int i = 0; imports[i].Characteristics; i++) {
		PIMAGE_THUNK_DATA t1, t2;
		PIMAGE_IMPORT_BY_NAME import;

		char *dlln = RVA2PTR(mz, imports[i].Name);
		DBG("checking dll %s", dlln);
		if (_stricmp(dll, dlln))
			continue;

		t1 = RVA2PTR(mz, imports[i].FirstThunk);
		t2 = RVA2PTR(mz, imports[i].OriginalFirstThunk);

		for (; t2->u1.Function; t1++, t2++) {
			void *oldfn;
			DWORD oldp;
			MEMORY_BASIC_INFORMATION vmi;

			if (t2->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				continue;

			import = RVA2PTR(mz, t2->u1.AddressOfData);
			if (strcmp(func, (char*)import->Name))
				continue;

			oldfn = (void*)t1->u1.Function;
			DBG("oldfn is %p\n",oldfn);

			VirtualQuery(t1, &vmi, sizeof(vmi));
			if (!VirtualProtect(vmi.BaseAddress, vmi.RegionSize, PAGE_READWRITE, &oldp)) {
				DBG("VirtualProtect failed with %d", (int)GetLastError());
				return NULL;
			}
			t1->u1.Function = (ULONG_PTR)to;
			VirtualProtect(vmi.BaseAddress, vmi.RegionSize, oldp, &oldp);
			return oldfn;
		}
	}
	DBG("symbol %s@%s not found in imports", func, dll);
	return NULL;
}

static NTSTATUS insmod(PUNICODE_STRING svc)
{
	return wind_insmod(svc->Buffer);
}

BOOL APIENTRY ENTRY(dll_main)(HANDLE hModule, DWORD code, LPVOID res)
{
	static int done = 0;
 	if (code != DLL_PROCESS_ATTACH || done)
		return TRUE;
	done = 1;
	DBG("inside dll!");
	patch_iat(GetModuleHandle(NULL), "ntdll.dll", "NtLoadDriver", insmod);
	return TRUE;
}

