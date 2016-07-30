#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include "defs.h"

#define STATUS_IMAGE_CERT_EXPIRED 0xc0000605 

static NTSTATUS __stdcall (*pNtLoadDriver)(PUNICODE_STRING DriverServiceName);

#include "ioctl.c"

static void *patch_iat(char *dll, char *func, void *to)
{
	HMODULE hostexe;
	PIMAGE_DOS_HEADER mz;
	PIMAGE_IMPORT_DESCRIPTOR imports;

	mz = (void*)(hostexe = GetModuleHandle(NULL));
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
			void *oldfn, *base;
			DWORD oldp;

			if (t2->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				continue;

			import = RVA2PTR(mz, t2->u1.AddressOfData);
			if (strcmp(func, (char*)import->Name))
				continue;

			oldfn = (void*)t1->u1.Function;
			DBG("oldfn is %p\n",oldfn);
			base = (void*)(((ULONG_PTR)t1)&(~4095));
			if (!VirtualProtect(base, 8192, PAGE_EXECUTE_READWRITE, &oldp)) {
				DBG("VirtualProtect failed with %d", (int)GetLastError());
				return NULL;
			}
			t1->u1.Function = (ULONG_PTR)to;
			VirtualProtect(base, 8192, oldp, &oldp);
			return oldfn;
		}
	}
	DBG("symbol %s@%s not found in imports", func, dll);
	return NULL;
}

static NTSTATUS insmod(PUNICODE_STRING svc)
{
	DBG("insmod %S", svc->Buffer);
	NTSTATUS res = pNtLoadDriver(svc);
	if ( 	// TBD: are these all the evil ones?
		res == STATUS_IMAGE_CERT_REVOKED || res == STATUS_INVALID_SIGNATURE ||
		res == STATUS_INVALID_IMAGE_HASH || res == STATUS_INVALID_SID ||
		res == STATUS_IMAGE_CERT_EXPIRED || res == STATUS_HASH_NOT_PRESENT ||
		res == STATUS_HASH_NOT_SUPPORTED
	   ) {
		DBG("load failed, err = %08x", (int)res);
		HANDLE h = ioctl_open();
		if (h) {
			res = ioctl_insmod(h, svc->Buffer);
			ioctl_close(h);
		}
	}
	return res;
}

BOOL APIENTRY ENTRY(dll_main)(HANDLE hModule, DWORD code, LPVOID res)
{
	static int done = 0;
 	if (code == DLL_PROCESS_ATTACH && !done) {
		done = 1;
		pNtLoadDriver = patch_iat("ntdll.dll", "NtLoadDriver", insmod);
		DBG("iat patched, old = %p", pNtLoadDriver);
	}
	return TRUE;
}

