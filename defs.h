// universally used macros go here
// ONLY macros

#define LOADER_ID 10
#define SYS_ID 20
#define DLL_ID 30

#ifdef _WIN64
#define BITS "64"
#define ENTRY(x) _##x
#else
#define ENTRY(x) x
#define BITS "32"
#endif

#define IO_DEVNAME "WinD"
#define BASENAME "WinD" BITS

#define IOCTL_SETUP 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INSMOD 	CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define RTL_STRING(s) ((UNICODE_STRING){sizeof(s)-sizeof((s)[0]),sizeof(s),(s)})

#define RVA2PTR(base,rva) ((void*)(((PBYTE) base) + rva))
#define ID_SeLoadDriverPrivilege 10
#define LUID_SeLoadDriverPrivilege (LUID){ID_SeLoadDriverPrivilege,0}

#define FILE_VBS "wind-restorepoint.vbs"
#define RESTORE_VBS \
	"set obj=GetObject(\"winmgmts:\\\\.\\root\\default:Systemrestore\")\nobj.Enable(\"\")\n" \
	"obj.CreateRestorePoint \"%s\", 0, 100\nWScript.Quit 123"

#define SVC_BASE L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\"
#define APPINIT_BASE L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"

#define LOAD_ATTEMPTS 8

#ifndef NDEBUG
#ifdef _DRIVER
#define DBG(x...) DbgPrint("WiND: " x);
#else
//#define DBG(x...) { printf("! %s:%d@%s(): ",__FILE__,__LINE__,__func__); printf(x); printf("\n"); }
#define DBG(x...) {  \
	char _buf[512]; \
	sprintf(_buf + sprintf(_buf, "! %s:%d@%s(): ",__FILE__,__LINE__,__func__), x); \
	strcat(_buf, "\n"); \
	OutputDebugStringA(_buf); \
}
#endif
#else
#define DBG(x...)
#endif
