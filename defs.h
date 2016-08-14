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

#define BASENAME "WinD" BITS

#define RTL_STRING(s) ((UNICODE_STRING){sizeof(s)-sizeof((s)[0]),sizeof(s),(s)})

#define RVA2PTR(base,rva) ((void*)(((PCHAR) base) + rva))
#define ID_SeLoadDriverPrivilege 10
#define LUID_SeLoadDriverPrivilege (LUID){ID_SeLoadDriverPrivilege,0}

#define FILE_VBS "wind-restorepoint.vbs"
#define RESTORE_VBS \
	"set obj=GetObject(\"winmgmts:\\\\.\\root\\default:Systemrestore\")\nobj.Enable(\"\")\n" \
	"obj.CreateRestorePoint \"%s\", 0, 100\nWScript.Quit 123"

#define POLICY_KEY "System\\CurrentControlSet\\Control\\ProductOptions"
#define PRODUCT_POLICY "ProductPolicy"
#define CUSTOM_POLICY "CustomPolicy"

#define NT_MACHINE L"\\Registry\\Machine\\"

#define POLICY_PATH NT_MACHINE POLICY_KEY
#define SVC_BASE NT_MACHINE "System\\CurrentControlSet\\Services\\"
#define LOAD_ATTEMPTS 8

#ifndef NDEBUG
#ifdef _WIND_DRIVER
#define DBG(x...) DbgPrint("WIND: " x);
#else
//#define DBG(x...) { printf("! %s:%d@%s(): ",__FILE__,__LINE__,__func__); printf(x); printf("\n"); }
#define DBG(x...) {  \
	char _buf[512]; \
	sprintf(_buf + sprintf(_buf, "WIND: %s:%d@%s(): ",__FILE__,__LINE__,__func__), x); \
	strcat(_buf, "\n"); \
	OutputDebugStringA(_buf); \
}
#endif
#else
#define DBG(x...)
#endif

#define RTL_QUERY_REGISTRY_TYPECHECK 0x00000100
#define RTL_QUERY_REGISTRY_TYPECHECK_SHIFT 24

#define WIN7 (cfg.protbit >= 0)
#define SystemModuleInformation 0xb
#define SystemBootEnvironmentInformation 0x5a
#define SystemCodeIntegrityInformation 0x67
#define SystemSecureBootPolicyInformation 0x8f


#define WSKIP(p) while (*p == L' ' || *p == L'\t') p++;
#define EQUALS(a,b) (RtlCompareMemory(a,b,sizeof(b)-1)==(sizeof(b)-1))

