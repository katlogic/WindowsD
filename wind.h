// Public API, standalone header.
// Parent includes:  windows.h, winternl.h
// Links against ntdll.

// Open \\Device\\WinD
#define WIND_DEVNAME "WinD"

// Used to pass initialization.
typedef struct {
	UCHAR 	*ci_opt;
	UCHAR 	*ci_orig;
	UCHAR 	ci_guess;  // If ciorigptr is 0, use this guess instead.
	int 	protofs;   // _EPROCESS->Flags2 offset on Win7, PS_PROTECTION Win8.
	int 	protbit;   // Flags2->ProtectedProcess bit on Win7, -1 otherwise.
	int 	bootreg;   // process registry entries at boot
	LIST_ENTRY *cblist;
	NTSTATUS NTAPI (*pExUpdateLicenseData)(ULONG,PVOID);
	NTSTATUS __fastcall (*pExUpdateLicenseData2)(ULONG,PVOID);
} wind_config_t;
#define WIND_POL_MAX 512

#define WIND_IOCTL_REGCBOFF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WIND_IOCTL_REGCBON CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Load a driver. Argument is simply the unicode string.
#define WIND_IOCTL_INSMOD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Lock/Unlock registry key. Odd ones are the 'on' command.
#define WIND_IOCTL_REGLOCKON CTL_CODE(FILE_DEVICE_UNKNOWN, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WIND_IOCTL_REGLOCKOFF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WIND_IOCTL_REGNON CTL_CODE(FILE_DEVICE_UNKNOWN, 0x813, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define WIND_IOCTL_REGNOFF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)


// Get/set WinTcb process protection.
#define WIND_IOCTL_PROT   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct {
	char SignatureLevel;
	char SectionSignatureLevel;
	char Level;
	UCHAR Type:3;
	UCHAR Audit:1;
	UCHAR Signer:4;
} WIND_PS_PROTECTION;
typedef struct {
	LONG_PTR pid; 		// Pid this is for. Negative = get flags only.
	WIND_PS_PROTECTION prot;// New protection flags. Old flags stored in there.
} wind_prot_t;

// Policy header
typedef struct {
	ULONG 	sz; 		// Size of everything.
	ULONG 	data_sz; 	// Always sz-0x18.
	ULONG 	endpad; 	// End padding. Usually 4.
	ULONG 	tainted; 	// 1 if tainted.
	ULONG 	pad1; 		// Always 1
} __attribute((packed)) wind_pol_hdr;

// Policy entry
typedef struct {
	USHORT  sz; 		// Size of whole entry.
	USHORT 	name_sz; 	// Size of the following field, in bytes.
	USHORT 	type; 		// Field type
	USHORT 	data_sz; 	// Field size
	ULONG 	flags; 		// Field flags
	ULONG 	pad0; 		// Always 0
	UCHAR 	name[0]; 	// WCHAR name, NOT zero terminated!
} __attribute__((packed)) wind_pol_ent;

static int wind_pol_unpack(UCHAR *blob, wind_pol_ent **array)
{
	wind_pol_hdr *h = (void*)blob;
	wind_pol_ent *e = (void*)blob + sizeof(*h);
	void *endptr = ((void*)e) + h->data_sz;
	int n = 0;
	// Unusual.
	if (h->sz >= 65536)
		return -1;
	if (h->endpad != 4)
		return -2;
	if (h->data_sz+0x18 != h->sz)
		return -3;
	if (blob[h->sz-4] != 0x45)
		return -4;
	while (((void*)e) < endptr) {
		array[n++] = e;
		e = ((void*)e) + e->sz;
		if (n == WIND_POL_MAX)
			return -1;
	}
	return n;
}

static int wind_pol_pack(UCHAR *dst, wind_pol_ent **array, int n)
{
	wind_pol_hdr *h = (void*)dst;
	wind_pol_ent *e = (void*)dst + sizeof(*h);
	int i = 0;
	memset(dst, 0, 65536);
	for (i = 0; i < n; i++) {
		int total = sizeof(*e) + array[i]->name_sz + array[i]->data_sz;
		memcpy(e, array[i], total);
		total = (total + 4) & (~3);
		e->sz = total;
		e = ((void*)e) + total;
		h->data_sz += total;
	}
	h->sz = h->data_sz + 0x18;
	h->endpad = 4;
	h->pad1 = 1;
	dst[h->sz-4] = 0x45;
	return h->sz;
}

// Open the kernel driver
#ifndef _WIND_DRIVER
#define WIND_RTL_STRING(s) ((UNICODE_STRING){sizeof(s)-sizeof((s)[0]),sizeof(s),(s)})
static HANDLE wind_open()
{
	OBJECT_ATTRIBUTES attr = {
		.Length = sizeof(attr),
		.Attributes = OBJ_CASE_INSENSITIVE,
		.ObjectName = &WIND_RTL_STRING(L"\\Device\\" WIND_DEVNAME),
	};
	IO_STATUS_BLOCK io;
	HANDLE dev;
	BOOLEAN old;
	extern NTSTATUS NTAPI RtlAdjustPrivilege(ULONG,BOOLEAN,BOOLEAN,PBOOLEAN);
	RtlAdjustPrivilege(10, 1, 0, &old);
	NTSTATUS status = NtOpenFile(&dev, FILE_GENERIC_READ, &attr, &io,
		FILE_SHARE_READ,FILE_NON_DIRECTORY_FILE| FILE_SYNCHRONOUS_IO_NONALERT);
	if (status == STATUS_NOT_FOUND)
		return NULL;
	if (!NT_SUCCESS(status))
		return NULL;
	return dev;
}

// Pass an ioctl. IOCTLs with 9th bit set are read-write, others are write-only.
static NTSTATUS wind_ioctl(HANDLE dev, ULONG num, void *buf, int len)
{
	IO_STATUS_BLOCK io;
	if (num & (0x100<<2)) {
		return NtDeviceIoControlFile(dev, NULL, NULL, NULL, &io,
				num, buf, len, buf, len);
	} else {
		return NtDeviceIoControlFile(dev, NULL, NULL, NULL, &io,
				num, buf, len, NULL, 0);
	}
}
static NTSTATUS wind_ioctl_string(HANDLE dev, ULONG num, WCHAR *s)
{
	return wind_ioctl(dev, num, s, wcslen(s)*2+2);
}

// Close driver.
static NTSTATUS wind_close(HANDLE dev)
{
	extern NTSTATUS NTAPI NtClose(HANDLE);
	if (dev)
		return NtClose(dev);
	return 0;
}

#ifndef STATUS_IMAGE_CERT_EXPIRED
#define STATUS_IMAGE_CERT_EXPIRED 0xc0000605 
#endif

// Utility: Load a driver with DSE bypass.
static NTSTATUS wind_insmod(WCHAR *svc)
{
	UNICODE_STRING svcu;
	NTSTATUS status;
       
	RtlInitUnicodeString(&svcu, svc);
	status = NtLoadDriver(&svcu);
	// TBD: are these all the evil ones?
	if (status == STATUS_IMAGE_CERT_REVOKED 
		|| status == STATUS_INVALID_SIGNATURE
		|| status == STATUS_INVALID_IMAGE_HASH
		|| status == STATUS_INVALID_SID
		|| status == STATUS_IMAGE_CERT_EXPIRED
		|| status == STATUS_HASH_NOT_PRESENT
		|| status == STATUS_HASH_NOT_SUPPORTED) {

		HANDLE h = wind_open();
		if (!h) return status;
		status = wind_ioctl_string(h, WIND_IOCTL_INSMOD, svc);
		wind_close(h);
	}
	return status;
}

#endif

