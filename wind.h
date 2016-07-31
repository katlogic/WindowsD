// Public API, standalone header.
// Depends only on NT dll (see ntcruft.h) and headers.

// Open \\Device\\WinD
#define WIND_DEVNAME "WinD"

// used to pass initialization
typedef struct {
	UCHAR 	*ci_opt;
	UCHAR 	*ci_orig;
	UCHAR 	ci_guess;  // if ciorigptr is 0, use this guess instead
	int 	protofs;  // _EPROCESS->Flags2 offset on Win7, PS_PROTECTION Win8
	int 	protbit;  // Flags2->ProtectedProcess bit on Win7, -1 otherwise
} wind_config_t;

// Load a driver. Argument is simply the unicode string.
#define WIND_IOCTL_INSMOD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Get/set WinTcb process protection
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
	WIND_PS_PROTECTION prot; // New protection flags. Old flags stored in there.
} wind_prot_t;

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

// Close driver.
static NTSTATUS wind_close(HANDLE dev)
{
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
		status = wind_ioctl(h, WIND_IOCTL_INSMOD, svc, wcslen(svc)*2+2);
		wind_close(h);
	}
	return status;
}

#endif

