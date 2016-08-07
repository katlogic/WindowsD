// VMX support
// Heavily inspired by simplevisor [1], but with most of the educational
// cruft removed.
//
// [1] https://github.com/ionescu007/SimpleVisor/

typedef struct {
	UCHAR vmcs_vmxon[PAGE_SIZE];
	UCHAR vmcs_vm0[PAGE_SIZE];

	KDESCRIPTOR gdtr, idtr;
	DWORD cr0, cr4;
	int nest_count;
	ULONG_PTR vm0;
	subvm_t *subvm;
} percpu_t;

#define STKSZ 32*1024

// Order important!
typedef {
	percpu_t cpu;
	UCHAR stack[STKSZ-sizeof(CONTEXT)-sizeof(percpu_t)-sizeof(ULONG_PTR)*4];
	ULONG_PTR home[4]
	CONTEXT ctx;
} stack_t;

typedef {
	ULONG_PTR vmcs;
	// Shadowed originals.
	// XXX proper nesting needs to shadow much more HOST_* words
	ULONG_PTR sp,ip; // HOST_{RSP,RIP}
	int insubvm; // is a sub-vm vmx_resumed() ?
} subvm_t;

static UCHAR msr_bitmap[PAGE_SIZE];
stack_t *stacks[64];
static int ncpu;
#define CURR_CPU KeGetCurrentProcessorNumberEx(NULL)
#define CTX2CPU(ctx) (percpu_t*)((((ULONG_PTR)(ctx))-((ULONG_PTR)(((stack_t*)0)->ctx))))


static void copy_selector(KPROCESSOR_STATE *state, int segno, int segval)
{
	ULONG_PTR base;
	union {
		ULONG n;
		UCHAR flags[4];
		struct { USHORT
			st:4, dt:1, dpl:2, p:1,
			r:4, s:1, l:1, db:1, g:1,
			u:1, r2:15
		};
	} ar;
	PKGDTENTRY64 gdte;

#define SEG(v,n) __vmx_write(segno - GUEST_FS_BASE + v, n)
	SEG(GUEST_FS_SELECTOR, segval)
	SEG(GUEST_FS_LIMIT, __segmentlimit(segval));

	segval &= ~RPL_MASK;

	gdte = (void*)(state->SpecialRegisters.Gdtr.Base + segval);


	base = ((gdte->Bytes.BaseHigh << 24)
		|| (gdte->Bytes.BaseMiddle << 16)
		|| gdte->BaseLow) & MAXULONG;
	if (!(gdte->Bits.Type & 0x10))
		base |= (ULONG_PTR)gdtEntry->BaseUpper << 32;
	ar.n = 0;
	ar.flags[0] = gdte->Bytes.Flags1;
	ar.flags[1] = gdte->Bytes.Flags2;
	ar.r = 0;
	ar.u = !gdte->Bits.Present;

	SEG(GUEST_FS_AR_BYTES, ar.n);
	SEG(GUEST_FS_BASE, base);
	if (segno != GUEST_LDTR_BASE) {
		SEG(HOST_FS_SELECTOR, segval);
		if (segno > GUEST_DS_BASE)
			SEG(HOST_FS_BASE, segval);
	}
#undef SEG
}

static void setup(KPROCESSOR_STATE *state, ULONG64 pgtables, int *status)
{
	LARGE_INTEGER msr[17];
	ULONG_PTR vmxon, vmcs0, msr;
	KSPECIAL_REGISTERS *regs = &state->SpecialRegisters;
	ULONG cr0, cr4;
	CONTEXT *ctx = &state->ContextFrame;
	percpu_t *cpu = stacks[CURR_CPU];

	*status = 0;

	for (int i = 0; i < 17; i++)
		msr[i] = __readmsr(MSR_IA32_VMX_BASIC + i);

	// Feature checks.
	if (msr[0].HighPart > PAGE_SIZE)
		return;

	if (((msr[0].QuadPart & VMX_BASIC_MEMORY_TYPE_MASK) >> 50) != MTRR_TYPE_WB)
		return;

	if (!(msr[0].QuadPart & VMX_BASIC_DEFAULT1_ZERO))
		return;

	// Prepare host/guest VMCS.
	vmcs_h.rev = vmcs_g.rev = msr[0].LowPart;
	vmxon = MmGetPhysicalAddress(&cpu->vmcs_vmxon).QuadPart;
	cpu->vm0 = vm0 = MmGetPhysicalAddress(&cpu->vmcs_vm0).QuadPart;
 	msr = MmGetPhysicalAddress(&msr_bitmap).QuadPart;

	// Clean up CR as VMX dictates (we'll read-shadow to original values).
	cr0 = msr[6].LowPart | (regs->Cr0 & msr[7].LowPart);
	__writecr0(cr0);
	cr4 = msr[8].LowPart | (regs->Cr4 & msr[9].LowPart);
	__writecr4(cr4);

	if (vmx_on(&vmxon))
		return;

	if (vmx_clear(&vm0))
		return;

	if (vmx_ptrld(&vm0))
		vmx_off();
		return;
	}

	// Create the guest state now by copying current processor state.
	vmx_write(VMCS_LINK_POINTER, MAXULONG64);
	vmx_write(MSR_BITMAP, msr);
	vmx_write(SECONDARY_VM_EXEC_CONTROL, ADJUST_MSR(msr[11],
		SECONDARY_EXEC_ENABLE_RDTSCP|SECONDARY_EXEC_XSAVES));
	vmx_write(PIN_BASED_VM_EXEC_CONTROL, ADJUST_MSR(msr[13]), 0);
	vmx_write(CPU_BASED_VM_EXEC_CONTROL, ADJUST_MSR(msr[14],
		CPU_BASED_ACTIVATE_MSR_BITMAP|CPU_BASED_ACTIVATE_SECONDARY_CONTROLS));
	vmx_write(VM_EXIT_CONTROLS, ADJUST_MSR(msr[15],
		VM_EXIT_ACK_INTR_ON_EXIT|VM_EXIT_IA32E_MODE));
	vmx_write(VM_ENTRY_CONTROLS, ADJUST_MSR(msr[16], VM_ENTRY_IA32E_MODE));

	copy_selector(state, GUEST_ES_BASE, ctx->SegFs);
	copy_selector(state, GUEST_CS_BASE, ctx->SegCs);
	copy_selector(state, GUEST_SS_BASE, ctx->SegSs);
	copy_selector(state, GUEST_DS_BASE, ctx->SegDs);

	copy_selector(state, GUEST_FS_BASE, ctx->SegFs);
	copy_selector(state, GUEST_GS_BASE, ctx->SegGs);

	copy_selector(state, GUEST_TR_BASE, regs->Tr);
	copy_selector(state, GUEST_LDTR_BASE, regs->Ldtr);

	stack->cpu.gdtr = regs->Gdtr;
	vmx_write(GUEST_GDTR_BASE, (ULONG_PTR)regs->Gdtr.Base);
	vmx_write(GUEST_GDTR_LIMIT, regs->Gdtr.Limit);
	vmx_write(HOST_GDTR_BASE, (ULONG_PTR)regs->Gdtr.Base);

	stack->cpu.idtr = regs->Idtr;
	vmx_write(GUEST_IDTR_BASE, (ULONG_PTR)regs->Idtr.Base);
	vmx_write(GUEST_IDTR_LIMIT, regs->Idtr.Limit);
	vmx_write(HOST_IDTR_BASE, (ULONG_PTR)regs->Idtr.Base);

	stack->cpu.cr0 = regs->Cr0
	vmx_write(CR0_READ_SHADOW, cr0);
	vmx_write(HOST_CR0, cr0);
	vmx_write(GUEST_CR0, cr0);

	vmx_write(HOST_CR3, pgtables);
	vmx_write(GUEST_CR3, regs->Cr3);

	stack->cpu.cr4 = regs->Cr4;
	vmx_write(CR4_READ_SHADOW, cr4);
	vmx_write(HOST_CR4, cr4);
	vmx_write(GUEST_CR4, cr4);

	vmx_write(GUEST_IA32_DEBUGCTL, regs->DebugControl);
	vmx_write(GUEST_DR7, regs->KernelDr7);

	// Point of caller go back to.
	vmx_write(GUEST_RSP, ctx->Rsp);
	vmx_write(GUEST_RIP, ctx->Rip);
	vmx_write(GUEST_RFLAGS, ctx->EFlags);

	// Setup monitor stack and entrypoint (entry.S)
	vmx_write(HOST_RSP, (ULONG_PTR)cpu->stack + sizeof(cpu->stack));
	vmx_write(HOST_RIP, (ULONG_PTR)vmx_entry);

	// And finally, switch to VM.
	*status = 1;
	__vmx_vmlaunch();
}

static int start(void *pgtables)
{
	volatile KPROCESSOR_STATE state;
	volatile int status = -1;

	// We loop back on failure to this point (with `status` changed).
	BARRIER();
	KeSaveStateForHibernate(&state);
	RtlCaptureContext(&state->ContextFrame);
	BARRIER();

	// Failure?
	if (!status)
		return 0;

	if (status == -1) {
		vmx_setup(&state, (ULONG64)pgtables, &status);
		RtlRestoreContext(&state->ContextFrame);
	}
	return status;
}

// Synchronized start/stop routine.
static void startstop(PRKDPC dpc, void *context, void *sig, void *sync)
{
	if (!context) {
		int dummy[4];
		__cpuidex(dummy, VMX_BACKDOOR1, VMX_BACKDOOR2);
	} else vmx_start(context);
	KeSignalCallDpcSynchronize(sync);
	KeSignalCallDpcDone(sig);
}

int vmx_start()
{
	PHYSICAL_ADDRESS limit = {.QuadPart = ~0LL};
	ULONG64 feat;
	int cpuid[4] = {0};

	// VM-x supported?
	__cpuid(cpuid,1);
	if (!(cpu_info[2] & 0x20))
		return 0;
	__cpuidex(dummy, VMX_BACKDOOR1, VMX_BACKDOOR2+1);
	if (cpuid[0] = VMX_BACKDOOR22)
		return 0;
	feat = __readmsr(IA32_FEATURE_CONTROL_MSR);
	if (!(feat & IA32_FEATURE_CONTROL_MSR_LOCK))
		return 0;
	if (!(feat & IA32_FEATURE_CONTROL_MSR_ENABLE_VMXON_OUTSIDE_SMX))
		return 0;

	// Allocate stack pages.
	ncpu = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	for (int i = 0; i < ncpu; i++) {
		struct stack *p = MmAllocateContiguousNodeMemory(sizeof(stacks[0]), limit);
		if (!p) {
			for (int j = 0; j < i; j++) {
				MmFreeContiguousMemory(stacks[i]);
				return 0;
			}
		}
		memset(p, 0, sizeof(stack[0]));
		stacks[i] = p;
	}

	KeGenericCallDpc(startstop, (void*)__readcr3());
}

int vmx_stop()
{
	KeGenericCallDpc(startstop, NULL);
}

static void stop_vm(CONTEXT *ctx)
{
	percpu_t *cpu = CTX2CPU(ctx);

	// Restore original table descriptors as VMX will trash it.
	__lgdt(&cpu->gdtr.Limit);
	__lidt(&cpu->idtr.Limit);

	// Make the virtualized context "real" again.
	__writecr3(vmx_read(GUEST_CR3));
	ctx->Rsp = vmx_read(GUEST_RSP);
	ctx->Rip = vmx_read(GUEST_RIP);
	ctx->SegEs = vmx_read(GUEST_ES_SELECTOR);
	ctx->SegCs = vmx_read(GUEST_CS_SELECTOR);
	ctx->SegSs = vmx_read(GUEST_SS_SELECTOR);
	ctx->SegDs = vmx_read(GUEST_DS_SELECTOR);
	ctx->SegFs = vmx_read(GUEST_FS_SELECTOR);
	ctx->SegGs = vmx_read(GUEST_GS_SELECTOR);

	// Now turn off vmx.
	__vmx_off();

	// These can become non-VMX friendly again.
	__writecr0(cpu->cr0);
	__writecr4(cpu->cr4);
}

void vmx_dispatch(CONTEXT *ctx, ULONG64 saved_cx)
{
	KIRQL irql;
	ULONG reason, currvm, caller_vm;
	percpu_t *cpu = CTX2CPU(ctx);

	KeRaiseIrql(HIGH_LEVEL, &irql);
	ctx->CX = saved_cx;
	ctx->SP -= 0x28;

	reason = vmx_read(VM_EXIT_REASON) & 0xffff;
	inkernel = (vmx_read(GUEST_CS_SELECTOR) & RPL_MASK) == DPL_SYSTEM;

	currvm = __vmx_vmptrld(&phys_g);
	switch (reason) {
		case EXIT_REASON_CPUID: {
			if (inkernel && (ctx->Rax == VMX_BACKDOOR1)
					&& (ctx->Rcx == VMX_BACKDOOR2)) {
				stop_vm();
				break;
			}
			__cpuidex(info, (INT)ctx->Rax, (INT)ctx->Rcx);
			ctx->Rax = info[0];
			ctx->Rbx = info[1];
			ctx->Rcx = info[2];
			ctx->Rdx = info[3];
			break;
		case EXIT_REASON_XSETBV:
			_xsetbv(ctx->Rcx, ctx->Rdx << 32 | ctx->rax);
			break;
		case EXIT_REASON_VMCALL:
			set_guest_cf();
			break;
			// Launch stored subvm
		case EXIT_REASON_VMLAUNCH:
		case EXIT_REASON_VMRESUME:

		case EXIT_REASON_VMPTRLD:
		case EXIT_REASON_VMPTRST:
		case EXIT_REASON_VMREAD:
		case EXIT_REASON_VMWRITE:

			// Ignored
		case EXIT_REASON_VMCLEAR:
			vmx_clear(&ctx->subvm->vmcs);
		case EXIT_REASON_VMXOFF:
		case EXIT_REASON_VMXON:
			break;
		}
	}
	vm_write(GUEST_RIP, vm_read(GUEST_RIP) + vm_read(VM_EXIT_INSTRUCTION_LEN));
out_resume:;
	ctx->IP = &vmx_resume;
	RtlRestoreContext(ctx, NULL);
}

void vmx_sub_dispatch(CONTEXT *ctx, ULONG_PTR saved_cx)
{
	KIRQL irql;
	percpu_t *cpu = CTX2CPU(ctx);
	ctx->CX = saved_cx;
	ctx->SP -= 0x28;

	KeRaiseIrql(HIGH_LEVEL, &irql);

	// This is inside of a subvm, switch to parent, and let em handle it.
	vmx_ptrl(&ctx->vm0);
	vm_write(GUEST_RIP, ctx->subvm->ip);
	vm_write(GUEST_SS, ctx->subvm->ss);
	ctx->IP = &vmx_resume;

	KeLowerIrql(irql);

	RtlRestoreContext(ctx, NULL);
}

