// A tiny VMX hypervisor. It is "bluepilled", that is, with VM nesting support.
//
// Heavily inspired by simplevisor [1], but with most of the educational
// cruft removed.
//
// [1] https://github.com/ionescu007/SimpleVisor/

static UCHAR msr_bitmap[PAGE_SIZE];
static stack_t *stacks[64];

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

// Copy current machine state into a guest, and start that guest.
static void vmsetup(KPROCESSOR_STATE *state, ULONG64 pgtables, int *status)
{
#define MSR(n) msr[MSR_IA32_VMX_##n]
#define ADJUST_MSR(target, mask,val) \
	vmx_write(target, (((val) & MSR(n).HighPart) | MSR(n).LowPart))

	LARGE_INTEGER msr[17];
	ULONG_PTR vmxon, vmcs0, msr, shadowing = 0;
	KSPECIAL_REGISTERS *regs = &state->SpecialRegisters;
	ULONG cr0, cr4;
	CONTEXT *ctx = &state->ContextFrame;
	percpu_t *cpu = stacks[CURR_CPU];

	*status = 0;

	// Read all MSRs in bulk, for easier indexing later.
	for (int i = 0; i < 17; i++)
		msr[i] = __readmsr(MSR_IA32_VMX_BASIC + i);

	// Feature checks.
	if (MSR(BASIC).HighPart > PAGE_SIZE)
		return;

	if (((MSR(BASIC).QuadPart & VMX_BASIC_MEMORY_TYPE_MASK) >> 50) != MTRR_TYPE_WB)
		return;

	if (!(MSR(BASIC).QuadPart & VMX_BASIC_DEFAULT1_ZERO))
		return;
#if ENABLE_VMCS_SHADOWING
	shadowing = MSR(MISC).LowPart & SECONDARY_EXEC_ENABLE_VMCS_SHADOWING;
#endif

	// Prepare host/guest VMCS.
	vmcs_h.rev = vmcs_g.rev = msr[0].LowPart;
	vmxon = MmGetPhysicalAddress(&cpu->vmcs_vmxon).QuadPart;
	cpu->vm0 = vm0 = MmGetPhysicalAddress(&cpu->vmcs_vm0).QuadPart;
 	msr = MmGetPhysicalAddress(&msr_bitmap).QuadPart;

	// Clean up CR as VMX dictates.
	cr0 = MSR0(CR0_FIXED).LowPart | (regs->Cr0 & MSR(CR0_FIXED1).LowPart);
	__writecr0(cr0);
	cr4 = msr[8].LowPart | (regs->Cr4 & msr[9].LowPart);
	__writecr4(cr4);

	if (vmx_on(&vmxon))
		return;

	if (vmx_clear(&vm0))
		return;

	if (vmx_ptrld(&vm0)) {
		vmx_off();
		return;
	}

	// Create the guest state now by copying current processor state.
	vmx_write(VMCS_LINK_POINTER, MAXULONG64);
	vmx_write(MSR_BITMAP, msr);
#if ENABLE_VMCS_SHADOWING
	vmx_write(VMREAD_BITMAP, msr);
	vmx_write(VMWRITE_BITMAP, msr);
#endif

	// Enable RDTSCP and XSAVE. Maybe shadowing too.
	ADJUST(SECONDARY_VM_EXEC_CONTROL, PROCBASED_CTLS2,
		SECONDARY_EXEC_ENABLE_RDTSCP|SECONDARY_EXEC_XSAVES|shadowing);

	ADJUST(PIN_BASED_VM_EXEC_CONTROL, TRUE_PINBASED_CTLS, 0);

	// Activate MSR bitmap (whic will be all 0, so no triggers).
	ADJUST(CPU_BASED_VM_EXEC_CONTROL, TRUE_PROCBASED_CTLS, 
		CPU_BASED_ACTIVATE_MSR_BITMAP|CPU_BASED_ACTIVATE_SECONDARY_CONTROLS);

	// Run interrupts on exit, exit into long mode.
	ADJUST(VM_EXIT_CONTROLS, TRUE_EXIT_CTLS,
		VM_EXIT_ACK_INTR_ON_EXIT|VM_EXIT_IA32E_MODE);

	// Entry in long mode too.
	ADJUST(VM_ENTRY_CONTROLS,  TRUE_ENTRY_CTLS,
		VM_ENTRY_IA32E_MODE);

	// Now copy all selectors into guest state.
	copy_selector(state, GUEST_ES_BASE, ctx->SegFs);
	copy_selector(state, GUEST_CS_BASE, ctx->SegCs);
	copy_selector(state, GUEST_SS_BASE, ctx->SegSs);
	copy_selector(state, GUEST_DS_BASE, ctx->SegDs);

	copy_selector(state, GUEST_FS_BASE, ctx->SegFs);
	copy_selector(state, GUEST_GS_BASE, ctx->SegGs);

	copy_selector(state, GUEST_TR_BASE, regs->Tr);
	copy_selector(state, GUEST_LDTR_BASE, regs->Ldtr);

	// GDT and IDT too. Save those as well, as vmxon will trash em.
	stack->cpu.gdtr = regs->Gdtr;
	vmx_write(GUEST_GDTR_BASE, (ULONG_PTR)regs->Gdtr.Base);
	vmx_write(GUEST_GDTR_LIMIT, regs->Gdtr.Limit);
	vmx_write(HOST_GDTR_BASE, (ULONG_PTR)regs->Gdtr.Base);

	stack->cpu.idtr = regs->Idtr;
	vmx_write(GUEST_IDTR_BASE, (ULONG_PTR)regs->Idtr.Base);
	vmx_write(GUEST_IDTR_LIMIT, regs->Idtr.Limit);
	vmx_write(HOST_IDTR_BASE, (ULONG_PTR)regs->Idtr.Base);

	// Now CR0 and CR4.
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

	// Debug regs.
	vmx_write(GUEST_IA32_DEBUGCTL, regs->DebugControl);
	vmx_write(GUEST_DR7, regs->KernelDr7);

	// Point of caller go back to.
	vmx_write(GUEST_RSP, ctx->Rsp);
	vmx_write(GUEST_RIP, ctx->Rip);
	vmx_write(GUEST_RFLAGS, ctx->EFlags);

	// Setup monitor stack and entrypoint (entry.S)
	vmx_write(HOST_RSP, (ULONG_PTR)cpu->stack + sizeof(cpu->stack));
	vmx_write(HOST_RIP, (ULONG_PTR)vmx_entry);

	// And finally, switch to a VM.
	*status = 1;
	if (__vmx_vmlaunch()) {
		// Failed. Restore CR.
		__writecr0(stack->cpu.cr0);
		__writecr4(stack->cpu.cr4);
		*status = 0;
	}
#undef MSR
#undef ADJUST_MSR
}

// Switch to VM mode (called per cpu).
static int start(void *pgtables)
{
	volatile KPROCESSOR_STATE state;
	volatile int status = -1;

	BARRIER();
	KeSaveStateForHibernate(&state);
	// We loop back to this point (with `status` changed).
	RtlCaptureContext(&state->ContextFrame);
	BARRIER();

	// Didn't try yet.
	if (status == -1)
		vmsetup(&state, (ULONG64)pgtables, &status);

	return status;
}

// Synchronized start/stop DPC.
static void startstop(PRKDPC dpc, void *context, void *sig, void *sync)
{
	if (!context) {
		int dummy[4];
		__cpuidex(dummy, VMX_BACKDOOR1, VMX_BACKDOOR2);
	} else start(context);
	KeSignalCallDpcSynchronize(sync);
	KeSignalCallDpcDone(sig);
}

// Allocate needed structures, and launch VM on all CPUs.
int vmx_start()
{
	PHYSICAL_ADDRESS limit = {.QuadPart = ~0LL};
	ULONG64 feat;
	int cpuid[4] = {0};
	int ncpu;

	// VM-x supported?
	__cpuid(cpuid,1);
	if (!(cpu_info[2] & 0x20))
		return 0;

	// Already present?
	__cpuidex(dummy, VMX_BACKDOOR1, VMX_BACKDOOR2+1);
	if (cpuid[0] = VMX_BACKDOOR22)
		return 0;

	feat = __readmsr(IA32_FEATURE_CONTROL_MSR);

	// BIOS locked.
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

// Deliver DPC with our backdoor stop CPUID.
int vmx_stop()
{
	KeGenericCallDpc(startstop, NULL);
}

static void vmstop(CONTEXT *ctx)
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
				vmstop();
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
	KeLowerIrql(irql);
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

