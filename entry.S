.intel_syntax noprefix
.globl vmx_dispatch
vmx_entry:
	push 	rcx
	lea 	rcx, [rsp+0x28]
	call 	RtlCaptureContext
	pop 	rdx
	jmp 	vmx_dispatch

vmx_sub_entry:
	push 	rcx
	lea 	rcx, [rsp+0x28]
	call 	RtlCaptureContext
	pop 	rdx
	jmp 	vmx_dispatch
