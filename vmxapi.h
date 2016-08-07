#include <windows.h>
#include <winternl.h>
#define VMX_API

VMX_API
UCHAR vmx_write(ULONG_PTR vmxop, ULONG_PTR data)
{
	UCHAR cf;
	asm("vmwrite %1, %2; setc %0"
		: "=rm" (cf)
		: "rm" ((ULONG_PTR) data), "r" (vmxop)
		: "cc");
	return cf;
}

VMX_API
UCHAR vmx_read_check(ULONG_PTR vmxop, ULONG_PTR *data)
{
	UCHAR cf;
	asm("vmread %2, %1; setc %0"
		: "=rm" (cf), "=rm" (*data)
		: "r" (vmxop)
		: "cc");
	return cf;
}

VMX_API
ULONG_PTR vmx_read(ULONG_PTR vmxop)
{
	ULONG_PTR data;
	asm("vmread %1, %0"
		: "=rm" (data)
		: "r" (vmxop)
		: "cc");
	return data;
}

VMX_API
UCHAR vmx_clear(void *vmcs)
{
	UCHAR cf;
	asm("vmclear %1; setc %0"
		: "=rm"(cf)
		: "m" (*(ULONG_PTR*)vmcs)
		: "cc");
	return cf;
}

VMX_API
UCHAR vmx_ptrld(void *vmcs)
{
	UCHAR cf;
	asm("vmptrld %1; setc %0"
		: "=rm"(cf)
		: "m" (*(ULONG_PTR*)vmcs)
		: "cc");
	return cf;
}

VMX_API
UCHAR vmx_ptrst(void *vmcs)
{
	UCHAR cf;
	asm("vmptrst %1; setc %0"
		: "=rm"(cf)
		: "m" (*(ULONG_PTR*)vmcs)
	: "cc");
	return cf;
}

VMX_API
UCHAR vmx_on(void *vmcs)
{
	UCHAR cf;
	asm("vmxon %1; setc %0"
		: "=rm"(cf)
		: "m" (*(ULONG_PTR*)vmcs)
		: "cc");
	return cf;
}

VMX_API
UCHAR vmx_off()
{
	UCHAR cf;
	asm("vmxoff; setc %0"
		: "=rm"(cf)
		:
		: "cc");
	return cf;
}

VMX_API
UCHAR vmx_resume()
{
	UCHAR cf;
	asm("vmresume; setc %0"
		: "=rm"(cf)
		:
		: "cc");
	return cf;
}

VMX_API
UCHAR vmx_launch()
{
	UCHAR cf;
	asm("vmresume; setc %0"
		: "=rm"(cf)
		:
		: "cc");
	return cf;
}

VMX_API
ULONG_PTR get_segment_limit(ULONG_PTR sel)
{
	ULONG_PTR limit;
	asm volatile ("lsl %1,%0"
	: "=r" (limit)
	: "rm" ((ULONG)sel));
	return limit;
}

