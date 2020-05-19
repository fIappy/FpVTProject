#include <ntddk.h>
#include "helpers.h"
#include "ia32.h"
#include "AsmVmx.h"

PVOID kmalloc(ULONG_PTR size)
{
	PHYSICAL_ADDRESS p = { -1 };
	return MmAllocateContiguousMemory(size,p);
}

void kfree(ULONG_PTR p)
{
	MmFreeContiguousMemory(p);
}


void SetPageBits(PVOID buf, ULONG loc, ULONG num)
{
	RTL_BITMAP bitmap = { 0 };

	RtlInitializeBitMap(&bitmap, buf, PAGE_SIZE * 8);
	RtlSetBits(&bitmap, loc, num);
}

void SetLONGBits(PVOID buf, ULONG loc, ULONG num)
{
	RTL_BITMAP bitmap = { 0 };

	RtlInitializeBitMap(&bitmap, buf, sizeof(ULONG) * 8);
	RtlSetBits(&bitmap, loc, num);
}


void SetLONG64Bits(PVOID buf, ULONG loc, ULONG num)
{
	RTL_BITMAP bitmap = { 0 };

	RtlInitializeBitMap(&bitmap, buf, sizeof(ULONG64) * 8);
	RtlSetBits(&bitmap, loc, num);
}

ULONG64 UtilPaFromVa(void *va) 
{
	PHYSICAL_ADDRESS pa = MmGetPhysicalAddress(va);
	return pa.QuadPart;
}

ULONG64 UtilVaFromPa(void *addr)
{
	PHYSICAL_ADDRESS pa = { addr };
	return MmGetVirtualForPhysical(pa);

}


PFN_NUMBER UtilPfnFromPa(ULONG64 pa) {
	return pa >> PAGE_SHIFT;
}

void *UtilVaFromPfn(PFN_NUMBER pfn) {
	return UtilVaFromPa(UtilPaFromPfn(pfn));
}

ULONG64 UtilPaFromPfn(PFN_NUMBER pfn) {
	return (ULONG64)(pfn) << PAGE_SHIFT;
};


BOOLEAN UtilForEachProcessor(BOOLEAN(*callback_routine)(void *), void *context) 
{
	PAGED_CODE()

	const ULONG number_of_processors =KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	BOOLEAN status=TRUE;

	for (ULONG processor_index = 0; processor_index < number_of_processors;
		processor_index++) {
		PROCESSOR_NUMBER processor_number = {0};
	
		if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processor_index, &processor_number)))
		{
			return FALSE;
		}

		// Switch the current processor
		GROUP_AFFINITY affinity = {0};
		affinity.Group = processor_number.Group;
		affinity.Mask = 1ull << processor_number.Number;
		GROUP_AFFINITY previous_affinity = {0};
		KeSetSystemGroupAffinityThread(&affinity, &previous_affinity);

		// Execute callback
		status = callback_routine(context);

		KeRevertToUserGroupAffinityThread(&previous_affinity);
		if (!status)
		{
			return FALSE;
		}
	}
	return TRUE;
}


BOOLEAN UtilVmPtrld(ULONG_PTR pPhysicalVmcs)
{
	ULONG_PTR p = pPhysicalVmcs;
	int status = __vmx_vmptrld(&p);
	ULONG errorCode = 0;
	if (!status)
	{
		return TRUE;
	}

	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if(status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d",errorCode);
		return FALSE;
	}
	return TRUE;
}
BOOLEAN UtilVmPtrst(ULONG_PTR* pPhysicalBuf)
{
	__try
	{
		__vmx_vmptrst(pPhysicalBuf);

	}
	__except (1)
	{
		return FALSE;
	}
	return TRUE;
}
BOOLEAN UtilVmClear(ULONG_PTR pPhysicalVmcs)
{
	ULONG_PTR p = pPhysicalVmcs;
	int status = __vmx_vmclear(&p);
	ULONG errorCode = 0;
	if (!status)
	{
		return TRUE;
	}

	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}
BOOLEAN UtilVmxOn(ULONG_PTR pPhysicalVmxon)
{
	ULONG_PTR p = pPhysicalVmxon;
	int status = __vmx_on(&p);
	ULONG errorCode = 0;
	if (!status)
	{
		return TRUE;
	}
	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN UtilVmLaunch()
{
	int status = __vmx_vmlaunch();
	ULONG errorCode = 0;
	if (!status)
	{
		return TRUE;
	}
	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}
BOOLEAN UtilVmResume()
{
	int status = __vmx_vmresume();
	ULONG errorCode = 0;
	if (!status)
	{
		return TRUE;
	}
	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN UtilVmxWrite(ULONG_PTR field, ULONG_PTR value)
{
	int status = __vmx_vmwrite(field, value);
	ULONG errorCode = 0;
	if (!status)
	{
		return TRUE;
	}
	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN UtilInveptGlobal() {
	InvEptDescriptor desc = {0};
	int status = AsmInvept(kGlobalInvalidation, &desc);
	ULONG errorCode = 0;

	if (!status)
	{
		return TRUE;
	}
	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}

BOOLEAN UtilInvvpidAllContext() {
	InvVpidDescriptor desc = {0};
	int status = AsmInvvpid(kAllContextInvalidation, &desc);
	ULONG errorCode = 0;

	if (!status)
	{
		return TRUE;
	}
	else if (status == 1)
	{
		kprintf("VMfailValid");
		return FALSE;
	}
	else if (status == 2)
	{
		__vmx_vmread(VmVMInstructionError, &errorCode);
		kprintf("VMfailValid %d", errorCode);
		return FALSE;
	}
	return TRUE;
}



BOOLEAN UtilIsInBounds(_In_ const ULONG_PTR value, _In_ const ULONG_PTR min,
	_In_ const ULONG_PTR max) {
	return (min <= value) && (value <= max);
}