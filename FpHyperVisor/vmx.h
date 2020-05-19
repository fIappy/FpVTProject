#pragma once
#ifndef _VMX_H
#define _VMX_H
#include "ia32.h"
#include "ept.h"

typedef struct _VCPU
{
	BOOLEAN IsVmx;
	EptData* pEptData;
	PVOID pVmxonRegion;
	PVOID pVmcsRegion;
	PVOID pVmmStack;
	PVOID pVmmStackBase;
	PVOID pMsrBitmap;
	PVOID pIoBitmap;
	GpRegisters* pGuestGpRegisters;
	FlagRegister* pGuestFlagRegister;
}VCPU;
typedef struct _GuestContext
{
	GpRegisters* pGuestRegisters;
	ULONG_PTR rip;
}GuestContext;


extern VCPU *vcpu;
extern ULONG_PTR g_MsrBitmap;
BOOLEAN VmxInit();
BOOLEAN VmxStart();
BOOLEAN VmxEnableVmxFeature(PVOID context);
BOOLEAN VmxIsSupported();
BOOLEAN VmxInitMsrBitmap();
BOOLEAN VmxAsmVmxLaunch(void *context);
BOOLEAN VmxLaunchVm(PVOID guestStack, PVOID guestResumeRip);
BOOLEAN VmxInitVmmStack(VCPU* vcpu);
BOOLEAN VmxInitVmxon(VCPU* vcpu);
void VmxWriteVmcs(VCPU* vcpu, PVOID guestStack, PVOID guestResumeRip);
BOOLEAN VmxInitVmcs(VCPU* vcpu);
void VmxFreeVmx();
void VmxPrepareOff(GpRegisters* pGuestRegisters);
ULONG VmxAdjustControlValue(ULONG Msr, ULONG Ctl);


ULONG_PTR VmpGetSegmentBaseByDescriptor(
	const SegmentDescriptor *segment_descriptor);
SegmentDescriptor *VmpGetSegmentDescriptor(
	ULONG_PTR descriptor_table_base, USHORT segment_selector);

ULONG_PTR VmpGetSegmentBase(
	ULONG_PTR gdt_base, USHORT segment_selector);
ULONG VmxGetSegmentAccessRight(
	USHORT segment_selector);

BOOLEAN VmxTermination();
BOOLEAN VmxStopVmx();












#endif // !_VMX_H



