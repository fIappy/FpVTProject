#pragma once
#include <ntddk.h>
#include <intrin.h>


#define kprintf(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID,DPFLTR_ERROR_LEVEL,\
"[VTPlatform][%d][%s][%d]: " format "\n",PsGetCurrentProcessId(),__FUNCTION__,__LINE__, ##__VA_ARGS__)


PVOID kmalloc(ULONG_PTR);
void kfree(ULONG_PTR);


void SetPageBits(PVOID buf, ULONG loc, ULONG num);
void SetLONGBits(PVOID buf, ULONG loc, ULONG num);
void SetLONG64Bits(PVOID buf, ULONG loc, ULONG num);
ULONG64 UtilVaFromPa(void *addr);
ULONG64 UtilPaFromVa(void *va);
BOOLEAN UtilForEachProcessor(BOOLEAN(*callback_routine)(void *), void *context);





BOOLEAN UtilVmPtrld(ULONG_PTR);
BOOLEAN UtilVmPtrst(ULONG_PTR*);
BOOLEAN UtilVmClear(ULONG_PTR);
BOOLEAN UtilVmxOn(ULONG_PTR);
BOOLEAN UtilVmLaunch();
BOOLEAN UtilVmResume();
BOOLEAN UtilVmxWrite(ULONG_PTR,ULONG_PTR);
BOOLEAN UtilInveptGlobal();
BOOLEAN UtilInvvpidAllContext();
BOOLEAN UtilIsInBounds(_In_ const ULONG_PTR value, _In_ const ULONG_PTR min,
	_In_ const ULONG_PTR max);
PFN_NUMBER UtilPfnFromPa(ULONG64 pa);
void *UtilVaFromPfn(PFN_NUMBER pfn);

ULONG64 UtilPaFromPfn(PFN_NUMBER pfn);
