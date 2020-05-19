#pragma once

#ifndef _EXITHANDLER_H
#define _EXITHANDLER_H
#include "ia32.h"
#include "vmx.h"
#include <ntddk.h>



BOOLEAN VmxVmexitHandler(GpRegisters* pGuestRegisters);

void EptExitHandler(GuestContext* pGuestContext);

void VmmpInjectInterruption(
	ULONG interruption_type, ULONG vector,
	BOOLEAN deliver_error_code, ULONG32 error_code);

void VmmAdjustGuestRip();






#endif // !_EXITHANDLER_H
