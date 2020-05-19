#include "exithandler.h"
#include "ia32.h"
#include "helpers.h"
#include "AsmVmx.h"
#include "vmx.h"
#include "ept.h"
#include <ntddk.h>
#include <intrin.h>

BOOLEAN VmxVmexitHandler(GpRegisters* pGuestRegisters)
{
	KIRQL irql= KeGetCurrentIrql();
	if (irql < DISPATCH_LEVEL) {
		KeRaiseIrqlToDpcLevel();
	}

	ULONG CurrentProcessorIndex = KeGetCurrentProcessorNumberEx(NULL);
	VmExitInformation ExitReason = { 0 };
	FlagRegister guestRflag = { 0 };
	BOOLEAN ContinueVmx = TRUE;
	ULONG_PTR Rip = 0;
	__vmx_vmread(GuestRip,&Rip);

	__vmx_vmread(VmExitReason, &ExitReason);
	GuestContext guestContext = { pGuestRegisters ,Rip };

	switch (ExitReason.fields.reason)
	{
	case ExitTripleFault:
		kprintf("TripleFault %p",Rip);
		//VmmAdjustGuestRip();
		DbgBreakPoint();
		break;
	case ExitEptMisconfig:
		kprintf("ExitEptMisconfig");
		DbgBreakPoint();
		break;
	case ExitEptViolation:
		//kprintf("ExitEptViolation");
		EptExitHandler(&guestContext);
		break;
	case ExitCrAccess:
	{
		//这种属于指令执行导致的vmexit. 与指令相关信息存放在ExitQualification和VmExitInstructionInformation
		//cr操作数,只支持cr0,3,4
		//另一个是寄存器操作数
		kprintf("ExitCrAccess %p", Rip);
		ExitQualification eq = { 0 };
		__vmx_vmread(VmExitQualification, &eq);

		char crOp = eq.ControlRegisterAccesses.control_register;
		char regOp = eq.ControlRegisterAccesses.gp_register;
		if (eq.ControlRegisterAccesses.access_type==AcMoveToCr)//写操作
		{

		}
		else if (eq.ControlRegisterAccesses.access_type == AcMoveToCr)//读操作
		{

		}
		else
		{
			kprintf("crAccess error");
			DbgBreakPoint();
		}
		break;
	}
	//msr读写必须处理
	case ExitMsrRead:
	{
		ExitQualification eq = { 0 };
		__vmx_vmread(VmExitQualification, &eq);
		LARGE_INTEGER msr = { 0 };
		//if (!(pGuestRegisters->cx <= 0x1fff)
		//	&&!((pGuestRegisters->cx >= 0xc0000000) && (pGuestRegisters->cx <= 0xc0001fff)))
		//{
		//	kprintf("out range ExitMsrRead %08x", pGuestRegisters->cx);

		//	//kprintf("fatal error msr out range %p",Rip);
		//	//DbgBreakPoint();
		//	msr.QuadPart = __readmsr(pGuestRegisters->cx);
		//	pGuestRegisters->ax = msr.LowPart;
		//	pGuestRegisters->dx = msr.HighPart;
		//	VmmAdjustGuestRip();
		//}
		//else
		//{
		//	kprintf("ExitMsrRead");
		//}
		kprintf("ExitMsrRead %d", pGuestRegisters->cx);
		msr.QuadPart = __readmsr(pGuestRegisters->cx);
		pGuestRegisters->ax = msr.LowPart;
		pGuestRegisters->dx = msr.HighPart;
		VmmAdjustGuestRip();
		break;
	}
	case ExitMsrWrite:
	{
		ExitQualification eq = { 0 };
		__vmx_vmread(VmExitQualification, &eq);
		kprintf("ExitMsrWrite");
		LARGE_INTEGER msr = { 0 };

		//if (!(pGuestRegisters->cx <= 0x1fff)
		//	&& !((pGuestRegisters->cx >= 0xc0000000) && (pGuestRegisters->cx <= 0xc0001fff)))
		//{
		///*	kprintf("fatal error msr out range %p", Rip);
		//	DbgBreakPoint();*/
		//	msr.LowPart = pGuestRegisters->ax;
		//	msr.HighPart = pGuestRegisters->dx;
		//	__writemsr(pGuestRegisters->cx, msr.QuadPart);
		//	VmmAdjustGuestRip();
		//}

		msr.LowPart = pGuestRegisters->ax;
		msr.HighPart = pGuestRegisters->dx;
		__writemsr(pGuestRegisters->cx, msr.QuadPart);
		VmmAdjustGuestRip();
		break;
	}
	case ExitCpuid:
	{
		//kprintf("ExitCpuid");
		//访问很频繁
		int leaf = (int)pGuestRegisters->ax;
		int sub_leaf = (int)pGuestRegisters->cx;
		int result[4] = { 0 };
		__cpuidex(&result, leaf, sub_leaf);

		//if (leaf ==1)
		//{
		//	//((CpuFeaturesEcx*)&result[2])->fields.
		//}
		pGuestRegisters->ax = result[0];
		pGuestRegisters->bx = result[1];
		pGuestRegisters->cx = result[2];
		pGuestRegisters->dx = result[3];
		VmmAdjustGuestRip();
		break;
	}
	case ExitIoInstruction:
	{
		kprintf("ExitIoInstruction");
		VmmAdjustGuestRip();
		break;
	}
	case ExitVmcall:
	{
		ContinueVmx = FALSE;
		VmxPrepareOff(pGuestRegisters);
		break;
	}
	case ExitExceptionOrNmi:
	{
		kprintf("ExitExceptionOrNmi");
		VmExitInterruptionInformationField exception = { 0 };
		__vmx_vmread(VmExitInterruptionInformation, &exception);

		if (exception.fields.interruption_type== kHardwareException)
		{
			//VmmpInjectInterruption(exception.fields.interruption_type,)
			exception.fields.valid = TRUE;
			UtilVmxWrite(VmEntryInterruptionInformation, exception.all);
		}
		else if (exception.fields.interruption_type == kSoftwareException)
		{
			UtilVmxWrite(VmEntryInterruptionInformation, exception.all);
			int exit_inst_length = 0;
			__vmx_vmread(VmExitInstructionLength,&exit_inst_length);
			UtilVmxWrite(VmEntryInstructionLength, exit_inst_length);
		}
		break;
	}
	case ExitMonitorTrapFlag:
	{
		kprintf("ExitMonitorTrapFlag");

		break;
	}
	case ExitHlt:
	{
		kprintf("ExitHlt");
		break;
	}
	case ExitVmclear:
	case ExitVmptrld:
	case ExitVmptrst:
	case ExitVmread:
	case ExitVmwrite:
	case ExitVmresume:
	case ExitVmoff:
	case ExitVmon:
	case ExitVmlaunch:
	case ExitVmfunc:
	case ExitInvept:
	case ExitInvvpid:
	{
		kprintf("vm inst");
		__vmx_vmread(GuestRflags, &guestRflag);
		guestRflag.fields.cf = 1;
		UtilVmxWrite(GuestRflags, guestRflag.all);
		VmmAdjustGuestRip();
		break;
	}
	case ExitInvd:
	{
		kprintf("ExitInvd");
		AsmInvd();
		VmmAdjustGuestRip();
		break;
	}
	case ExitInvlpg:
	{
		kprintf("ExitInvlpg");
		ExitQualification eq = { 0 };
		__vmx_vmread(VmExitQualification, &eq);
		InvVpidDescriptor desc = { 0 };
		desc.vpid = CurrentProcessorIndex + 1;
		desc.linear_address= eq.all;
		AsmInvvpid(kIndividualAddressInvalidation,&desc);
		VmmAdjustGuestRip();
		break;
	}
	case ExitRdtsc:
	{
		kprintf("ExitRdtsc");

		ULARGE_INTEGER tsc = {0};
		tsc.QuadPart = __rdtsc();
		pGuestRegisters->dx = tsc.HighPart;
		pGuestRegisters->ax = tsc.LowPart;
		VmmAdjustGuestRip();
		break;
	}
	case ExitRdtscp:
	{
		kprintf("ExitRdtscp");

		unsigned int tsc_aux = 0;
		ULARGE_INTEGER tsc = {0};
		tsc.QuadPart = __rdtscp(&tsc_aux);
		pGuestRegisters->dx = tsc.HighPart;
		pGuestRegisters->ax = tsc.LowPart;
		pGuestRegisters->cx = tsc_aux;
		VmmAdjustGuestRip();
		break;
	}
	case ExitXsetbv:
	{
		kprintf("ExitXsetbv");

		ULARGE_INTEGER value = {0};
		value.LowPart = pGuestRegisters->ax;
		value.HighPart = pGuestRegisters->dx;
		_xsetbv(pGuestRegisters->cx, value.QuadPart);

		VmmAdjustGuestRip();
		break;
	}
	default:
		kprintf("Unexpected Exit %d", ExitReason.fields.reason);
		DbgBreakPoint();
		break;
	}

	if (irql < DISPATCH_LEVEL) {
		KeLowerIrql(irql);
	}

	return ContinueVmx;
}

void VmmAdjustGuestRip()
{
	ULONG instLen = 0;
	ULONG_PTR rip = 0;
	__vmx_vmread(GuestRip, &rip);
	__vmx_vmread(VmExitInstructionLength, &instLen);
	UtilVmxWrite(GuestRip, rip + instLen);
}
void VmmpInjectInterruption(
	ULONG interruption_type, ULONG vector,
	BOOLEAN deliver_error_code, ULONG32 error_code) {
	VmEntryInterruptionInformationField inject = {0};
	inject.fields.valid = TRUE;
	inject.fields.interruption_type =interruption_type;
	inject.fields.vector =vector;
	inject.fields.deliver_error_code = deliver_error_code;
	UtilVmxWrite(VmEntryInterruptionInformation, inject.all);

	if (deliver_error_code) {
		UtilVmxWrite(VmEntryExceptionErrorCode, error_code);
	}
}

