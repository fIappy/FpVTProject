#include "ia32.h"
#include "vmx.h"
#include "helpers.h"
#include "AsmVmx.h"
#include "ept.h"
#include <ntddk.h>

VCPU *vcpu;
ULONG_PTR g_MsrBitmap;
BOOLEAN VmxInit()
{
	if (!VmxIsSupported())
		return FALSE;

	if (!EptIsEptAvailable())
		return FALSE;


	if (!UtilForEachProcessor(VmxEnableVmxFeature, NULL))
	{
		return FALSE;
	}

	ULONG number_of_processors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
	kprintf("number_of_processors:%d", number_of_processors);
	vcpu = kmalloc(number_of_processors * sizeof(VCPU));
	if (!vcpu)
	{
		kprintf("kmalloc vcpu failed");
		return FALSE;
	}
	RtlSecureZeroMemory(vcpu, number_of_processors*sizeof(VCPU));

	//设置msr位图
	if (!VmxInitMsrBitmap())
	{
		return FALSE;
	}

	//获取mtrrs
	EptInitializeMtrrEntries();

	//获取物理内存范围
	g_utilp_physical_memory_ranges = UtilpBuildPhysicalMemoryRanges();
	if (!g_utilp_physical_memory_ranges)
	{
		return FALSE;
	}
	return TRUE;
}

BOOLEAN VmxInitMsrBitmap()
{
	g_MsrBitmap = kmalloc(PAGE_SIZE);
	if (!g_MsrBitmap)
	{
		kprintf("MsrBitmap malloc failed");
		return FALSE;
	}
	
	RtlZeroMemory(g_MsrBitmap, PAGE_SIZE);
	ULONG_PTR readMsrLow = g_MsrBitmap;
	ULONG_PTR readMsrHigh = readMsrLow + 1024;
	ULONG_PTR writeMsrLow = readMsrHigh + 1024;
	ULONG_PTR writeMsrHigh = writeMsrLow + 1024;

	//SetPageBits(g_MsrBitmap, (MsrLstar & 0x1fff + 1024) * 8, 1);//syscall hook

	return TRUE;
}

BOOLEAN VmxInitVmmStack(VCPU* vcpu)
{
	VCPU* currentVcpu = vcpu;
	PHYSICAL_ADDRESS MaxAddr = { 0 };
	MaxAddr.QuadPart = -1;
	currentVcpu->pVmmStack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, MaxAddr);
	if (!currentVcpu->pVmmStack)
	{
		kprintf("MmAllocateContiguousMemory failed");
		return FALSE;
	}
	RtlSecureZeroMemory(currentVcpu->pVmmStack, KERNEL_STACK_SIZE);
	currentVcpu->pVmmStackBase = (char*)currentVcpu->pVmmStack + KERNEL_STACK_SIZE-0x10;


	return TRUE;
}
BOOLEAN VmxInitVmxon(VCPU* vcpu)
{
	VCPU* currentVcpu = vcpu;

	const Cr0 cr0_fixed0 = { __readmsr(MsrVmxCr0Fixed0) };
	const Cr0 cr0_fixed1 = { __readmsr(MsrVmxCr0Fixed1) };
	Cr0 cr0 = { __readcr0() };
	Cr0 cr0_original = cr0;
	cr0.all &= cr0_fixed1.all;
	cr0.all |= cr0_fixed0.all;
	__writecr0(cr0.all);


	// See: VMX-FIXED BITS IN CR4
	const Cr4 cr4_fixed0 = { __readmsr(MsrVmxCr4Fixed0) };
	const Cr4 cr4_fixed1 = { __readmsr(MsrVmxCr4Fixed1) };
	Cr4 cr4 = { __readcr4() };
	Cr4 cr4_original = cr4;
	cr4.all &= cr4_fixed1.all;
	cr4.all |= cr4_fixed0.all;
	__writecr4(cr4.all);







	PHYSICAL_ADDRESS MaxAddr = { 0 };
	MaxAddr.QuadPart = -1;
	currentVcpu->pVmxonRegion = MmAllocateContiguousMemory(PAGE_SIZE, MaxAddr);
	if (!currentVcpu->pVmxonRegion)
	{
		kprintf("MmAllocateContiguousMemory failed");
		return FALSE;
	}
	RtlSecureZeroMemory(currentVcpu->pVmxonRegion, PAGE_SIZE);
	Ia32VmxBasicMsr msr = { 0 };
	msr.all = __readmsr(MsrVmxBasic);

	*(ULONG*)currentVcpu->pVmxonRegion = msr.fields.revision_identifier;
	if (!UtilVmxOn(UtilPaFromVa(currentVcpu->pVmxonRegion)))
	{
		return FALSE;

	}

	if (UtilInveptGlobal()&& UtilInvvpidAllContext())
	{
		return TRUE;
	}
	
	return FALSE;
}
BOOLEAN VmxInitVmcs(VCPU* vcpu)
{
	VCPU* currentVcpu = vcpu;
	PHYSICAL_ADDRESS MaxAddr = { 0 };
	MaxAddr.QuadPart = -1;
	currentVcpu->pVmcsRegion = MmAllocateContiguousMemory(PAGE_SIZE, MaxAddr);
	if (!currentVcpu->pVmcsRegion)
	{
		kprintf("MmAllocateContiguousMemory failed");
		return FALSE;
	}
	RtlSecureZeroMemory(currentVcpu->pVmcsRegion, PAGE_SIZE);
	Ia32VmxBasicMsr msr = { 0 };
	msr.all = __readmsr(MsrVmxBasic);

	*(ULONG*)currentVcpu->pVmcsRegion = msr.fields.revision_identifier;

	if (!UtilVmClear(UtilPaFromVa(currentVcpu->pVmcsRegion)))
	{
		return FALSE;
	}
	if (!UtilVmPtrld(UtilPaFromVa(currentVcpu->pVmcsRegion)))
	{
		return FALSE;
	}
	
	return TRUE;
}

BOOLEAN VmxIsSupported()
{
	PAGED_CODE();

	//检测cpuid
	ULONG ret[4] = { 0 };
	__cpuid(&ret, 1);
	if (!((CpuFeaturesEcx*)&ret[2])->fields.vmx)
	{
		kprintf("cpu不支持虚拟化");
		return FALSE;
	}
	return TRUE;
}
BOOLEAN VmxEnableVmxFeature(PVOID context)
{



	//检测cr0和开启cr4.vmxe
	Cr0 cr0 = { 0 };
	Cr4 cr4 = { 0 };

	cr0.all = __readcr0();
	if (!cr0.fields.pg|| !cr0.fields.ne||!cr0.fields.pe)
	{
		kprintf("cr0不支持虚拟化");
	}
	cr4.all = __readcr4();
	cr4.fields.vmxe = TRUE;
	__writecr4(cr4.all);




	//对每个cpu开启vmxon指令的限制
	Ia32FeatureControlMsr msr = { 0 };
	msr.all = __readmsr(MsrFeatureControl);
	if (!msr.fields.lock)
	{
		msr.fields.lock = TRUE;
		msr.fields.enable_vmxon = TRUE;
		__writemsr(MsrFeatureControl, msr.all);
		msr.all = __readmsr(MsrFeatureControl);
	}

	
	if (!msr.fields.lock && !msr.fields.enable_vmxon)
	{
		kprintf("BIOS未开启虚拟化");
		return FALSE;
	}
	

}

BOOLEAN VmxStart()
{
	PAGED_CODE();
	if (!UtilForEachProcessor(VmxAsmVmxLaunch, NULL))
	{
		VmxTermination();
		return FALSE;
	}
	kprintf("开启vt成功");
	//DbgBreakPoint();
	return TRUE;
}

BOOLEAN VmxAsmVmxLaunch(void *context)
{
	ULONG currentProcessor = KeGetCurrentProcessorNumberEx(NULL);
	VCPU* CurrentVcpu = &vcpu[currentProcessor];
	if (AsmVmxLaunch())
	{
		CurrentVcpu->IsVmx = TRUE;
		return TRUE;
	}
	return FALSE;
}

BOOLEAN VmxLaunchVm(PVOID guestStack,PVOID guestResumeRip)
{
	ULONG currentProcessor = KeGetCurrentProcessorNumberEx(NULL);
	VCPU* CurrentVcpu = &vcpu[currentProcessor];

	CurrentVcpu->pEptData=EptInitialization();
	if (!CurrentVcpu->pEptData)
		return FALSE;
	if (!VmxInitVmmStack(CurrentVcpu))
		return FALSE;
	
	if (!VmxInitVmxon(CurrentVcpu))
		return FALSE;
	
	if (!VmxInitVmcs(CurrentVcpu))
		return FALSE;

	VmxWriteVmcs(CurrentVcpu, guestStack, guestResumeRip);

	//这个其实不用判断,如果执行成功不可能到这里
	if (!UtilVmLaunch())
	{
		CurrentVcpu->IsVmx = FALSE;
		return FALSE;
	}
	//永远不会执行
	return FALSE;
}

void VmxWriteVmcs(VCPU* currentVcpu, PVOID guestStack, PVOID guestResumeRip)
{

	Ia32VmxBasicMsr vBMsr = { 0 };
	vBMsr.all = __readmsr(MsrVmxBasic);

	//配置基于pin的vm执行控制信息域
	VmxPinBasedControls vm_pinctl_requested = { 0 };
	VmxPinBasedControls vm_pinctl = {
		VmxAdjustControlValue((vBMsr.fields.vmx_capability_hint) ? MsrVmxTruePinbasedCtls
											  : MsrVmxPinbasedCtls,
							  vm_pinctl_requested.all) };
	UtilVmxWrite(PinBasedVmExecutionControls, vm_pinctl.all);
	//配置基于处理器的主vm执行控制信息域
	VmxProcessorBasedControls vm_procctl_requested = { 0 };
	//vm_procctl_requested.fields.cr3_load_exiting = TRUE;//拦截MOV to CR3
	//vm_procctl_requested.fields.cr3_store_exiting = TRUE;//拦截mov from cr3
	//vm_procctl_requested.fields.cr8_load_exiting = TRUE;//拦截mov to cr8
	//vm_procctl_requested.fields.cr8_store_exiting = TRUE;//拦截 mov from cr8
	//vm_procctl_requested.fields.mov_dr_exiting = TRUE; //拦截调试寄存器访问
	//vm_procctl_requested.fields.use_io_bitmaps = TRUE; //拦截io指令
	//vm_procctl_requested.fields.unconditional_io_exiting = TRUE;//无条件拦截io指令
	vm_procctl_requested.fields.use_msr_bitmaps = TRUE;  //拦截msr寄存器访问,必须设置,不然任何访msr的操作都会导致vmexit
	vm_procctl_requested.fields.activate_secondary_control = TRUE;
	VmxProcessorBasedControls vm_procctl = {
		VmxAdjustControlValue((vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueProcBasedCtls
											  : MsrVmxProcBasedCtls,
							  vm_procctl_requested.all) };
	UtilVmxWrite(PrimaryProcessorBasedVmExecutionControls, vm_procctl.all);

	//配置基于处理器的辅助vm执行控制信息域
	VmxSecondaryProcessorBasedControls vm_procctl2_requested = { 0 };
	vm_procctl2_requested.fields.enable_ept = TRUE;//开启ept
	//vm_procctl2_requested.fields.descriptor_table_exiting = TRUE;//拦截LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, STR. 
	vm_procctl2_requested.fields.enable_rdtscp = TRUE;  // for Win10
	vm_procctl2_requested.fields.enable_vpid = TRUE;
	vm_procctl2_requested.fields.enable_invpcid = TRUE;        // for Win10
	vm_procctl2_requested.fields.enable_xsaves_xstors = TRUE;  // for Win10
	VmxSecondaryProcessorBasedControls vm_procctl2 = { VmxAdjustControlValue(
		MsrVmxProcBasedCtls2, vm_procctl2_requested.all) };

	UtilVmxWrite(SecondaryProcessorBasedVmExecutionControls, vm_procctl2.all);

	//配置vm-entry控制域

	VmxVmEntryControls vm_entryctl_requested = { 0 };
	//vm_entryctl_requested.fields.load_debug_controls = TRUE;
	vm_entryctl_requested.fields.ia32e_mode_guest = TRUE; //64系统必须填
	VmxVmEntryControls vm_entryctl = { VmxAdjustControlValue(
		(vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueEntryCtls : MsrVmxEntryCtls,
		vm_entryctl_requested.all) };
	UtilVmxWrite(VmEntryControls, vm_entryctl.all);



	//配置vm-exit控制信息域
	VmxVmExitControls vm_exitctl_requested = { 0 };
	vm_exitctl_requested.fields.host_address_space_size = TRUE;//64系统必须填
	VmxVmExitControls vm_exitctl = { VmxAdjustControlValue(
		(vBMsr.fields.vmx_capability_hint) ? MsrVmxTrueExitCtls : MsrVmxExitCtls,
		vm_exitctl_requested.all) };
	UtilVmxWrite(VmExitControls, vm_exitctl.all);


	//配置其它控制域
	ULONG processor = KeGetCurrentProcessorNumberEx(NULL);
	Cr0 cr0_mask = { 0 };
	Cr0 cr0_shadow = { __readcr0() };

	Cr4 cr4_mask = { 0 };
	Cr4 cr4_shadow = { __readcr4() };
	//用于有条件拦截cr0,cr4的访问
	UtilVmxWrite(Cr0GuestHostMask, cr0_mask.all);
	UtilVmxWrite(Cr4GuestHostMask, cr4_mask.all);
	UtilVmxWrite(Cr0ReadShadow, 0);// cr0_shadow.all);
	UtilVmxWrite(Cr4ReadShadow, 0);// cr4_shadow.all);

	UtilVmxWrite(VirtualProcessorId, processor + 1);

	//error |= UtilVmWrite64(VmcsField::kIoBitmapA, UtilPaFromVa(processor_data->shared_data->io_bitmap_a));
	//error |= UtilVmWrite64(VmcsField::kIoBitmapB, UtilPaFromVa(processor_data->shared_data->io_bitmap_b));
	UtilVmxWrite(MsrBitmap, UtilPaFromVa(g_MsrBitmap));
	UtilVmxWrite(EptPointer, currentVcpu->pEptData->ept_pointer.all);
	ULONG_PTR exception_bitmap = 0;
	UtilVmxWrite(ExceptionBitmap, exception_bitmap);

	//配置guest state,主要是寄存器域
	Gdtr gdtr = { 0 };
	_sgdt(&gdtr);

	Idtr idtr = { 0 };
	__sidt(&idtr);

	UtilVmxWrite(GuestEsSelector, AsmReadES());
	UtilVmxWrite(GuestCsSelector, AsmReadCS());
	UtilVmxWrite(GuestSsSelector, AsmReadSS());
	UtilVmxWrite(GuestDsSelector, AsmReadDS());
	UtilVmxWrite(GuestFsSelector, AsmReadFS());
	UtilVmxWrite(GuestGsSelector, AsmReadGS());
	UtilVmxWrite(GuestLDTRSelector, AsmReadLDTR());
	UtilVmxWrite(GuestTRSelector, AsmReadTR());

	UtilVmxWrite(GuestVmcsLinkPointer, MAXULONG64);
	UtilVmxWrite(GuestIa32DebugCtl, __readmsr(MsrDebugctl));

	UtilVmxWrite(GuestEsLimit, GetSegmentLimit(AsmReadES()));
	UtilVmxWrite(GuestCsLimit, GetSegmentLimit(AsmReadCS()));
	UtilVmxWrite(GuestSsLimit, GetSegmentLimit(AsmReadSS()));
	UtilVmxWrite(GuestDsLimit, GetSegmentLimit(AsmReadDS()));
	UtilVmxWrite(GuestFsLimit, GetSegmentLimit(AsmReadFS()));
	UtilVmxWrite(GuestGsLimit, GetSegmentLimit(AsmReadGS()));
	UtilVmxWrite(GuestLDTRLimit, GetSegmentLimit(AsmReadLDTR()));
	UtilVmxWrite(GuestTRLimit, GetSegmentLimit(AsmReadTR()));
	UtilVmxWrite(GuestGDTRLimit, gdtr.limit);
	UtilVmxWrite(GuestIDTRLimit, idtr.limit);

	UtilVmxWrite(GuestEsAccessRight, VmxGetSegmentAccessRight(AsmReadES()));
	UtilVmxWrite(GuestCsAccessRight, VmxGetSegmentAccessRight(AsmReadCS()));
	UtilVmxWrite(GuestSsAccessRight, VmxGetSegmentAccessRight(AsmReadSS()));
	UtilVmxWrite(GuestDsAccessRight, VmxGetSegmentAccessRight(AsmReadDS()));
	UtilVmxWrite(GuestFsAccessRight, VmxGetSegmentAccessRight(AsmReadFS()));
	UtilVmxWrite(GuestGsAccessRight, VmxGetSegmentAccessRight(AsmReadGS()));
	UtilVmxWrite(GuestLDTRAccessRight, VmxGetSegmentAccessRight(AsmReadLDTR()));
	UtilVmxWrite(GuestTRAccessRight, VmxGetSegmentAccessRight(AsmReadTR()));
	UtilVmxWrite(GuestIa32SYSENTERCS, __readmsr(MsrSysenterCs));

	UtilVmxWrite(GuestCr0, __readcr0());
	UtilVmxWrite(GuestCr3, __readcr3());
	UtilVmxWrite(GuestCr4, __readcr4());

	UtilVmxWrite(GuestEsBase, 0);
	UtilVmxWrite(GuestCsBase, 0);
	UtilVmxWrite(GuestSsBase, 0);
	UtilVmxWrite(GuestDsBase, 0);
	UtilVmxWrite(GuestFsBase, __readmsr(MsrFsBase));
	UtilVmxWrite(GuestGsBase, __readmsr(MsrGsBase));

	UtilVmxWrite(GuestLDTRBase, VmpGetSegmentBase(gdtr.base, AsmReadLDTR()));
	UtilVmxWrite(GuestTRBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	UtilVmxWrite(GuestGDTRBase, gdtr.base);
	UtilVmxWrite(GuestIDTRBase, idtr.base);
	UtilVmxWrite(GuestDr7, __readdr(7));
	UtilVmxWrite(GuestRsp, guestStack);
	UtilVmxWrite(GuestRip, guestResumeRip);
	UtilVmxWrite(GuestRflags, __readeflags());
	UtilVmxWrite(GuestIa32SYSENTERESP, __readmsr(MsrSysenterEsp));
	UtilVmxWrite(GuestIa32SYSENTEREIP, __readmsr(MsrSysenterEip));

	//配置host state
	UtilVmxWrite(HostEsSelector, AsmReadES() & 0xf8);
	UtilVmxWrite(HostCsSelector, AsmReadCS() & 0xf8);
	UtilVmxWrite(HostSsSelector, AsmReadSS() & 0xf8);
	UtilVmxWrite(HostDsSelector, AsmReadDS() & 0xf8);
	UtilVmxWrite(HostFsSelector, AsmReadFS() & 0xf8);
	UtilVmxWrite(HostGsSelector, AsmReadGS() & 0xf8);
	UtilVmxWrite(HostTrSelector, AsmReadTR() & 0xf8);
	UtilVmxWrite(HostIa32SYSENTERCS, __readmsr(MsrSysenterCs));
	UtilVmxWrite(HostCr0, __readcr0());
	UtilVmxWrite(HostCr3, __readcr3());
	UtilVmxWrite(HostCr4, __readcr4());
	UtilVmxWrite(HostFsBase, __readmsr(MsrFsBase));
	UtilVmxWrite(HostGsBase, __readmsr(MsrGsBase));
	UtilVmxWrite(HostTrBase, VmpGetSegmentBase(gdtr.base, AsmReadTR()));
	UtilVmxWrite(HostGDTRBase, gdtr.base);
	UtilVmxWrite(HostIDTRBase, idtr.base);
	UtilVmxWrite(HostIa32SYSENTERESP, __readmsr(MsrSysenterEsp));
	UtilVmxWrite(HostIa32SYSENTEREIP, __readmsr(MsrSysenterEip));
	UtilVmxWrite(HostRsp, currentVcpu->pVmmStackBase);
	UtilVmxWrite(HostRip, AsmVmmEntryPoint);
}

void VmxPrepareOff(GpRegisters* pGuestRegisters)
{
	//DbgBreakPoint();
	// The processor sets ffff to limits of IDT and GDT when VM-exit occurred.
  // It is not correct value but fine to ignore since vmresume loads correct
  // values from VMCS. But here, we are going to skip vmresume and simply
  // return to where VMCALL is executed. It results in keeping those broken
  // values and ends up with bug check 109, so we should fix them manually.
	ULONG_PTR gdt_limit = 0;
	__vmx_vmread(GuestGDTRLimit, &gdt_limit);

	ULONG_PTR gdt_base = 0;
	__vmx_vmread(GuestGDTRBase,&gdt_base);
	ULONG_PTR idt_limit = 0;
	__vmx_vmread(GuestIDTRLimit,&idt_limit);
	ULONG_PTR idt_base = 0;
	__vmx_vmread(GuestIDTRBase,&idt_base);

	Gdtr gdtr = { (USHORT)gdt_limit, gdt_base };
	Idtr idtr = { (USHORT)(idt_limit), idt_base };
	AsmWriteGDT(&gdtr);
	__lidt(&idtr);


	// Set rip to the next instruction of VMCALL
	ULONG_PTR exit_instruction_length = 0;
	__vmx_vmread(VmExitInstructionLength,&exit_instruction_length);
	ULONG_PTR rip = 0;
	__vmx_vmread(GuestRip, &rip);

	ULONG_PTR return_address = rip + exit_instruction_length;

	// Since the flag register is overwritten after VMXOFF, we should manually
	// indicates that VMCALL was successful by clearing those flags.
	// See: CONVENTIONS
	FlagRegister rflags = { 0 };
	__vmx_vmread(GuestRflags, &rflags);

	rflags.fields.cf = FALSE;
	rflags.fields.pf = FALSE;
	rflags.fields.af = FALSE;
	rflags.fields.zf = FALSE;
	rflags.fields.sf = FALSE;
	rflags.fields.of = FALSE;
	rflags.fields.cf = FALSE;
	rflags.fields.zf = FALSE;

	// Set registers used after VMXOFF to recover the context. Volatile
	// registers must be used because those changes are reflected to the
	// guest's context after VMXOFF.
	pGuestRegisters->cx = return_address;
	__vmx_vmread(GuestRsp, &pGuestRegisters->dx);
	pGuestRegisters->ax = rflags.all;

	UtilInveptGlobal();
	UtilInvvpidAllContext();
}

void VmxFreeVmx()
{

	ULONG currentProcessor = KeGetCurrentProcessorNumber();
	VCPU* currentVcpu = &vcpu[currentProcessor];
	if (currentVcpu)
	{
		if (currentVcpu->pVmxonRegion)
		{
			MmFreeContiguousMemory(currentVcpu->pVmxonRegion);
			currentVcpu->pVmxonRegion = 0;
		}
		if (currentVcpu->pVmcsRegion)
		{
			MmFreeContiguousMemory(currentVcpu->pVmcsRegion);
			currentVcpu->pVmcsRegion = 0;
		}
		if (currentVcpu->pVmmStack)
		{
			MmFreeContiguousMemory(currentVcpu->pVmmStack);
			currentVcpu->pVmmStack = 0;
			currentVcpu->pVmmStackBase = 0;
		}
		if (currentVcpu->pEptData)
		{
			EptTermination(currentVcpu->pEptData);
		}
		currentVcpu->pGuestFlagRegister = 0;
		currentVcpu->pGuestGpRegisters = 0;
	}

	
	


}



BOOLEAN VmxTermination()
{
	//需要释放(全局只有一个)的,msr位图,I/O位图,物理内存range描述

	//需要释放每个处理器都对应一份的vmxon,vmcs,vmm stack,ept内存
	//最后是vcpu
	if (UtilForEachProcessor(VmxStopVmx, NULL))
	{
		if (vcpu)
		{
			kfree(vcpu);
			vcpu = 0;
		}
		if (g_utilp_physical_memory_ranges)
		{
			kfree(g_utilp_physical_memory_ranges);
			g_utilp_physical_memory_ranges = 0;
		}
		return TRUE;
	}
	return FALSE;
}

BOOLEAN VmxStopVmx(int context)
{
	if (!vcpu)
	{
		return TRUE;
	}
	ULONG currentProcessor = KeGetCurrentProcessorNumberEx(NULL);

	if (vcpu[currentProcessor].IsVmx)
	{
		kprintf("关闭cpu %d", currentProcessor);
		AsmVmxCall(1, NULL);
		vcpu[currentProcessor].IsVmx = FALSE;
	}

	// Clear CR4.VMXE, as there is no reason to leave the bit after vmxoff
	Cr4 cr4 = { __readcr4() };
	cr4.fields.vmxe = FALSE;
	__writecr4(cr4.all);
	
	VCPU* currentVcpu = &vcpu[currentProcessor];
	if (currentVcpu)
	{
		if (currentVcpu->pVmxonRegion)
		{
			MmFreeContiguousMemory(currentVcpu->pVmxonRegion);
			currentVcpu->pVmxonRegion = 0;
		}
		if (currentVcpu->pVmcsRegion)
		{
			MmFreeContiguousMemory(currentVcpu->pVmcsRegion);
			currentVcpu->pVmcsRegion = 0;
		}
		if (currentVcpu->pVmmStack)
		{
			MmFreeContiguousMemory(currentVcpu->pVmmStack);
			currentVcpu->pVmmStack = 0;
			currentVcpu->pVmmStackBase = 0;
		}
		if (currentVcpu->pEptData)
		{
			EptTermination(currentVcpu->pEptData);
			currentVcpu->pEptData = 0;
		}
		currentVcpu->pGuestFlagRegister = 0;
		currentVcpu->pGuestGpRegisters = 0;
	}
	
	//VmxFreeVmx();
	kprintf("关闭cpu %d 完成", currentProcessor);
	return TRUE;
}


ULONG VmxAdjustControlValue(ULONG Msr, ULONG Ctl)
{
	PAGED_CODE()
		LARGE_INTEGER MsrValue = { 0 };
	MsrValue.QuadPart = __readmsr(Msr);
	Ctl &= MsrValue.HighPart;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.LowPart;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}
ULONG VmxGetSegmentAccessRight(
	USHORT segment_selector) {
	PAGED_CODE()

		VmxRegmentDescriptorAccessRight access_right = {0};
	if (segment_selector) {
		const SegmentSelector ss = { segment_selector };
		ULONG_PTR native_access_right = AsmLoadAccessRightsByte(ss.all);
		native_access_right >>= 8;
		access_right.all = (ULONG)(native_access_right);
		access_right.fields.reserved1 = 0;
		access_right.fields.reserved2 = 0;
		access_right.fields.unusable = FALSE;
	}
	else {
		access_right.fields.unusable = TRUE;
	}
	return access_right.all;
}








ULONG_PTR VmpGetSegmentBase(
	ULONG_PTR gdt_base, USHORT segment_selector) {
	PAGED_CODE()

	SegmentSelector ss = { segment_selector };
	if (!ss.all) {
		return 0;
	}

	if (ss.fields.ti) {
		SegmentDescriptor* local_segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, AsmReadLDTR());
		ULONG_PTR  ldt_base =
			VmpGetSegmentBaseByDescriptor(local_segment_descriptor);


		SegmentDescriptor*  segment_descriptor =
			VmpGetSegmentDescriptor(ldt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
	else {
		SegmentDescriptor*  segment_descriptor =
			VmpGetSegmentDescriptor(gdt_base, segment_selector);
		return VmpGetSegmentBaseByDescriptor(segment_descriptor);
	}
}

SegmentDescriptor *VmpGetSegmentDescriptor(
	ULONG_PTR descriptor_table_base, USHORT segment_selector) {
	PAGED_CODE()

		const SegmentSelector ss = { segment_selector };
	return (SegmentDescriptor *)(
		descriptor_table_base + ss.fields.index * sizeof(SegmentDescriptor));
}


ULONG_PTR VmpGetSegmentBaseByDescriptor(
	const SegmentDescriptor *segment_descriptor) {
	PAGED_CODE()

	// Calculate a 32bit base address
	const ULONG_PTR base_high = { segment_descriptor->fields.base_high << (6 * 4) };
	const ULONG_PTR base_middle = { segment_descriptor->fields.base_mid << (4 * 4) };
	const ULONG_PTR base_low = { segment_descriptor->fields.base_low };

	ULONG_PTR base = (base_high | base_middle | base_low) & MAXULONG;
	// Get upper 32bit of the base address if needed
	if (!segment_descriptor->fields.system) {
		SegmentDesctiptorX64 *desc64 =
			(const SegmentDesctiptorX64 *)(segment_descriptor);
		ULONG64 base_upper32 = desc64->base_upper32;
		base |= (base_upper32 << 32);
	}
	return base;
}










