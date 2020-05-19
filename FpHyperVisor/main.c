#include "helpers.h"
#include <ntddk.h>
#include "vmx.h"



VOID UnLoadDriver(PDRIVER_OBJECT pDriverObject)
{
	PDEVICE_OBJECT pDevObj;
	UNICODE_STRING sysLinkName;
	kprintf("unload!");
	VmxTermination();


}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING pPath)
{
	PAGED_CODE();

	kprintf("DriverEntry");
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);


	DriverObject->DriverUnload = UnLoadDriver;
	if (!VmxInit())
	{
		return STATUS_UNSUCCESSFUL;
	}

	VmxStart();



	return STATUS_SUCCESS;
}









