#pragma once
#ifndef _EPT_H
#define _EPT_H
#include <ntddk.h>
#include "ia32.h"



#include <pshpack1.h>
typedef struct _MtrrData {
	BOOLEAN enabled;        //!< Whether this entry is valid
	BOOLEAN fixedMtrr;      //!< Whether this entry manages a fixed range MTRR
	UCHAR type;          //!< Memory Type (such as WB, UC)
	BOOLEAN reserverd1;     //!< Padding
	ULONG reserverd2;    //!< Padding
	ULONG64 range_base;  //!< A base address of a range managed by this entry
	ULONG64 range_end;   //!< An end address of a range managed by this entry
}MtrrData;
#include <poppack.h>

typedef struct _PhysicalMemoryRun {
	ULONG_PTR base_page;   //!< A base address / PAGE_SIZE (ie, 0x1 for 0x1000)
	ULONG_PTR page_count;  //!< A number of pages
}PhysicalMemoryRun;

typedef struct _PhysicalMemoryDescriptor {
	PFN_COUNT number_of_runs;    //!< A number of PhysicalMemoryDescriptor::run
	PFN_NUMBER number_of_pages;  //!< A physical memory size in pages
	PhysicalMemoryRun run[1];    //!< ranges of addresses
}PhysicalMemoryDescriptor;



PhysicalMemoryDescriptor *
UtilpBuildPhysicalMemoryRanges();
extern PhysicalMemoryDescriptor* g_utilp_physical_memory_ranges;

BOOLEAN EptIsEptAvailable();
EptData *EptInitialization();
void EptTermination(EptData *ept_data);
void EptInitializeMtrrEntries();

EptCommonEntry *EptpConstructTables(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address,
	EptData *ept_data);
void EptpDestructTables(EptCommonEntry *table,
	ULONG table_level);
void EptpFreeUnusedPreAllocatedEntries(
	EptCommonEntry **preallocated_entries, long used_count);
void EptpInitTableEntry(
	EptCommonEntry *entry, ULONG table_level, ULONG64 physical_address);

EptCommonEntry *EptpGetEptPtEntry(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address);
EptCommonEntry *EptGetEptPtEntry(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address);

EptCommonEntry *EptpAllocateEptEntry(
	EptData *ept_data);

ULONG64 EptpAddressToPxeIndex(
	ULONG64 physical_address);
ULONG64 EptpAddressToPteIndex(
	ULONG64 physical_address);
ULONG64 EptpAddressToPdeIndex(
	ULONG64 physical_address);
ULONG64 EptpAddressToPpeIndex(
	ULONG64 physical_address);

UCHAR EptpGetMemoryType(
	ULONG64 physical_address);
BOOLEAN EptpIsDeviceMemory(
	ULONG64 physical_address);




#endif // !_EPT_H
