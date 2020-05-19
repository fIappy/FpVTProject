#include "ept.h"
#include "helpers.h"
#include "ia32.h"
#include "vmx.h"
MtrrData g_eptp_mtrr_entries[255+11*8];
UCHAR g_eptp_mtrr_default_type;
PhysicalMemoryDescriptor* g_utilp_physical_memory_ranges;
// Get the highest 25 bits
static const ULONG_PTR kEptpPxiShift = 39ull;

// Get the highest 34 bits
static const ULONG_PTR kEptpPpiShift = 30ull;

// Get the highest 43 bits
static const ULONG_PTR kEptpPdiShift = 21ull;

// Get the highest 52 bits
static const ULONG_PTR kEptpPtiShift = 12ull;

// Use 9 bits; 0b0000_0000_0000_0000_0000_0000_0001_1111_1111
static const ULONG_PTR kEptpPtxMask = 0x1ffull;


PhysicalMemoryDescriptor *
UtilpBuildPhysicalMemoryRanges() {
	PAGED_CODE()

	const PPHYSICAL_MEMORY_RANGE pm_ranges = MmGetPhysicalMemoryRanges();
	if (!pm_ranges) {
		return NULL;
	}

	PFN_COUNT number_of_runs = 0;
	PFN_NUMBER number_of_pages = 0;
	for (/**/; /**/; ++number_of_runs) 
	{
		const PPHYSICAL_MEMORY_RANGE range = &pm_ranges[number_of_runs];
		if (!range->BaseAddress.QuadPart && !range->NumberOfBytes.QuadPart) {
			break;
		}
		number_of_pages += (PFN_NUMBER)(BYTES_TO_PAGES(range->NumberOfBytes.QuadPart));
	}
	if (number_of_runs == 0) 
	{
		ExFreePoolWithTag(pm_ranges, 'hPmM');
		return NULL;
	}

	const ULONG memory_block_size =
		sizeof(PhysicalMemoryDescriptor) +
		sizeof(PhysicalMemoryRun) * (number_of_runs - 1);
	PhysicalMemoryDescriptor* pm_block =
		(PhysicalMemoryDescriptor *)kmalloc(memory_block_size);
	if (!pm_block) {
		ExFreePoolWithTag(pm_ranges, 'hPmM');
		return NULL;
	}
	RtlZeroMemory(pm_block, memory_block_size);

	pm_block->number_of_runs = number_of_runs;
	pm_block->number_of_pages = number_of_pages;

	for (ULONG run_index = 0ul; run_index < number_of_runs; run_index++) {
		PhysicalMemoryRun* current_run = &pm_block->run[run_index];
		PPHYSICAL_MEMORY_RANGE current_block = &pm_ranges[run_index];
		current_run->base_page = (ULONG_PTR)(
			UtilPfnFromPa(current_block->BaseAddress.QuadPart));
		current_run->page_count = (ULONG_PTR)(
			BYTES_TO_PAGES(current_block->NumberOfBytes.QuadPart));
	}

	ExFreePoolWithTag(pm_ranges, 'hPmM');
	return pm_block;
}


void EptTermination(EptData *ept_data) {


	EptpFreeUnusedPreAllocatedEntries(ept_data->preallocated_entries,
		ept_data->preallocated_entries_count);
	EptpDestructTables(ept_data->ept_pml4, 4);
	kfree(ept_data);
}

BOOLEAN EptIsEptAvailable() {
	PAGED_CODE()

		// Check the followings:
		// - page walk length is 4 steps
		// - extended page tables can be laid out in write-back memory
		// - INVEPT instruction with all possible types is supported
		// - INVVPID instruction with all possible types is supported
		Ia32VmxEptVpidCapMsr capability = { __readmsr(MsrVmxEptVpidCap) };
	if (!capability.fields.support_page_walk_length4 ||
		!capability.fields.support_write_back_memory_type ||
		!capability.fields.support_invept ||
		!capability.fields.support_single_context_invept ||
		!capability.fields.support_all_context_invept ||
		!capability.fields.support_invvpid ||
		!capability.fields.support_individual_address_invvpid ||
		!capability.fields.support_single_context_invvpid ||
		!capability.fields.support_all_context_invvpid ||
		!capability.fields.support_single_context_retaining_globals_invvpid) {
		kprintf("ept 不可用");

		return FALSE;
	}
	return TRUE;
}

void EptInitializeMtrrEntries() {
	PAGED_CODE()

		int index = 0;
	MtrrData *mtrr_entries = g_eptp_mtrr_entries;

	// Get and store the default memory type
	Ia32MtrrDefaultTypeMsr default_type = { __readmsr(MsrMtrrDefType) };
	g_eptp_mtrr_default_type = kWriteBack;// default_type.fields.default_mtemory_type;

	// Read MTRR capability
	Ia32MtrrCapabilitiesMsr mtrr_capabilities = {
	__readmsr(MsrMtrrCap) };
	kprintf(
		"MTRR Default=%llu, VariableCount=%llu, FixedSupported=%llu, "
		"FixedEnabled=%llu",
		default_type.fields.default_mtemory_type,
		mtrr_capabilities.fields.variable_range_count,
		mtrr_capabilities.fields.fixed_range_supported,
		default_type.fields.fixed_mtrrs_enabled);

	// Read fixed range MTRRs if supported
	if (mtrr_capabilities.fields.fixed_range_supported &&
		default_type.fields.fixed_mtrrs_enabled) {
		static const ULONG_PTR k64kBase = 0x0;
		static const ULONG_PTR k64kManagedSize = 0x10000;
		static const ULONG_PTR k16kBase = 0x80000;
		static const ULONG_PTR k16kManagedSize = 0x4000;
		static const ULONG_PTR k4kBase = 0xC0000;
		static const ULONG_PTR k4kManagedSize = 0x1000;

		// The kIa32MtrrFix64k00000 manages 8 ranges of memory. The first range
		// starts at 0x0, and each range manages a 64k (0x10000) range. For example,
		//  entry[0]:     0x0 : 0x10000 - 1
		//  entry[1]: 0x10000 : 0x20000 - 1
		//  ...
		//  entry[7]: 0x70000 : 0x80000 - 1
		ULONG64 offset = 0;
		Ia32MtrrFixedRangeMsr fixed_range = {__readmsr(MsrMtrrFix64k00000) };

		for (UCHAR memory_type = 0, i = 0; i < 8;i++ ) {
			memory_type = fixed_range.fields.types[i];
			// Each entry manages 64k (0x10000) length.
			ULONG64 base = k64kBase + offset;
			offset += k64kManagedSize;

			// Saves the MTRR
			mtrr_entries[index].enabled = TRUE;
			mtrr_entries[index].fixedMtrr = TRUE;
			mtrr_entries[index].type = memory_type;
			mtrr_entries[index].range_base = base;
			mtrr_entries[index].range_end = base + k64kManagedSize - 1;
			index++;
		}
		NT_ASSERT(k64kBase + offset == k16kBase);

		// kIa32MtrrFix16k80000 manages 8 ranges of memory. The first range starts
		// at 0x80000, and each range manages a 16k (0x4000) range. For example,
		//  entry[0]: 0x80000 : 0x84000 - 1
		//  entry[1]: 0x88000 : 0x8C000 - 1
		//  ...
		//  entry[7]: 0x9C000 : 0xA0000 - 1
		// Also, subsequent memory ranges are managed by other MSR,
		// kIa32MtrrFix16kA0000, which manages 8 ranges of memory starting at
		// 0xA0000 in the same fashion. For example,
		//  entry[0]: 0xA0000 : 0xA4000 - 1
		//  entry[1]: 0xA8000 : 0xAC000 - 1
		//  ...
		//  entry[7]: 0xBC000 : 0xC0000 - 1
		offset = 0;
		for (ULONG msr = MsrMtrrFix16k80000;
			msr <= MsrMtrrFix16kA0000; msr++) {

			fixed_range.all = __readmsr(msr);
			for (UCHAR memory_type = 0, i = 0; i < 8; i++) {
				memory_type = fixed_range.fields.types[i];
				// Each entry manages 16k (0x4000) length.
				ULONG64 base = k16kBase + offset;
				offset += k16kManagedSize;

				// Saves the MTRR
				mtrr_entries[index].enabled = TRUE;
				mtrr_entries[index].fixedMtrr = TRUE;
				mtrr_entries[index].type = memory_type;
				mtrr_entries[index].range_base = base;
				mtrr_entries[index].range_end = base + k16kManagedSize - 1;
				index++;
			}
		}
		NT_ASSERT(k16kBase + offset == k4kBase);

		// kIa32MtrrFix4kC0000 manages 8 ranges of memory. The first range starts
		// at 0xC0000, and each range manages a 4k (0x1000) range. For example,
		//  entry[0]: 0xC0000 : 0xC1000 - 1
		//  entry[1]: 0xC1000 : 0xC2000 - 1
		//  ...
		//  entry[7]: 0xC7000 : 0xC8000 - 1
		// Also, subsequent memory ranges are managed by other MSRs such as
		// kIa32MtrrFix4kC8000, kIa32MtrrFix4kD0000, and kIa32MtrrFix4kF8000. Each
		// MSR manages 8 ranges of memory in the same fashion up to 0x100000.
		offset = 0;
		for (ULONG msr = MsrMtrrFix4kC0000;
			msr <= MsrMtrrFix4kF8000; msr++) {
			fixed_range.all = __readmsr(msr);
			for (UCHAR memory_type = 0, i = 0; i < 8; i++) {
				memory_type = fixed_range.fields.types[i];
				// Each entry manages 4k (0x1000) length.
				ULONG64 base = k4kBase + offset;
				offset += k4kManagedSize;

				// Saves the MTRR
				mtrr_entries[index].enabled = TRUE;
				mtrr_entries[index].fixedMtrr = TRUE;
				mtrr_entries[index].type = memory_type;
				mtrr_entries[index].range_base = base;
				mtrr_entries[index].range_end = base + k4kManagedSize - 1;
				index++;
			}
		}
		NT_ASSERT(k4kBase + offset == 0x100000);
	}

	// Read all variable range MTRRs
	for (ULONG i = 0; i < mtrr_capabilities.fields.variable_range_count; i++) {
		// Read MTRR mask and check if it is in use
		const ULONG phy_mask = MsrMtrrPhysMaskN + i * 2;
		Ia32MtrrPhysMaskMsr mtrr_mask = { __readmsr(phy_mask) };
		if (!mtrr_mask.fields.valid) {
			continue;
		}

		// Get a length this MTRR manages
		ULONG length;
		BitScanForward64(&length, mtrr_mask.fields.phys_mask * PAGE_SIZE);

		// Read MTRR base and calculate a range this MTRR manages
		const ULONG phy_base = MsrMtrrPhysBaseN + i * 2;
		Ia32MtrrPhysBaseMsr mtrr_base = { __readmsr(phy_base) };
		ULONG64 base = mtrr_base.fields.phys_base * PAGE_SIZE;
		ULONG64 end = base + (1ull << length) - 1;

		// Save it
		mtrr_entries[index].enabled = TRUE;
		mtrr_entries[index].fixedMtrr = FALSE;
		mtrr_entries[index].type = mtrr_base.fields.type;
		mtrr_entries[index].range_base = base;
		mtrr_entries[index].range_end = end;
		index++;
	}
}


EptData *EptInitialization() {
	PAGED_CODE()
	//DbgBreakPoint();

	static const UCHAR kEptPageWalkLevel = 4ul;

	// Allocate ept_data
	EptData* ept_data = (EptData *)(kmalloc(sizeof(EptData)));
	if (!ept_data) {
		return NULL;
	}
	RtlZeroMemory(ept_data, sizeof(EptData));

	// Allocate EPT_PML4 and initialize EptPointer
	//分配pml4表内存，总共一个页面大小，每个表项8字节，共512项
	const EptCommonEntry* ept_pml4 = (EptCommonEntry *)(kmalloc(PAGE_SIZE));
	if (!ept_pml4) {
		kfree(ept_data);
		return NULL;
	}
	RtlZeroMemory(ept_pml4, PAGE_SIZE);
	ept_data->ept_pointer.all = 0;
	ept_data->ept_pointer.fields.memory_type = kWriteBack;// EptpGetMemoryType(UtilPaFromVa(ept_pml4));
	ept_data->ept_pointer.fields.page_walk_length = kEptPageWalkLevel - 1;
	ept_data->ept_pointer.fields.pml4_address = UtilPfnFromPa(UtilPaFromVa(ept_pml4));

	// Initialize all EPT entries for all physical memory pages
	const PhysicalMemoryDescriptor* pm_ranges = g_utilp_physical_memory_ranges;
	for (int run_index = 0ul; run_index < pm_ranges->number_of_runs;
		++run_index) {
		const PhysicalMemoryRun* run = &pm_ranges->run[run_index];
		const ULONG_PTR base_addr = run->base_page * PAGE_SIZE;
		for (ULONG_PTR page_index = 0ull; page_index < run->page_count; ++page_index) {
			const ULONG_PTR indexed_addr = base_addr + page_index * PAGE_SIZE;
			//对这个物理页面构造
			const ULONG_PTR ept_pt_entry =
				EptpConstructTables(ept_pml4, 4, indexed_addr, NULL);
			if (!ept_pt_entry) {
				EptpDestructTables(ept_pml4, 4);
				kfree(ept_data);
				return NULL;
			}
		}
	}
	// DbgBreakPoint();
	 // Initialize an EPT entry for APIC_BASE. It is required to allocated it now
	 // for some reasons, or else, system hangs.
	const Ia32ApicBaseMsr apic_msr = { __readmsr(MsrApicBase) };
	if (!EptpConstructTables(ept_pml4, 4, apic_msr.fields.apic_base * PAGE_SIZE,
		NULL)) {
		EptpDestructTables(ept_pml4, 4);
		kfree(ept_data);
		return NULL;
	}

	// Allocate preallocated_entries
	const ULONG preallocated_entries_size =
		sizeof(EptCommonEntry *) * 50;
	const EptCommonEntry** preallocated_entries = (EptCommonEntry **)(
		kmalloc(preallocated_entries_size));
	if (!preallocated_entries) {
		EptpDestructTables(ept_pml4, 4);
		kfree(ept_data);
		return NULL;
	}
	RtlZeroMemory(preallocated_entries, preallocated_entries_size);

	// And fill preallocated_entries with newly created entries
	for (ULONG i = 0ul; i < 50; ++i) {
		const EptCommonEntry* ept_entry = EptpAllocateEptEntry(NULL);
		if (!ept_entry) {
			EptpFreeUnusedPreAllocatedEntries(preallocated_entries, 0);
			EptpDestructTables(ept_pml4, 4);
			kfree(ept_data);
			return NULL;
		}
		preallocated_entries[i] = ept_entry;
	}

	// Initialization completed
	ept_data->ept_pml4 = ept_pml4;
	ept_data->preallocated_entries = preallocated_entries;
	ept_data->preallocated_entries_count = 0;
	return ept_data;
}

void EptpFreeUnusedPreAllocatedEntries(
	EptCommonEntry **preallocated_entries, long used_count) {
	for (long i = used_count; i < 50; ++i) {
		if (!preallocated_entries[i]) {
			break;
		}
#pragma warning(push)
#pragma warning(disable : 6001)
		kfree(preallocated_entries[i]);
#pragma warning(pop)
	}
	kfree(preallocated_entries);
}

void EptpDestructTables(EptCommonEntry *table,
	ULONG table_level) {
	for (auto i = 0ul; i < 512; ++i) {
		const EptCommonEntry entry = table[i];
		if (entry.fields.physial_address) {
			const EptCommonEntry* sub_table = (EptCommonEntry *)(
				UtilVaFromPfn(entry.fields.physial_address));

			switch (table_level) {
			case 4:  // table == PML4, sub_table == PDPT
			case 3:  // table == PDPT, sub_table == PDT
				EptpDestructTables(sub_table, table_level - 1);
				break;
			case 2:  // table == PDT, sub_table == PT
				kfree(sub_table);
				break;
			default:
				DbgBreakPoint();
				break;
			}
		}
	}
	kfree(table);
}


EptCommonEntry *EptpConstructTables(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address,
	EptData *ept_data) {
	switch (table_level) {
	case 4: {
		// table == PML4 (512 GB)
		const ULONG_PTR pxe_index = EptpAddressToPxeIndex(physical_address);
		const EptCommonEntry* ept_pml4_entry = &table[pxe_index];
		if (!ept_pml4_entry->all) {
			const EptCommonEntry* ept_pdpt = EptpAllocateEptEntry(ept_data);
			if (!ept_pdpt) {
				return NULL;
			}
			EptpInitTableEntry(ept_pml4_entry, table_level, UtilPaFromVa(ept_pdpt));
		}
		return EptpConstructTables(
			(EptCommonEntry *)(
				UtilVaFromPfn(ept_pml4_entry->fields.physial_address)),
			table_level - 1, physical_address, ept_data);
	}
	case 3: {
		// table == PDPT (1 GB)
		const ULONG_PTR ppe_index = EptpAddressToPpeIndex(physical_address);
		const EptCommonEntry* ept_pdpt_entry = &table[ppe_index];
		if (!ept_pdpt_entry->all) {
			const EptCommonEntry* ept_pdt = EptpAllocateEptEntry(ept_data);
			if (!ept_pdt) {
				return NULL;
			}
			EptpInitTableEntry(ept_pdpt_entry, table_level, UtilPaFromVa(ept_pdt));
		}
		return EptpConstructTables(
			(EptCommonEntry *)(
				UtilVaFromPfn(ept_pdpt_entry->fields.physial_address)),
			table_level - 1, physical_address, ept_data);
	}
	case 2: {
		// table == PDT (2 MB)
		const ULONG_PTR pde_index = EptpAddressToPdeIndex(physical_address);
		const EptCommonEntry* ept_pdt_entry = &table[pde_index];
		if (!ept_pdt_entry->all) {
			const EptCommonEntry* ept_pt = EptpAllocateEptEntry(ept_data);
			if (!ept_pt) {
				return NULL;
			}
			EptpInitTableEntry(ept_pdt_entry, table_level, UtilPaFromVa(ept_pt));
		}
		return EptpConstructTables(
			(EptCommonEntry *)(
				UtilVaFromPfn(ept_pdt_entry->fields.physial_address)),
			table_level - 1, physical_address, ept_data);
	}
	case 1: {
		// table == PT (4 KB)
		const ULONG_PTR pte_index = EptpAddressToPteIndex(physical_address);
		const EptCommonEntry* ept_pt_entry = &table[pte_index];
		NT_ASSERT(!ept_pt_entry->all);
		EptpInitTableEntry(ept_pt_entry, table_level, physical_address);
		return ept_pt_entry;
	}
	default:
		DbgBreakPoint();
		return NULL;
	}
}
void EptpInitTableEntry(
	EptCommonEntry *entry, ULONG table_level, ULONG64 physical_address) {
	entry->fields.read_access = 1;
	entry->fields.write_access = 1;
	entry->fields.execute_access = 1;
	entry->fields.physial_address = UtilPfnFromPa(physical_address);
	if (table_level == 1) {
		entry->fields.memory_type =
			EptpGetMemoryType(physical_address);
	}
}


EptCommonEntry *EptpAllocateEptEntry(
	EptData *ept_data) {
	if (ept_data) 
	{
		const auto count =
			InterlockedIncrement(&ept_data->preallocated_entries_count);
		if (count > 50) {
			DbgBreakPoint();
			//HYPERPLATFORM_COMMON_BUG_CHECK(
			//	HyperPlatformBugCheck::kExhaustedPreallocatedEntries, count,
			//	reinterpret_cast<ULONG_PTR>(ept_data), 0);
		}
		return ept_data->preallocated_entries[count - 1];
	}
	else {
		static const int kAllocSize = 512 * sizeof(EptCommonEntry);

		const EptCommonEntry* entry = (EptCommonEntry *)(kmalloc(kAllocSize));
		if (!entry) {
			return entry;
		}
		RtlZeroMemory(entry, kAllocSize);
		return entry;
	}
}


ULONG64 EptpAddressToPxeIndex(
	ULONG64 physical_address) {
	const ULONG64 index = (physical_address >> kEptpPxiShift) & kEptpPtxMask;
	return index;
}

ULONG64 EptpAddressToPpeIndex(
	ULONG64 physical_address) {
	const ULONG64 index = (physical_address >> kEptpPpiShift) & kEptpPtxMask;
	return index;
}

// Return an address of PDE
ULONG64 EptpAddressToPdeIndex(
	ULONG64 physical_address) {
	const ULONG64 index = (physical_address >> kEptpPdiShift) & kEptpPtxMask;
	return index;
}

// Return an address of PTE
ULONG64 EptpAddressToPteIndex(
	ULONG64 physical_address) {
	const ULONG64 index = (physical_address >> kEptpPtiShift) & kEptpPtxMask;
	return index;
}

UCHAR EptpGetMemoryType(
	ULONG64 physical_address) {
	// Indicate that MTRR is not defined (as a default)
	UCHAR result_type = MAXUCHAR;

	// Looks for MTRR that includes the specified physical_address
	for (ULONG i = 0; g_eptp_mtrr_entries[i].enabled;i++) {

		MtrrData mtrr_entry = g_eptp_mtrr_entries[i];
		if (!mtrr_entry.enabled) {
			// Reached out the end of stored MTRRs
			break;
		}

		if (!UtilIsInBounds(physical_address, mtrr_entry.range_base,
			mtrr_entry.range_end)) {
			// This MTRR does not describe a memory type of the physical_address
			continue;
		}

		// See: MTRR Precedences
		if (mtrr_entry.fixedMtrr) {
			// If a fixed MTRR describes a memory type, it is priority
			result_type = mtrr_entry.type;
			break;
		}

		if (mtrr_entry.type == kUncacheable) {
			// If a memory type is UC, it is priority. Do not continue to search as
			// UC has the highest priority
			result_type = mtrr_entry.type;
			break;
		}

		//需要遍历整个range,除非遇到uc.当是当前range是wt时,结果为wt.没有一个wt时才能是wb.
		if (result_type == kWriteThrough ||
			mtrr_entry.type == kWriteThrough) {
			if (result_type == kWriteBack) {
				// If two or more MTRRs describes an over-wrapped memory region, and
				// one is WT and the other one is WB, use WT. However, look for other
				// MTRRs, as the other MTRR specifies the memory address as UC, which is
				// priority.
				result_type = kWriteThrough;
				continue;
			}
		}

		// Otherwise, processor behavior is undefined. We just use the last MTRR
		// describes the memory address.
		result_type = mtrr_entry.type;
	}

	// Use the default MTRR if no MTRR entry is found
	if (result_type == MAXUCHAR) {
		result_type = g_eptp_mtrr_default_type;
	}

	return result_type;
}


EptCommonEntry *EptGetEptPtEntry(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address) {
	if (!table) {
		return NULL;
	}
	switch (table_level) {
	case 4: {
		// table == PML4
		const ULONG64 pxe_index = EptpAddressToPxeIndex(physical_address);
		const EptCommonEntry* ept_pml4_entry = &table[pxe_index];
		if (!ept_pml4_entry->all) {
			return NULL;
		}
		return EptpGetEptPtEntry(UtilVaFromPfn(ept_pml4_entry->fields.physial_address),
			table_level - 1, physical_address);
	}
	case 3: {
		// table == PDPT
		const ULONG64 ppe_index = EptpAddressToPpeIndex(physical_address);
		const EptCommonEntry* ept_pdpt_entry = &table[ppe_index];
		if (!ept_pdpt_entry->all) {
			return NULL;
		}
		return EptpGetEptPtEntry(UtilVaFromPfn(ept_pdpt_entry->fields.physial_address),
			table_level - 1, physical_address);
	}
	case 2: {
		// table == PDT
		const ULONG64 pde_index = EptpAddressToPdeIndex(physical_address);
		const EptCommonEntry* ept_pdt_entry = &table[pde_index];
		if (!ept_pdt_entry->all) {
			return NULL;
		}
		return EptpGetEptPtEntry(UtilVaFromPfn(ept_pdt_entry->fields.physial_address),
			table_level - 1, physical_address);
	}
	case 1: {
		// table == PT
		const ULONG64 pte_index = EptpAddressToPteIndex(physical_address);
		const EptCommonEntry* ept_pt_entry = &table[pte_index];
		return ept_pt_entry;
	}
	default:
		DbgBreakPoint();
		return NULL;
	}
}

EptCommonEntry *EptpGetEptPtEntry(
	EptCommonEntry *table, ULONG table_level, ULONG64 physical_address) {
	if (!table) {
		return NULL;
	}
	switch (table_level) {
	case 4: {
		// table == PML4
		const ULONG64 pxe_index = EptpAddressToPxeIndex(physical_address);
		const EptCommonEntry* ept_pml4_entry = &table[pxe_index];
		if (!ept_pml4_entry->all) {
			return NULL;
		}
		return EptpGetEptPtEntry(UtilVaFromPfn(
			ept_pml4_entry->fields.physial_address),
			table_level - 1, physical_address);
	}
	case 3: {
		// table == PDPT
		const ULONG64 ppe_index = EptpAddressToPpeIndex(physical_address);
		const EptCommonEntry* ept_pdpt_entry = &table[ppe_index];
		if (!ept_pdpt_entry->all) {
			return NULL;
		}
		return EptpGetEptPtEntry((UtilVaFromPfn(
			ept_pdpt_entry->fields.physial_address)),
			table_level - 1, physical_address);
	}
	case 2: {
		// table == PDT
		const ULONG64 pde_index = EptpAddressToPdeIndex(physical_address);
		const EptCommonEntry* ept_pdt_entry = &table[pde_index];
		if (!ept_pdt_entry->all) {
			return NULL;
		}
		return EptpGetEptPtEntry((UtilVaFromPfn(
			ept_pdt_entry->fields.physial_address)),
			table_level - 1, physical_address);
	}
	case 1: {
		// table == PT
		const ULONG64 pte_index = EptpAddressToPteIndex(physical_address);
		const EptCommonEntry* ept_pt_entry = &table[pte_index];
		return ept_pt_entry;
	}
	default:
		DbgBreakPoint();
		return NULL;
	}
}



BOOLEAN EptpIsDeviceMemory(
	ULONG64 physical_address) {
	for (ULONG i = 0ul; i < g_utilp_physical_memory_ranges->number_of_runs; ++i) {
		PhysicalMemoryRun* current_run = &g_utilp_physical_memory_ranges->run[i];
		ULONG_PTR base_addr =current_run->base_page * PAGE_SIZE;
		ULONG_PTR endAddr = base_addr + current_run->page_count * PAGE_SIZE - 1;
		if (UtilIsInBounds(physical_address, base_addr, endAddr)) {
			return FALSE;
		}
	}
	return TRUE;
}


void EptExitHandler(GuestContext* pGuestContext)
{
	ExitQualification eq = { 0 };
	__vmx_vmread(VmExitQualification, &eq);

	ULONG_PTR fault_va = 0;
	ULONG_PTR fault_pa = 0;
	//这个物理地址是根据ept表转换得到而来的,是host物理地址,而MmGetPhysicalAddress返回的值是真正的guest物理地址
	//当ept表构建正常时,2者值相同.但是如果ept表构建出错,可能导致2者不同
	//ept只是在原来分页基础上多加了一层无效转换(一般来说gpa和hpa相等),在转换过程中可以进行拦截,并对其实际rwx的
	//地址的欺骗
	//DbgBreakPoint();
	__vmx_vmread(VmExitGuestPhysicalAddress,&fault_pa);
	if (eq.EPTViolations.valid_guest_linear_address)
	{
		__vmx_vmread(VmExitGuestLinearAddress, &fault_va);
	}

	VCPU* currentVcpu = &vcpu[KeGetCurrentProcessorNumberEx(NULL)];
	EptCommonEntry* ept_entry = EptGetEptPtEntry(currentVcpu->pEptData->ept_pml4, 4,fault_pa);

	if (ept_entry&&ept_entry->all)
	{

		ULONG_PTR gpa = MmGetPhysicalAddress(fault_va).QuadPart;
		if (gpa== fault_pa)
		{
			//本应该正常,却导致了Violations,可能是没刷新?
			kprintf("fault pa:%p", fault_pa);
			UtilInveptGlobal();
			return;
		}
		else
		{
			//ept配置错误
			DbgBreakPoint();
			//EptpConstructTables(currentVcpu->pEptData->ept_pml4, 4, fault_pa, currentVcpu->pEptData);

		}


	}


	if (EptpIsDeviceMemory(fault_pa))
	{
		//这个时候开始从预分配的内存进行分配
		EptpConstructTables(currentVcpu->pEptData->ept_pml4, 4, fault_pa, currentVcpu->pEptData);
		UtilInveptGlobal();

	}
	else
	{
		//ept配置错误
		DbgBreakPoint();
	}

}


