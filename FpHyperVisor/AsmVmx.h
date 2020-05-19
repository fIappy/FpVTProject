#pragma once


BOOLEAN __stdcall AsmVmxLaunch();
void __stdcall AsmVmmEntryPoint();
void __stdcall AsmInvd();


void __stdcall AsmVmxCall(ULONG no, ULONG unuse);





unsigned char __stdcall AsmInvvpid(
	_In_ ULONG_PTR invvpid_type,
	_In_ ULONG_PTR *invvpid_descriptor);

unsigned char __stdcall AsmInvept(
	_In_ ULONG_PTR invept_type,
	_In_ ULONG_PTR *invept_descriptor);





void _sgdt(void*);
/// Writes to GDT
/// @param gdtr   A value to write
void __stdcall AsmWriteGDT(_In_ const Gdtr *gdtr);

/// Reads SLDT
/// @return LDT
USHORT __stdcall AsmReadLDTR();

/// Writes to TR
/// @param task_register   A value to write
void __stdcall AsmWriteTR(_In_ USHORT task_register);

/// Reads STR
/// @return TR
USHORT __stdcall AsmReadTR();

/// Writes to ES
/// @param segment_selector   A value to write
void __stdcall AsmWriteES(_In_ USHORT segment_selector);

/// Reads ES
/// @return ES
USHORT __stdcall AsmReadES();

/// Writes to CS
/// @param segment_selector   A value to write
void __stdcall AsmWriteCS(_In_ USHORT segment_selector);

/// Reads CS
/// @return CS
USHORT __stdcall AsmReadCS();

/// Writes to SS
/// @param segment_selector   A value to write
void __stdcall AsmWriteSS(_In_ USHORT segment_selector);

/// Reads SS
/// @return SS
USHORT __stdcall AsmReadSS();

/// Writes to DS
/// @param segment_selector   A value to write
void __stdcall AsmWriteDS(_In_ USHORT segment_selector);

/// Reads DS
/// @return DS
USHORT __stdcall AsmReadDS();

/// Writes to FS
/// @param segment_selector   A value to write
void __stdcall AsmWriteFS(_In_ USHORT segment_selector);

/// Reads FS
/// @return FS
USHORT __stdcall AsmReadFS();

/// Writes to GS
/// @param segment_selector   A value to write
void __stdcall AsmWriteGS(_In_ USHORT segment_selector);

/// Reads GS
/// @return GS
USHORT __stdcall AsmReadGS();

/// Loads access rights byte
/// @param segment_selector   A value to get access rights byte
/// @return An access rights byte
ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);







