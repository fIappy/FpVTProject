PUBLIC AsmVmxLaunch
EXTERN VmxLaunchVm:PROC
EXTERN VmxVmexitHandler:PROC

PUSHAQ MACRO
    push    rax
    push    rcx
    push    rdx
    push    rbx
    push    -1      ; dummy for rsp
    push    rbp
    push    rsi
    push    rdi
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
ENDM

; Loads all general purpose registers from the stack
POPAQ MACRO
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    pop     rdi
    pop     rsi
    pop     rbp
    add     rsp, 8    ; dummy for rsp
    pop     rbx
    pop     rdx
    pop     rcx
    pop     rax
ENDM

.const 
VMX_OK                      EQU     0
VMX_ERROR_WITH_STATUS       EQU     1
VMX_ERROR_WITHOUT_STATUS    EQU     2

.code




AsmVmxLaunch PROC
	pushfq
	PUSHAQ
	

	mov rcx,rsp
	mov rdx,VmLaunchToGuest
	sub rsp,20h
	call VmxLaunchVm
	add rsp,20h
	
	POPAQ
	popfq
	xor rax,rax
	ret

VmLaunchToGuest:

	POPAQ
	popfq
	xor rax,rax
	inc rax
	ret

AsmVmxLaunch ENDP


AsmVmmEntryPoint PROC
	PUSHAQ			;当guest转入vmm时,通用寄存器并不会改变.而其它寄存器存放在vmcs guest域中,包括rflags

	mov rcx,rsp
	sub rsp,50h
	call VmxVmexitHandler;该函数执行有三种结果,一种是遇到非预期的vmexit直接断点.返回0继续运行,需要vmresume. 返回1退出vmx,回到guest
	add rsp,50h
	test rax,rax
	jz ExitVmx		;返回0则退出vmx

	POPAQ
	vmresume		;会根据vmcs的guest域进行恢复guest状态,只是通用寄存器需要手动恢复
	jmp ErrorHandler
ExitVmx:
	POPAQ
	vmxoff			;执行完后rax=rflags,rdx=原来的栈,rcx=导致vmexit的下一条指令地址
	jz ErrorHandler             ; if (ZF) jmp
    jc ErrorHandler             ; if (CF) jmp
    push rax
    popfq                  ; rflags <= GuestFlags
    mov rsp, rdx            ; rsp <= GuestRsp
    push rcx
    ret                     ; jmp AddressToReturn
ErrorHandler:
    PUSHAQ                      ; -8 * 16
    mov rcx, rsp                ; all_regs

    ;sub rsp, 28h                ; 28h for alignment
    ;call VmmVmxFailureHandler   ; VmmVmxFailureHandler(all_regs);
    ;add rsp, 28h
    int 3

AsmVmmEntryPoint ENDP



AsmInvd PROC
    invd
    ret
AsmInvd ENDP



AsmInvvpid PROC
    invvpid rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvvpid ENDP



AsmInvept PROC
    invept rcx, oword ptr [rdx]
    jz errorWithCode        ; if (ZF) jmp
    jc errorWithoutCode     ; if (CF) jmp
    xor rax, rax            ; return VMX_OK
    ret

errorWithoutCode:
    mov rax, VMX_ERROR_WITHOUT_STATUS
    ret

errorWithCode:
    mov rax, VMX_ERROR_WITH_STATUS
    ret
AsmInvept ENDP







AsmVmxCall PROC
    vmcall                  ; vmcall(hypercall_number, context)
    ret
AsmVmxCall ENDP





; void __stdcall AsmWriteGDT(_In_ const GDTR *gdtr);
AsmWriteGDT PROC
    lgdt fword ptr [rcx]
    ret
AsmWriteGDT ENDP

; void __stdcall AsmWriteLDTR(_In_ USHORT local_segmeng_selector);
AsmWriteLDTR PROC
    lldt cx
    ret
AsmWriteLDTR ENDP

; USHORT __stdcall AsmReadLDTR();
AsmReadLDTR PROC
    sldt ax
    ret
AsmReadLDTR ENDP

; void __stdcall AsmWriteTR(_In_ USHORT task_register);
AsmWriteTR PROC
    ltr cx
    ret
AsmWriteTR ENDP

; USHORT __stdcall AsmReadTR();
AsmReadTR PROC
    str ax
    ret
AsmReadTR ENDP

; void __stdcall AsmWriteES(_In_ USHORT segment_selector);
AsmWriteES PROC
    mov es, cx
    ret
AsmWriteES ENDP

; USHORT __stdcall AsmReadES();
AsmReadES PROC
    mov ax, es
    ret
AsmReadES ENDP

; void __stdcall AsmWriteCS(_In_ USHORT segment_selector);
AsmWriteCS PROC
    mov cs, cx
    ret
AsmWriteCS ENDP

; USHORT __stdcall AsmReadCS();
AsmReadCS PROC
    mov ax, cs
    ret
AsmReadCS ENDP

; void __stdcall AsmWriteSS(_In_ USHORT segment_selector);
AsmWriteSS PROC
    mov ss, cx
    ret
AsmWriteSS ENDP

; USHORT __stdcall AsmReadSS();
AsmReadSS PROC
    mov ax, ss
    ret
AsmReadSS ENDP

; void __stdcall AsmWriteDS(_In_ USHORT segment_selector);
AsmWriteDS PROC
    mov ds, cx
    ret
AsmWriteDS ENDP

; USHORT __stdcall AsmReadDS();
AsmReadDS PROC
    mov ax, ds
    ret
AsmReadDS ENDP

; void __stdcall AsmWriteFS(_In_ USHORT segment_selector);
AsmWriteFS PROC
    mov fs, cx
    ret
AsmWriteFS ENDP

; USHORT __stdcall AsmReadFS();
AsmReadFS PROC
    mov ax, fs
    ret
AsmReadFS ENDP

; void __stdcall AsmWriteGS(_In_ USHORT segment_selector);
AsmWriteGS PROC
    mov gs, cx
    ret
AsmWriteGS ENDP

; USHORT __stdcall AsmReadGS();
AsmReadGS PROC
    mov ax, gs
    ret
AsmReadGS ENDP

; ULONG_PTR __stdcall AsmLoadAccessRightsByte(_In_ ULONG_PTR segment_selector);
AsmLoadAccessRightsByte PROC
    lar rax, rcx
    ret
AsmLoadAccessRightsByte ENDP




END


