; ============================================================================
; UnmapDll_x64.asm -- manual-map DLL unloader (x64).
; In-process shellcode: calls the manually mapped DLL's DllMain with
; DLL_PROCESS_DETACH, then releases the mapped image memory (VirtualFree).
;
; Entry : RCX = pointer to MmUnmapArgs { QWORD moduleBase; }
; Return: RAX = 1 success / 0 failure
;
; Flow : validate MZ/PE -> call DllMain(base, DLL_PROCESS_DETACH, NULL)
;        -> locate kernel32 via PEB (GS:[0x60]) -> resolve VirtualFree
;        -> VirtualFree(base, 0, MEM_RELEASE)
;
; Local vars (rsp-relative after 7 pushes + sub rsp,50h):
;   [rsp+00] nt          [rsp+08] base        [rsp+10] k32
;   [rsp+18] pVFree      [rsp+20] args        [rsp+28] selfbase
; ============================================================================

.code

PUBLIC UnmapDllEntry

UnmapDllEntry PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 50h
    cld

    ; --- save args + moduleBase ---------------------------------------------
    mov  [rsp+20h], rcx         ; args
    mov  rax, [rcx]             ; moduleBase
    mov  [rsp+08h], rax
    test rax, rax
    jz   $fail

    ; --- self-locate ---------------------------------------------------------
    call $next
$next:
    pop  rbx                    ; rbx = runtime address of $next
    mov  [rsp+28h], rbx         ; selfbase

    ; --- 1. validate MZ/PE ---------------------------------------------------
    mov  rbx, rax               ; base
    cmp  word ptr [rbx], 5A4Dh  ; 'MZ'
    jne  $fail
    mov  ecx, dword ptr [rbx+3Ch]
    lea  rsi, [rbx+rcx]         ; nt
    cmp  dword ptr [rsi], 4550h ; 'PE\0\0'
    jne  $fail
    mov  [rsp+00h], rsi         ; nt

    ; --- 2. call DllMain(base, DLL_PROCESS_DETACH, NULL) ---------------------
    mov  eax, dword ptr [rsi+28h]   ; AddressOfEntryPoint (opt+0x10)
    test eax, eax
    jz   $no_entry
    mov  rcx, [rsp+08h]         ; hinst = base
    xor  edx, edx               ; fdwReason = DLL_PROCESS_DETACH (0)
    xor  r8d, r8d               ; lpvReserved = NULL
    mov  r9, [rsp+08h]
    add  rax, r9                ; entry = base + entryRVA
    sub  rsp, 20h
    call rax
    add  rsp, 20h
$no_entry:

    ; --- 3. locate kernel32 via PEB module chain ------------------------------
    mov  rax, gs:[60h]          ; PEB
    mov  rax, [rax+18h]         ; Ldr
    lea  rdi, [rax+20h]         ; head (InMemoryOrderModuleList)
    mov  rax, [rdi]             ; first entry
$chain:
    cmp  rax, rdi
    je   $fail                  ; wrapped -> not found
    mov  r13, rax               ; keep entry pointer
    mov  r12, [rax+20h]         ; DllBase (from InMemoryOrderLinks)
    test r12, r12
    jz   $next_entry
    movzx ecx, word ptr [rax+48h]   ; BaseDllName.Length (bytes)
    cmp  cx, 24                 ; "kernel32.dll" = 12 wchars = 24 bytes
    jb   $next_entry
    mov  r8, [rax+50h]          ; BaseDllName.Buffer
    mov  rdx, [rsp+28h]         ; selfbase
    lea  r9, [rdx + (szKernel32 - $next)]
    xor  r10d, r10d
$cmp_loop:
    movzx eax, word ptr [r8+r10*2]      ; UTF-16 char
    movzx edx, byte ptr [r9+r10]        ; ASCII target char
    cmp  eax, 41h
    jb   $c1
    cmp  eax, 5Ah
    ja   $c1
    or   eax, 20h
$c1:
    cmp  edx, 41h
    jb   $c2
    cmp  edx, 5Ah
    ja   $c2
    or   edx, 20h
$c2:
    cmp  eax, edx
    jne  $next_entry
    test eax, eax
    jz   $found_k32
    inc  r10d
    cmp  r10d, 13
    jb   $cmp_loop
    jmp  $next_entry
$next_entry:
    mov  rax, [r13]             ; Flink
    jmp  $chain
$found_k32:
    mov  [rsp+10h], r12         ; k32

    ; --- 4. resolve VirtualFree from kernel32 exports --------------------------
    mov  rdx, [rsp+28h]         ; selfbase
    lea  r8, [rdx + (szVirtualFree - $next)]
    call $get_export
    test rbx, rbx
    jz   $fail
    mov  [rsp+18h], rbx         ; pVFree

    ; --- 5. VirtualFree(base, 0, MEM_RELEASE) ----------------------------------
    mov  rcx, [rsp+08h]         ; lpAddress = base
    xor  rdx, rdx               ; dwSize = 0
    mov  r8d, 8000h             ; MEM_RELEASE
    mov  rax, [rsp+18h]         ; pVirtualFree
    sub  rsp, 20h
    call rax
    add  rsp, 20h
    test rax, rax
    jz   $fail
    mov  eax, 1
$done:
    add  rsp, 50h
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
$fail:
    xor  eax, eax
    jmp  $done

; -----------------------------------------------------------------------------
; Internal: resolve an export by ASCII name from kernel32 (same as ManualMap).
; In : r12 = kernel32 base, r8 = &ascii-name (PIC)
; Out: rbx = function address or 0
; -----------------------------------------------------------------------------
$get_export:
    movzx eax, word ptr [r12]       ; MZ
    cmp  ax, 5A4Dh
    jne  $ge_fail
    mov  ecx, dword ptr [r12+3Ch]
    lea  rsi, [r12+rcx]             ; nt
    cmp  dword ptr [rsi], 4550h
    jne  $ge_fail
    mov  eax, dword ptr [rsi+88h]   ; export RVA (DataDirectory[0])
    test eax, eax
    jz   $ge_fail
    lea  rdi, [r12+rax]             ; ed
    mov  eax, dword ptr [rdi+18h]   ; NumberOfNames
    test eax, eax
    jz   $ge_fail
    mov  r11d, eax
    mov  eax, dword ptr [rdi+20h]   ; AddressOfNames
    lea  r13, [r12+rax]
    mov  eax, dword ptr [rdi+24h]   ; AddressOfNameOrdinals
    lea  r14, [r12+rax]
    mov  eax, dword ptr [rdi+1Ch]   ; AddressOfFunctions
    lea  r15, [r12+rax]
    xor  r10d, r10d
$ge_loop:
    test r11d, r11d
    jz   $ge_fail
    dec  r11d
    mov  eax, dword ptr [r13+r10*4] ; names[i] RVA
    lea  rsi, [r12+rax]             ; &name
    push rbx
    push r8
    xor  ecx, ecx
$se_loop:
    mov  al, [rsi+rcx]
    mov  bl, [r8+rcx]
    cmp  al, bl
    jne  $se_ne
    test al, al
    jz   $se_eq
    inc  rcx
    jmp  $se_loop
$se_ne:
    pop  r8
    pop  rbx
    inc  r10d
    jmp  $ge_loop
$se_eq:
    pop  r8
    pop  rbx
    movzx eax, word ptr [r14+r10*2] ; ordinal
    mov  eax, dword ptr [r15+rax*4] ; function RVA
    add  rax, r12                   ; + k32 base
    mov  rbx, rax
    ret
$ge_fail:
    xor  rbx, rbx
    ret

; -----------------------------------------------------------------------------
; Data (PIC: reached via selfbase + label delta)
; -----------------------------------------------------------------------------
szKernel32      BYTE "kernel32.dll", 0
szVirtualFree   BYTE "VirtualFree", 0

UnmapDllEntry ENDP

END
