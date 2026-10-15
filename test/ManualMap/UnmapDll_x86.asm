; ============================================================================
; UnmapDll_x86.asm -- manual-map DLL unloader (x86).
; In-process shellcode: calls the manually mapped DLL's DllMain with
; DLL_PROCESS_DETACH, then releases the mapped image memory (VirtualFree).
;
; Entry : [esp+4] = pointer to MmUnmapArgs { DWORD moduleBase; }
; Return: EAX = 1 success / 0 failure
;
; PEB  : FS:[0x30] -> PEB; +0x0C = Ldr; +0x1C = InMemoryOrderModuleList head
;        entry: DllBase = +0x08, BaseDllName.Length = +0x1C, Buffer = +0x20
; PE32 : nt + 0x78 = export RVA, nt + 0x28 = AddressOfEntryPoint
; Calls use stdcall (args pushed; CALLEE cleans the stack).
;
; Local vars (esp-relative after 4 pushes + sub esp, 20h):
;   [esp+00] base        [esp+04] nt          [esp+08] k32
;   [esp+0C] pVFree      [esp+10] selfbase    [esp+14] chain entry save
; ============================================================================

.686
.model flat, C
assume fs:nothing
.code

PUBLIC UnmapDllEntry

UnmapDllEntry PROC
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 20h
    cld

    ; --- save args + moduleBase (args at [esp+34h]) --------------------------
    mov  eax, [esp+34h]         ; args
    mov  eax, [eax]             ; moduleBase
    mov  [esp+00h], eax
    test eax, eax
    jz   $fail

    ; --- self-locate ----------------------------------------------------------
    call $next
$next:
    pop  ebx                    ; ebx = runtime address of $next
    mov  [esp+10h], ebx         ; selfbase

    ; --- 1. validate MZ/PE ----------------------------------------------------
    mov  ebx, eax               ; base
    cmp  word ptr [ebx], 5A4Dh
    jne  $fail
    mov  ecx, dword ptr [ebx+3Ch]
    lea  esi, [ebx+ecx]         ; nt
    cmp  dword ptr [esi], 4550h
    jne  $fail
    mov  [esp+04h], esi         ; nt

    ; --- 2. call DllMain(base, DLL_PROCESS_DETACH, NULL) ----------------------
    mov  eax, dword ptr [esi+28h]   ; AddressOfEntryPoint
    test eax, eax
    jz   $no_entry
    add  eax, [esp+00h]         ; entry = base + entryRVA
    push 0                      ; lpvReserved
    push 0                      ; fdwReason = DLL_PROCESS_DETACH (0)
    push dword ptr [esp+00h+0Ch] ; hinst = base (3 pushes -> [esp+0Ch])
    call eax
$no_entry:

    ; --- 3. locate kernel32 via PEB module chain --------------------------------
    mov  eax, fs:[30h]          ; PEB
    mov  eax, [eax+0Ch]         ; Ldr
    lea  edi, [eax+1Ch]         ; head
    mov  eax, [edi]             ; first entry
$chain:
    mov  [esp+14h], eax         ; save entry
    cmp  eax, edi
    je   $fail
    mov  edx, [eax+8]           ; DllBase
    test edx, edx
    jz   $next_entry
    movzx ecx, word ptr [eax+1Ch]   ; BaseDllName.Length
    cmp  cx, 24
    jb   $next_entry
    mov  esi, [eax+20h]         ; Buffer
    mov  ecx, [esp+10h]         ; selfbase
    lea  ebp, [ecx + (szKernel32 - $next)]
    xor  ecx, ecx               ; i
$cmp_loop:
    movzx eax, word ptr [esi+ecx*2]   ; UTF-16 char
    movzx edx, byte ptr [ebp+ecx]     ; ASCII target char
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
    inc  ecx
    cmp  ecx, 13
    jb   $cmp_loop
    jmp  $next_entry
$next_entry:
    mov  eax, [esp+14h]         ; restore entry
    mov  eax, [eax]             ; Flink
    jmp  $chain
$found_k32:
    mov  eax, [esp+14h]         ; entry
    mov  eax, [eax+8]           ; DllBase
    mov  [esp+08h], eax         ; k32

    ; --- 4. resolve VirtualFree from kernel32 exports ---------------------------
    mov  edi, [esp+08h]         ; k32 -> edi
    mov  ecx, [esp+10h]         ; selfbase
    lea  esi, [ecx + (szVirtualFree - $next)]
    call $get_export
    test eax, eax
    jz   $fail
    mov  [esp+0Ch], eax         ; pVFree

    ; --- 5. VirtualFree(base, 0, MEM_RELEASE) ------------------------------------
    mov  eax, [esp+00h]         ; base
    push 8000h                  ; MEM_RELEASE
    push 0                      ; dwSize
    push eax                    ; lpAddress
    mov  ecx, [esp+18h]         ; pVFree (3 pushes: base 在栈顶, pVFree 槽=原esp+0Ch, 当前esp+18h)
    call ecx
    test eax, eax
    jz   $fail
    mov  eax, 1
$done:
    add  esp, 20h
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret
$fail:
    xor  eax, eax
    jmp  $done

; -----------------------------------------------------------------------------
; Internal: resolve an export by ASCII name from kernel32 (same as ManualMap).
; In : edi = kernel32 base, esi = &ascii-name
; Out: eax = function address or 0
; -----------------------------------------------------------------------------
$get_export:
    cmp  word ptr [edi], 5A4Dh
    jne  $ge_fail
    mov  ecx, dword ptr [edi+3Ch]
    lea  edx, [edi+ecx]         ; nt
    cmp  dword ptr [edx], 4550h
    jne  $ge_fail
    mov  ecx, dword ptr [edx+78h]   ; export RVA
    test ecx, ecx
    jz   $ge_fail
    lea  ebp, [edi+ecx]         ; ed
    mov  ecx, dword ptr [ebp+18h]   ; NumberOfNames
    test ecx, ecx
    jz   $ge_fail
    push ecx                    ; [esp+0]=count
    push 0                      ; [esp+0]=index, [esp+4]=count
    mov  eax, dword ptr [ebp+24h]   ; AddressOfNameOrdinals
    add  eax, edi
    push eax                    ; [esp+0]=ords, [esp+4]=index, [esp+8]=count
    mov  eax, dword ptr [ebp+1Ch]   ; AddressOfFunctions
    add  eax, edi
    push eax                    ; [esp+0]=funcs, [esp+4]=ords, [esp+8]=index, [esp+0Ch]=count
    mov  eax, dword ptr [ebp+20h]   ; AddressOfNames
    add  eax, edi
    mov  ebx, eax               ; names table
$ge_loop:
    mov  eax, [esp+0Ch]         ; count
    test eax, eax
    jz   $ge_fail_clean
    dec  eax
    mov  [esp+0Ch], eax
    mov  eax, [esp+8]           ; index
    mov  ecx, [ebx+eax*4]       ; name RVA
    add  ecx, edi               ; &exp name
    xor  eax, eax               ; off
$se_loop:
    mov  dl, [ecx+eax]          ; export name byte (dl/dh keep ebx intact)
    mov  dh, [esi+eax]          ; target name byte
    cmp  dl, dh
    jne  $se_ne
    test dl, dl
    jz   $se_eq
    inc  eax
    cmp  eax, 40h               ; safety cap
    jb   $se_loop
$se_ne:
    inc  dword ptr [esp+8]      ; index++
    jmp  $ge_loop
$se_eq:
    mov  eax, [esp+8]           ; index
    mov  ecx, [esp+4]           ; ords
    movzx eax, word ptr [ecx+eax*2] ; ordinal
    mov  ecx, [esp]             ; funcs
    mov  eax, dword ptr [ecx+eax*4] ; func RVA
    add  eax, edi               ; + k32
    add  esp, 10h
    ret
$ge_fail_clean:
    add  esp, 10h
$ge_fail:
    xor  eax, eax
    ret

; -----------------------------------------------------------------------------
; Data (PIC: reached via selfbase + label delta)
; -----------------------------------------------------------------------------
szKernel32      BYTE "kernel32.dll", 0
szVirtualFree   BYTE "VirtualFree", 0

UnmapDllEntry ENDP

END
