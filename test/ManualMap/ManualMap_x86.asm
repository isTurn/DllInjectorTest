; ============================================================================
; ManualMap_x86.asm -- self-contained, position-independent manual-map
; shellcode (x86). Same design as ManualMap_x64.asm, 32-bit variant.
;
; Entry : [esp+4] = pointer to MmArgs { DWORD dllRaw; DWORD resultPtr; }
; Return: EAX = module base (0 = failure); *resultPtr = module base
;
; PEB  : FS:[0x30] -> PEB; +0x0C = Ldr; +0x1C = InMemoryOrderModuleList head
;        entry: DllBase = +0x08, BaseDllName.Length = +0x1C, Buffer = +0x20
; PE32 : nt + 0x78 = export RVA, nt + 0x80 = import RVA, nt + 0xA8 = basereloc
;        nt + 0x28 = AddressOfEntryPoint, nt + 0x34 = ImageBase,
;        nt + 0x50 = SizeOfImage, nt + 0x54 = SizeOfHeaders
; Calls use stdcall (args pushed; CALLEE cleans the stack).
;
; Local vars (esp-relative after 4 pushes + sub esp, 4Ch):
;   [esp+00] nt          [esp+04] newBase     [esp+08] delta
;   [esp+0C] sizeImage   [esp+10] imageBase   [esp+14] k32
;   [esp+18] pVA         [esp+1C] pLL         [esp+20] pGPA
;   [esp+24] resultPtr   [esp+28] dllRaw      [esp+2C] selfbase
;   [esp+30] counter/hMod                    [esp+34] chain entry save
; ============================================================================

.686
.model flat, C
assume fs:nothing
.code

PUBLIC ManualMapEntry

ManualMapEntry PROC
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 4Ch
    cld

    ; --- save arguments (args at [esp + 16 + 4Ch + 4]) ----------------------
    mov  eax, [esp+60h]         ; args ptr
    mov  ecx, [eax]             ; dllRaw
    mov  [esp+28h], ecx
    mov  ecx, [eax+4]           ; resultPtr
    mov  [esp+24h], ecx

    ; --- self-locate ---------------------------------------------------------
    call $next
$next:
    pop  ebx                    ; ebx = runtime address of $next
    mov  [esp+2Ch], ebx         ; selfbase

    ; --- 1. validate raw DLL MZ/PE32 -------------------------------------------
    mov  eax, [esp+28h]         ; raw
    cmp  word ptr [eax], 5A4Dh
    jne  $fail
    mov  ecx, dword ptr [eax+3Ch]
    lea  esi, [eax+ecx]         ; nt
    cmp  dword ptr [esi], 4550h
    jne  $fail
    movzx eax, word ptr [esi+18h]
    cmp  ax, 10Bh               ; PE32
    jne  $fail
    mov  [esp+00h], esi         ; nt
    mov  eax, dword ptr [esi+50h]   ; SizeOfImage
    mov  [esp+0Ch], eax
    mov  eax, dword ptr [esi+34h]   ; ImageBase
    mov  [esp+10h], eax

    ; --- 2. locate kernel32 via PEB module chain ---------------------------------
    mov  eax, fs:[30h]          ; PEB
    mov  eax, [eax+0Ch]         ; Ldr
    lea  edi, [eax+1Ch]         ; head
    mov  eax, [edi]             ; first entry
$chain:
    mov  [esp+34h], eax         ; save entry
    cmp  eax, edi
    je   $fail
    mov  edx, [eax+8]           ; DllBase
    test edx, edx
    jz   $next_entry
    movzx ecx, word ptr [eax+1Ch]   ; BaseDllName.Length
    cmp  cx, 24
    jb   $next_entry
    mov  esi, [eax+20h]         ; Buffer
    mov  ecx, [esp+2Ch]         ; selfbase
    lea  ebp, [ecx + (szKernel32 - $next)]  ; target ptr
    xor  ecx, ecx               ; i
$cmp_loop:
    movzx eax, word ptr [esi+ecx*2]   ; UTF-16 char (2 bytes/char)
    movzx edx, byte ptr [ebp+ecx]     ; ASCII target name (1 byte/char)
    ; lowercase both
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
    mov  eax, [esp+34h]         ; restore entry
    mov  eax, [eax]             ; Flink
    jmp  $chain
$found_k32:
    mov  eax, [esp+34h]         ; entry
    mov  eax, [eax+8]           ; DllBase
    mov  [esp+14h], eax         ; k32
$after_chain:
    mov  edi, [esp+14h]         ; k32 -> edi (for get_export)

    ; --- 3. resolve kernel32 exports ----------------------------------------------
    mov  ecx, [esp+2Ch]         ; selfbase
    lea  esi, [ecx + (szVirtualAlloc - $next)]
    call $get_export
    test eax, eax
    jz   $fail
    mov  [esp+18h], eax         ; pVA

    mov  ecx, [esp+2Ch]
    lea  esi, [ecx + (szLoadLibraryA - $next)]
    call $get_export
    test eax, eax
    jz   $fail
    mov  [esp+1Ch], eax         ; pLL

    mov  ecx, [esp+2Ch]
    lea  esi, [ecx + (szGetProcAddress - $next)]
    call $get_export
    test eax, eax
    jz   $fail
    mov  [esp+20h], eax         ; pGPA

    ; --- 4. VirtualAlloc(0, SizeOfImage, MEM_COMMIT|RESERVE, RWX) --------------------
    mov  eax, [esp+0Ch]         ; sizeImage
    push 40h                    ; PAGE_EXECUTE_READWRITE
    push 3000h                  ; MEM_RESERVE|MEM_COMMIT
    push eax
    push 0
    mov  ecx, [esp+18h+10h]     ; pVA
    call ecx
    test eax, eax
    jz   $fail
    mov  [esp+04h], eax         ; newBase

    ; --- 5. copy headers ---------------------------------------------------------------
    mov  edi, eax
    mov  esi, [esp+28h]         ; raw
    mov  ecx, [esp+00h]         ; nt
    mov  ecx, dword ptr [ecx+54h]   ; SizeOfHeaders
    rep  movsb

    ; --- 6. copy sections (file offsets) + zero BSS -------------------------------------
    mov  esi, [esp+00h]         ; nt
    movzx ecx, word ptr [esi+06h]   ; NumberOfSections
    mov  [esp+30h], ecx         ; counter
    movzx eax, word ptr [esi+14h]   ; SizeOfOptionalHeader
    lea  esi, [esi+18h]
    add  esi, eax               ; section table
$sec_loop:
    mov  eax, [esp+30h]
    test eax, eax
    jz   $sec_done
    dec  eax
    mov  [esp+30h], eax

    mov  ebp, esi               ; save section header ptr
    mov  edi, [esp+04h]         ; newBase
    mov  eax, dword ptr [ebp+0Ch]   ; VirtualAddress
    add  edi, eax
    mov  ecx, dword ptr [ebp+10h]   ; SizeOfRawData
    mov  ebx, ecx                   ; save RawSize (rep movsb zeroes ecx)
    test ecx, ecx
    jz   $sec_bss
    mov  eax, dword ptr [ebp+14h]   ; PointerToRawData
    mov  esi, [esp+28h]         ; raw
    add  esi, eax
    rep  movsb
$sec_bss:
    mov  eax, dword ptr [ebp+08h]   ; VirtualSize
    cmp  eax, ebx                   ; vs saved RawSize (ecx was zeroed)
    jbe  $sec_next
    sub  eax, ebx
    mov  ecx, eax
    xor  eax, eax
    rep  stosb
$sec_next:
    add  ebp, 28h
    mov  esi, ebp
    jmp  $sec_loop
$sec_done:

    ; --- 7. relocations ------------------------------------------------------------------
    mov  eax, [esp+04h]         ; newBase
    sub  eax, [esp+10h]         ; delta
    mov  [esp+08h], eax
    jz   $skip_reloc
    mov  esi, [esp+00h]         ; nt
    mov  eax, dword ptr [esi+0A0h]  ; BASERELOC RVA (PE32 dir[5])
    test eax, eax
    jz   $skip_reloc
    mov  ecx, dword ptr [esi+0A4h]  ; Size
    test ecx, ecx
    jz   $skip_reloc
    mov  esi, [esp+04h]
    add  esi, eax               ; reloc base
    lea  ebp, [esi+ecx]         ; end
$reloc_block:
    cmp  esi, ebp
    jae  $skip_reloc
    mov  eax, dword ptr [esi+4] ; SizeOfBlock
    test eax, eax
    jz   $skip_reloc
    mov  ecx, dword ptr [esi]   ; block VirtualAddress (DWORD, not word!)
    lea  edi, [esi+8]           ; entries
    lea  edx, [esi+eax]         ; block end
$reloc_entry:
    cmp  edi, edx
    jae  $reloc_next
    movzx eax, word ptr [edi]
    mov  ebx, eax
    and  ebx, 0FFFh             ; offset
    shr  eax, 12                ; type
    cmp  eax, 3                 ; HIGHLOW (x86)
    jne  $reloc_skip_entry
    mov  eax, [esp+04h]         ; newBase
    add  eax, ecx               ; + block VA
    add  eax, ebx               ; + offset
    mov  ebx, [eax]
    add  ebx, [esp+08h]         ; + delta
    mov  [eax], ebx
$reloc_skip_entry:
    add  edi, 2
    jmp  $reloc_entry
$reloc_next:
    mov  esi, edx
    jmp  $reloc_block
$skip_reloc:

    ; --- 8. fill IAT ------------------------------------------------------------------------
    mov  esi, [esp+00h]         ; nt
    mov  eax, dword ptr [esi+80h]   ; IMPORT RVA
    test eax, eax
    jz   $skip_iat
    mov  ecx, dword ptr [esi+84h]   ; Size
    test ecx, ecx
    jz   $skip_iat
    mov  esi, [esp+04h]
    add  esi, eax               ; imp descriptor array
$imp_loop:
    mov  eax, dword ptr [esi+0Ch]   ; Name RVA
    test eax, eax
    jz   $skip_iat
    mov  ebp, esi               ; save imp
    mov  edi, [esp+04h]
    add  edi, eax               ; dllName
    push edi
    mov  ecx, [esp+1Ch+4]       ; pLL
    call ecx
    test eax, eax
    jz   $imp_next
    mov  [esp+30h], eax         ; hMod
    mov  eax, dword ptr [ebp+00h]   ; OriginalFirstThunk
    test eax, eax
    jnz  $use_oft
    mov  eax, dword ptr [ebp+10h]   ; FirstThunk
$use_oft:
    mov  esi, [esp+04h]
    add  esi, eax               ; thunk
    mov  eax, dword ptr [ebp+10h]
    mov  edi, [esp+04h]
    add  edi, eax               ; iat
$thunk_loop:
    mov  eax, [esi]
    test eax, eax
    jz   $imp_next
    test eax, 80000000h         ; IMAGE_SNAP_BY_ORDINAL
    jnz  $ordinal
    add  eax, [esp+04h]         ; + newBase
    add  eax, 2                 ; skip Hint
    push eax                    ; name        [esp+0]=name
    push dword ptr [esp+30h+4]  ; hMod        [esp+0]=hMod, [esp+4]=name
    mov  ecx, [esp+20h+8]       ; pGPA        [esp+8]=ret
    call ecx
    jmp  $store
$ordinal:
    movzx eax, ax               ; ordinal low 16
    push eax
    push dword ptr [esp+30h+4]  ; hMod
    mov  ecx, [esp+20h+8]       ; pGPA
    call ecx
$store:
    mov  [edi], eax
    add  esi, 4
    add  edi, 4
    jmp  $thunk_loop
$imp_next:
    add  ebp, 14h
    mov  esi, ebp
    jmp  $imp_loop
$skip_iat:

    ; --- 9. call DllMain(DLL_PROCESS_ATTACH) --------------------------------------------------
    mov  eax, [esp+00h]         ; nt
    mov  eax, dword ptr [eax+28h]   ; AddressOfEntryPoint
    test eax, eax
    jz   $no_entry
    add  eax, [esp+04h]         ; entry = newBase + entryRVA
    push 0                      ; reserved
    push 1                      ; DLL_PROCESS_ATTACH
    push dword ptr [esp+04h+0Ch] ; hinst = newBase (3 pushes -> [esp+0Ch])
    call eax
$no_entry:

    ; --- 10. write result + return -------------------------------------------------------------
    mov  eax, [esp+04h]         ; newBase
    mov  ecx, [esp+24h]         ; resultPtr
    test ecx, ecx
    jz   $ret_val
    mov  [ecx], eax
$ret_val:
$done:
    add  esp, 4Ch
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret
$fail:
    xor  eax, eax
    jmp  $done

; -----------------------------------------------------------------------------
; Internal: resolve an export by ASCII name from kernel32.
; In : edi = kernel32 base, esi = &ascii-name
; Out: eax = function address or 0
;      clobbers ebx, ecx, edx, esi, edi, ebp
; Stack (own): [esp+0]=funcs_ptr [esp+4]=ords_ptr [esp+8]=index [esp+0Ch]=count
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
    mov  dl, [ecx+eax]          ; export name byte (dl/dh: keep ebx=names table intact)
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
szVirtualAlloc  BYTE "VirtualAlloc", 0
szLoadLibraryA  BYTE "LoadLibraryA", 0
szGetProcAddress BYTE "GetProcAddress", 0

ManualMapEntry ENDP

END
