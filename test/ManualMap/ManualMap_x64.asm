; ============================================================================
; ManualMap_x64.asm -- self-contained, position-independent manual-map
; shellcode (x64). The injector writes this shellcode + the DLL's raw file
; bytes into the target process and starts a remote thread at the shellcode.
;
; The shellcode performs the FULL PE mapping in-process WITHOUT LoadLibrary:
;   1. validate MZ/PE32+ headers
;   2. locate kernel32 via PEB (GS:[0x60]) module chain
;   3. resolve VirtualAlloc / LoadLibraryA / GetProcAddress from kernel32 exports
;   4. VirtualAlloc(SizeOfImage) + copy headers + sections (file offsets)
;   5. apply base relocations (.reloc, DIR64)
;   6. fill IAT via LoadLibraryA + GetProcAddress
;   7. call DllMain(DLL_PROCESS_ATTACH)
;   8. write full 64-bit module base to *resultPtr, return low 32 bits in rax
;
; Entry : RCX = pointer to MmArgs { QWORD dllRaw; QWORD resultPtr; }
; Return: RAX = module base low 32 bits (0 = failure); *resultPtr = full base
; All code is PIC: data is reached via self-location + label deltas.
;
; Local vars (rsp-relative after sub rsp,60h):
;   [rsp+00] nt          [rsp+08] newBase     [rsp+10] delta
;   [rsp+18] sizeImage   [rsp+20] imageBase   [rsp+28] k32
;   [rsp+30] pVA         [rsp+38] pLL         [rsp+40] pGPA
;   [rsp+48] resultPtr   [rsp+50] dllRaw      [rsp+58] selfbase/counter/hMod
; ============================================================================

.code

PUBLIC ManualMapEntry

ManualMapEntry PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 60h
    cld

    ; --- save arguments -------------------------------------------------
    mov  rax, [rcx]             ; dllRaw
    mov  [rsp+50h], rax
    mov  rax, [rcx+8]           ; resultPtr
    mov  [rsp+48h], rax

    ; --- self-locate -----------------------------------------------------
    call $next
$next:
    pop  rbx                    ; rbx = runtime address of $next
    mov  [rsp+58h], rbx         ; selfbase

    ; --- 1. validate raw DLL MZ/PE32+ ------------------------------------
    mov  rax, [rsp+50h]         ; raw
    cmp  word ptr [rax], 5A4Dh  ; 'MZ'
    jne  $fail
    mov  ecx, dword ptr [rax+3Ch]   ; e_lfanew
    lea  rsi, [rax+rcx]         ; nt
    cmp  dword ptr [rsi], 4550h ; 'PE\0\0'
    jne  $fail
    movzx eax, word ptr [rsi+18h]   ; magic
    cmp  ax, 20Bh               ; PE32+
    jne  $fail
    mov  [rsp+00h], rsi         ; nt
    mov  eax, dword ptr [rsi+50h]   ; SizeOfImage (opt+0x38)
    mov  [rsp+18h], rax
    mov  rax, qword ptr [rsi+30h]   ; ImageBase (opt+0x18)
    mov  [rsp+20h], rax

    ; --- 2. locate kernel32 via PEB module chain --------------------------
    mov  rax, gs:[60h]          ; PEB
    mov  rax, [rax+18h]         ; Ldr
    lea  rdi, [rax+20h]         ; head (InMemoryOrderModuleList)
    mov  rax, [rdi]             ; first entry
$chain:
    cmp  rax, rdi
    je   $fail                  ; wrapped -> not found
    mov  r13, rax               ; keep entry pointer (rax is clobbered below)
    mov  r12, [rax+20h]         ; DllBase (from InMemoryOrderLinks)
    test r12, r12
    jz   $next_entry
    movzx ecx, word ptr [rax+48h]   ; BaseDllName.Length (bytes)
    cmp  cx, 24                 ; "kernel32.dll" = 12 wchars = 24 bytes
    jb   $next_entry
    mov  r8, [rax+50h]          ; BaseDllName.Buffer
    mov  rdx, [rsp+58h]         ; selfbase
    lea  r9, [rdx + (szKernel32 - $next)]
    xor  r10d, r10d
$cmp_loop:
    movzx eax, word ptr [r8+r10*2]      ; UTF-16 char (2 bytes/char)
    movzx edx, byte ptr [r9+r10]        ; ASCII target name (1 byte/char)
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
    inc  r10d
    cmp  r10d, 13               ; compare 13 wchars incl. trailing null
    jb   $cmp_loop
    jmp  $next_entry
$next_entry:
    mov  rax, [r13]             ; Flink of current entry (r13 preserved)
    jmp  $chain
$found_k32:
    mov  [rsp+28h], r12         ; save k32 base

    ; --- 3. resolve kernel32 exports --------------------------------------
    mov  rdx, [rsp+58h]         ; selfbase
    lea  r8, [rdx + (szVirtualAlloc - $next)]
    call $get_export
    test rbx, rbx
    jz   $fail
    mov  [rsp+30h], rbx         ; pVA

    mov  rdx, [rsp+58h]
    lea  r8, [rdx + (szLoadLibraryA - $next)]
    call $get_export
    test rbx, rbx
    jz   $fail
    mov  [rsp+38h], rbx         ; pLL

    mov  rdx, [rsp+58h]
    lea  r8, [rdx + (szGetProcAddress - $next)]
    call $get_export
    test rbx, rbx
    jz   $fail
    mov  [rsp+40h], rbx         ; pGPA

    ; --- 4. VirtualAlloc(0, SizeOfImage, MEM_COMMIT|RESERVE, RWX) ----------
    xor  rcx, rcx               ; lpAddress = NULL
    mov  rdx, [rsp+18h]         ; dwSize = SizeOfImage
    mov  r8, 3000h              ; MEM_RESERVE|MEM_COMMIT
    mov  r9, 40h                ; PAGE_EXECUTE_READWRITE
    mov  rax, [rsp+30h]         ; pVirtualAlloc
    sub  rsp, 20h
    call rax
    add  rsp, 20h
    test rax, rax
    jz   $fail
    mov  [rsp+08h], rax         ; newBase

    ; --- 5. copy headers ---------------------------------------------------
    mov  rdi, [rsp+08h]         ; newBase (slot; rax may hold resultPtr after TEMP)
    mov  rsi, [rsp+50h]         ; raw
    mov  rcx, [rsp+00h]         ; nt
    mov  ecx, dword ptr [rcx+54h]   ; SizeOfHeaders (opt+0x3C)
    rep  movsb

    ; --- 6. copy sections (file offsets) + zero BSS -------------------------
    mov  rsi, [rsp+00h]         ; nt
    movzx ecx, word ptr [rsi+06h]   ; NumberOfSections
    mov  [rsp+58h], rcx         ; counter (selfbase no longer needed)
    movzx eax, word ptr [rsi+14h]   ; SizeOfOptionalHeader
    lea  rsi, [rsi+18h]
    add  rsi, rax               ; section table
$sec_loop:
    mov  rax, [rsp+58h]
    test rax, rax
    jz   $sec_done
    dec  rax
    mov  [rsp+58h], rax

    mov  r14, rsi               ; save section header ptr
    mov  rdi, [rsp+08h]         ; newBase
    mov  eax, dword ptr [r14+0Ch]   ; VirtualAddress
    add  rdi, rax
    mov  ecx, dword ptr [r14+10h]   ; SizeOfRawData
    mov  r13d, ecx                  ; save RawSize (rep movsb zeroes ecx)
    test ecx, ecx
    jz   $sec_bss
    mov  eax, dword ptr [r14+14h]   ; PointerToRawData
    mov  rsi, [rsp+50h]         ; raw
    add  rsi, rax
    rep  movsb
$sec_bss:
    mov  eax, dword ptr [r14+08h]   ; VirtualSize
    cmp  eax, r13d                  ; vs saved RawSize (ecx was zeroed)
    jbe  $sec_next
    sub  eax, r13d
    mov  ecx, eax
    xor  eax, eax
    rep  stosb
$sec_next:
    add  r14, 28h               ; 40 bytes per section header
    mov  rsi, r14
    jmp  $sec_loop
$sec_done:

    ; --- 7. relocations ------------------------------------------------------
    mov  rax, [rsp+08h]         ; newBase
    sub  rax, [rsp+20h]         ; delta = newBase - ImageBase
    mov  [rsp+10h], rax
    jz   $skip_reloc
    mov  rsi, [rsp+00h]         ; nt
    mov  eax, dword ptr [rsi+0B0h]  ; BASERELOC RVA (DataDirectory[5])
    test eax, eax
    jz   $skip_reloc
    mov  ecx, dword ptr [rsi+0B4h]  ; BASERELOC Size
    test ecx, ecx
    jz   $skip_reloc
    mov  rsi, [rsp+08h]
    add  rsi, rax               ; reloc base
    lea  r12, [rsi+rcx]         ; end
$reloc_block:
    cmp  rsi, r12
    jae  $skip_reloc
    mov  eax, dword ptr [rsi+4] ; SizeOfBlock
    test eax, eax
    jz   $skip_reloc
    mov  ecx, dword ptr [rsi]   ; block VirtualAddress (DWORD, not word!)
    lea  rdi, [rsi+8]           ; entries
    lea  r8, [rsi+rax]          ; block end
$reloc_entry:
    cmp  rdi, r8
    jae  $reloc_next
    movzx eax, word ptr [rdi]
    mov  edx, eax
    and  edx, 0FFFh             ; offset
    shr  eax, 12                ; type
    cmp  eax, 0Ah               ; DIR64
    je   $reloc_dir64
    cmp  eax, 3                 ; HIGHLOW
    je   $reloc_highlow
    jmp  $reloc_skip_entry
$reloc_dir64:
    mov  r9, [rsp+08h]          ; newBase
    add  r9, rcx
    add  r9, rdx
    mov  rax, [r9]
    add  rax, [rsp+10h]         ; + delta
    mov  [r9], rax
    jmp  $reloc_skip_entry
$reloc_highlow:
    mov  r9, [rsp+08h]
    add  r9, rcx
    add  r9, rdx
    mov  eax, [r9]
    add  eax, [rsp+10h]
    mov  [r9], eax
$reloc_skip_entry:
    add  rdi, 2
    jmp  $reloc_entry
$reloc_next:
    mov  rsi, r8
    jmp  $reloc_block
$skip_reloc:

    ; --- 8. fill IAT ----------------------------------------------------------
    mov  rsi, [rsp+00h]         ; nt
    mov  eax, dword ptr [rsi+90h]   ; IMPORT RVA (DataDirectory[1], opt+120 = nt+0x90)
    test eax, eax
    jz   $skip_iat
    mov  ecx, dword ptr [rsi+94h]   ; IMPORT Size
    test ecx, ecx
    jz   $skip_iat
    mov  rsi, [rsp+08h]
    add  rsi, rax               ; import descriptor array
$imp_loop:
    mov  eax, dword ptr [rsi+0Ch]   ; Name RVA
    test eax, eax
    jz   $skip_iat
    mov  r13, rsi               ; save imp
    mov  rdi, [rsp+08h]
    add  rdi, rax               ; dllName
    mov  rcx, rdi
    mov  rax, [rsp+38h]         ; pLoadLibraryA
    sub  rsp, 20h
    call rax
    add  rsp, 20h
    test rax, rax
    jz   $imp_next
    mov  [rsp+58h], rax         ; hMod
    mov  eax, dword ptr [r13+00h]   ; OriginalFirstThunk
    test eax, eax
    jnz  $use_oft
    mov  eax, dword ptr [r13+10h]   ; FirstThunk
$use_oft:
    mov  r14, [rsp+08h]
    add  r14, rax               ; thunk
    mov  eax, dword ptr [r13+10h]
    mov  r15, [rsp+08h]
    add  r15, rax               ; iat
$thunk_loop:
    mov  rax, [r14]
    test rax, rax
    jz   $imp_next
    bt   rax, 63
    jc   $ordinal
    mov  rdi, [rsp+08h]
    lea  rdi, [rdi+rax+2]       ; IMAGE_IMPORT_BY_NAME->Name (skip Hint)
    mov  rcx, [rsp+58h]         ; hMod
    mov  rdx, rdi               ; name
    mov  rax, [rsp+40h]         ; pGetProcAddress
    sub  rsp, 20h
    call rax
    add  rsp, 20h
    jmp  $store
$ordinal:
    mov  rcx, [rsp+58h]         ; hMod
    movzx edx, ax               ; ordinal (low 16 bits)
    mov  rax, [rsp+40h]
    sub  rsp, 20h
    call rax
    add  rsp, 20h
$store:
    mov  [r15], rax
    add  r14, 8
    add  r15, 8
    jmp  $thunk_loop
$imp_next:
    add  r13, 14h               ; 20 bytes per descriptor
    mov  rsi, r13
    jmp  $imp_loop
$skip_iat:

    ; --- 9. call DllMain(DLL_PROCESS_ATTACH) ----------------------------------
    mov  rax, [rsp+00h]         ; nt
    mov  eax, dword ptr [rax+28h]   ; AddressOfEntryPoint (opt+0x10)
    test eax, eax
    jz   $no_entry
    mov  rcx, [rsp+08h]         ; hinst = newBase
    mov  rdx, 1                 ; DLL_PROCESS_ATTACH
    xor  r8, r8
    mov  r9, [rsp+08h]
    add  rax, r9                ; entry = newBase + AddressOfEntryPoint
    sub  rsp, 20h
    call rax
    add  rsp, 20h
$no_entry:

    ; --- 10. write full base to resultPtr, return low 32 bits -----------------
    mov  rax, [rsp+08h]         ; newBase
    mov  rcx, [rsp+48h]         ; resultPtr
    test rcx, rcx
    jz   $ret_low
    mov  [rcx], rax             ; *resultPtr = full base
$ret_low:
    mov  eax, eax               ; zero upper 32 bits of rax
$done:
    add  rsp, 60h
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
; Internal: resolve an export by ASCII name from kernel32.
; In : r12 = kernel32 base, r8 = &ascii-name (PIC)
; Out: rbx = function address or 0
;      clobbers rax, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r13, r14, r15
; -----------------------------------------------------------------------------
$get_export:
    movzx eax, word ptr [r12]       ; MZ
    cmp  ax, 5A4Dh
    jne  $ge_fail
    mov  ecx, dword ptr [r12+3Ch]
    lea  rsi, [r12+rcx]             ; nt
    cmp  dword ptr [rsi], 4550h
    jne  $ge_fail
    mov  eax, dword ptr [rsi+88h]   ; export RVA (DataDirectory[0], opt+112)
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
    ; ascii compare rsi vs r8 (preserve rbx/r8, use bl as flag)
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
szVirtualAlloc  BYTE "VirtualAlloc", 0
szLoadLibraryA  BYTE "LoadLibraryA", 0
szGetProcAddress BYTE "GetProcAddress", 0

ManualMapEntry ENDP

END
