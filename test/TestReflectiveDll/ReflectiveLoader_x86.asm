; ReflectiveLoader 入口（x86）
.386
.model flat, C
.code

EXTERN RfiMap:PROC
PUBLIC ReflectiveLoader

ReflectiveLoader PROC
    push ebp
    mov  ebp, esp
    call $next
$next:
    pop  eax                      ; eax = $next 运行时地址
    sub  eax, OFFSET $next - OFFSET ReflectiveLoader  ; eax = ReflectiveLoader 入口运行时地址
    and  eax, 0FFFF0000h          ; 向下 64KB 对齐（原始字节所在块）
    push eax
    call RfiMap                   ; LPVOID RfiMap(LPVOID)  (cdecl, 调用方清理)
    add  esp, 4
    pop  ebp
    ret
ReflectiveLoader ENDP

END
