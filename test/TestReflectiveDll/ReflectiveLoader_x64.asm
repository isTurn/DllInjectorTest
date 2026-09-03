; ReflectiveLoader 入口（x64）
; 线程以本函数为入口启动。用 call/pop 取得当前指令运行时地址，
; 减去编译期相对偏移得到本函数入口地址，向下 64KB 对齐后传给 C 的 RfiMap
; （RfiMap 会继续向前搜索 MZ 头并完成完整 PE 映射）。
.code

EXTERN RfiMap:PROC
PUBLIC ReflectiveLoader

ReflectiveLoader PROC
    push rbp
    mov  rbp, rsp
    sub  rsp, 20h                    ; keep RSP 16-byte aligned before call RfiMap
    call $next
$next:
    pop  rax                       ; rax = $next 运行时地址
    sub  rax, OFFSET $next - OFFSET ReflectiveLoader  ; rax = ReflectiveLoader 入口运行时地址
    and  rax, 0FFFFFFFFFFFF0000h   ; 向下 64KB 对齐（原始字节所在块）
    mov  rcx, rax                  ; 参数1 = 对齐后的原始基址
    call RfiMap                    ; LPVOID RfiMap(LPVOID)
    leave
    ret
ReflectiveLoader ENDP

END
