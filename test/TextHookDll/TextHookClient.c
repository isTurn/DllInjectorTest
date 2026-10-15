// ============================================================================
//  TextHookClient.c — 文本 Hook 管道消费者（控制台）
//
//  连接到 TextHookDll 创建的命名管道，实时打印捕获到的游戏文本。
//  协议：每行 UTF-8，字段以 \t 分隔
//        GalToolText\t<pid>\t<hook>\t<text>
//
//  用法：
//    TextHookClient.exe                连接默认管道 GalToolText
//    TextHookClient.exe MyPipe         连接自定义管道名（需与 DLL 的 pipe= 一致）
//
//  编译（MSVC）：
//    cl /nologo /O2 /utf-8 TextHookClient.c /link /OUT:TextHookClient.exe
//    /utf-8 必需（本文件含 UTF-8 中文注释，否则 MSVC 按系统代码页解析会出错）
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <string.h>

// 打印一行：把 "GalToolText\t<pid>\t<hook>\t<text>" 格式化成便于阅读的形式
static void PrintLine(char* line)
{
    char* f1 = strchr(line, '\t');
    if (!f1) { printf("%s\n", line); return; }
    *f1 = 0;
    char* f2 = strchr(f1 + 1, '\t');
    if (!f2) { printf("%s\n", f1 + 1); return; }
    *f2 = 0;
    char* f3 = strchr(f2 + 1, '\t');
    // 必须截断 hook 字段：f2 只终止了 pid，若不在此处补一个 0，
    // hook 会一路吞到行尾（把 hook 名和文本连成一片），
    // 表现为「hook 列里带着 TAB 和文本」，且文本被打印两遍。
    if (f3) *f3 = 0;

    const char* pid  = f1 + 1;
    const char* hook = f2 + 1;
    const char* text = f3 ? f3 + 1 : "";

    printf("[%s] %-14s %s\n", pid, hook, text);
    fflush(stdout);
}

int main(int argc, char* argv[])
{
    // 控制台切到 UTF-8，否则捕获到的日文/中文会显示成乱码
    SetConsoleOutputCP(CP_UTF8);

    const char* name = (argc > 1) ? argv[1] : "GalToolText";
    char full[MAX_PATH];
    sprintf_s(full, MAX_PATH, "\\\\.\\pipe\\%s", name);

    printf("Waiting for pipe %s ...\n", full);
    printf("(管道由 DLL 在注入后创建；若一直连不上，确认 DLL 已注入且 pipe= 名称一致)\n\n");

    // 管道可能尚未创建（游戏还没注入），轮询等待最多 60 秒
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 600; i++)
    {
        h = CreateFileA(full, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        Sleep(100);
    }

    if (h == INVALID_HANDLE_VALUE)
    {
        printf("连接失败（错误码 %lu）。\n", GetLastError());
        return 1;
    }

    printf("已连接。开始接收文本（Ctrl+C 退出）...\n\n");

    char  buf[8192];
    char  line[8192];
    int   li = 0;
    DWORD got = 0;

    for (;;)
    {
        if (!ReadFile(h, buf, sizeof(buf), &got, NULL) || got == 0)
        {
            printf("\n[管道已断开]\n");
            break;
        }
        for (DWORD i = 0; i < got; i++)
        {
            char c = buf[i];
            if (c == '\n')
            {
                line[li] = 0;
                if (li > 0) PrintLine(line);
                li = 0;
            }
            else if (c != '\r' && li < (int)sizeof(line) - 1)
            {
                line[li++] = c;
            }
        }
    }

    CloseHandle(h);
    return 0;
}
