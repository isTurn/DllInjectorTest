// TestHookDll.c — 测试注入器「注入后调用 DLL 导出函数」功能的示例 DLL
//
// 编译（MSVC）:
//   x64: vcvarsall.bat x64 && cl /LD /O2 TestHookDll.c /Fe:TestHookDll-x64.dll
//   x86: vcvarsall.bat x86 && cl /LD /O2 TestHookDll.c /Fe:TestHookDll-x86.dll
//
// 用法:
//   DllInjector-x64.exe -inject 目标.exe TestHookDll-x64.dll -export InstallHook -exportarg "你的参数"
//   或在 GUI「导出函数」填 InstallHook / Init，「调用参数」填字符串
//
// 调用成功后，会在本 DLL 同目录生成 hook_call_log.txt 记录调用结果。

#include <windows.h>
#include <stdio.h>

static HMODULE g_hDll = NULL;

// 把一行日志追加写到本 DLL 同目录的 hook_call_log.txt
static void AppendLog(const wchar_t* line)
{
    wchar_t path[MAX_PATH];
    wchar_t dir[MAX_PATH];
    wchar_t file[MAX_PATH];

    if (!g_hDll) return;
    GetModuleFileNameW(g_hDll, path, MAX_PATH);

    wcscpy_s(dir, MAX_PATH, path);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *(slash + 1) = 0;              // 去掉文件名，只留目录
    swprintf_s(file, MAX_PATH, L"%shook_call_log.txt", dir);

    FILE* f = _wfopen(file, L"a, ccs=UTF-8");
    if (!f) return;
    fwprintf(f, L"%s", line);
    fclose(f);
}

// 导出函数 1：InstallHook —— 接收一个指针参数（指向目标进程内 UTF-16 字符串，可为 NULL）
// 返回 1 = 成功（非零）
__declspec(dllexport) DWORD WINAPI InstallHook(LPVOID param)
{
    wchar_t buf[1024];
    if (param) {
        swprintf_s(buf, 1024, L"[InstallHook] PID=%lu  param=\"%s\"\n",
                   GetCurrentProcessId(), (const wchar_t*)param);
    } else {
        swprintf_s(buf, 1024, L"[InstallHook] PID=%lu  param=NULL\n",
                   GetCurrentProcessId());
    }
    AppendLog(buf);
    return 1;
}

// 导出函数 2：Init —— 无参用法演示（未填调用参数 = 传 NULL）
// 返回 42 演示非零返回码
__declspec(dllexport) DWORD WINAPI Init(LPVOID param)
{
    wchar_t buf[1024];
    swprintf_s(buf, 1024, L"[Init] PID=%lu  (无参数)\n", GetCurrentProcessId());
    AppendLog(buf);
    return 42;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        g_hDll = hinstDLL;   // 记住自身模块句柄，用于定位日志文件目录
    return TRUE;
}
