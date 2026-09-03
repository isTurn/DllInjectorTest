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

// 导出函数 3：InstallConfig —— 演示"复杂参数（结构体）"用法
// 注入器只能传一个字符串参数，所以约定用编码字符串表达结构化配置：
//   格式：key1=value1|key2=value2|key3=value3   （| 分隔多个键值对，= 分隔键和值）
// 本函数把字符串解析还原成多个字段（等价于填充结构体），逐个写日志。
// 返回解析出的字段个数（0 = 失败）
__declspec(dllexport) DWORD WINAPI InstallConfig(LPVOID param)
{
    wchar_t buf[2048];
    if (!param) {
        AppendLog(L"[InstallConfig] 未提供参数（NULL）\n");
        return 0;
    }

    const wchar_t* s = (const wchar_t*)param;
    swprintf_s(buf, 2048, L"[InstallConfig] 原始参数: \"%s\"\n", s);
    AppendLog(buf);

    wchar_t copy[1024];
    wcscpy_s(copy, 1024, s);

    int count = 0;
    wchar_t* ctx = NULL;
    wchar_t* pair = wcstok_s(copy, L"|", &ctx);
    while (pair && count < 16) {
        wchar_t key[256], val[512];
        wchar_t* eq = wcschr(pair, L'=');
        if (eq) {
            *eq = 0;
            wcscpy_s(key, 256, pair);
            wcscpy_s(val, 512, eq + 1);
        } else {
            wcscpy_s(key, 256, pair);
            wcscpy_s(val, 512, L"");
        }
        swprintf_s(buf, 2048, L"[InstallConfig]   [%d] %s = \"%s\"\n", count + 1, key, val);
        AppendLog(buf);
        count++;
        pair = wcstok_s(NULL, L"|", &ctx);
    }

    if (count == 0) {
        AppendLog(L"[InstallConfig]   (无有效键值对)\n");
        return 0;
    }
    return count;   // 返回解析出的字段个数
}

// 导出函数 4：InstallMulti —— 演示"多参数"用法
// 注入器把调用参数用 "||" 分隔成多个，在目标进程构造 NULL 结尾的字符串指针数组
//   （LPVOID* args：args[0]..args[n-1] 各指向一个 UTF-16 字符串，args[n] = NULL）。
// 导出函数直接按数组访问每个参数，返回参数个数。
// 对应注入器用法：-export InstallMulti -exportarg "张三||2024-01-01||admin"
__declspec(dllexport) DWORD WINAPI InstallMulti(LPVOID* args)
{
    wchar_t buf[2048];
    AppendLog(L"[InstallMulti] 按数组访问多个参数:\n");
    int n = 0;
    while (args && args[n]) {
        swprintf_s(buf, 2048, L"[InstallMulti]   arg[%d] = \"%s\"\n", n, (const wchar_t*)args[n]);
        AppendLog(buf);
        n++;
    }
    if (n == 0) AppendLog(L"[InstallMulti]   (无参数)\n");
    return n;   // 返回参数个数
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
        g_hDll = hinstDLL;   // 记住自身模块句柄，用于定位日志文件目录
    return TRUE;
}
