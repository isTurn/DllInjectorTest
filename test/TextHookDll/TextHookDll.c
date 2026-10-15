// ============================================================================
//  TextHookDll.c — GalGame 多引擎文本 Hook（一阶段：IAT Hook）
//
//  设计说明见 docs/text-hook-design.md。
//
//  职责：在目标进程内挂钩文本输出 API，把捕获到的文本经统一编码转换后，
//        通过命名管道推送给外部消费者（翻译工具 / TextHookClient.exe）。
//
//  分层：
//    EngineProfile  引擎适配表（唯一与引擎相关的部分）
//    HookEngine     IAT Hook 安装 / 卸载
//    Extractor      文本提取 + 编码转换（SJIS/GBK/UTF-16 -> UTF-8）
//    Sink           去重 -> 队列 -> 管道 / 文件
//
//  与注入器集成（复用现有的 -export / -exportarg 机制，注入器无需改动）：
//    DllInjector-x64.exe -inject 游戏.exe TextHookDll-x64.dll \
//        -export InstallConfig -exportarg "engine=generic-gdi|cp=932|pipe=GalToolText|log=1"
//
//  配置项（k=v 用 | 分隔）：
//    engine=generic-gdi|generic-gdi-sjis|generic-gdi-gbk|generic-unicode  （默认 generic-gdi）
//    cp=932|936|65001|1200   强制指定 *A 系列文本的代码页（覆盖 profile 默认值）
//    pipe=<名称>             管道名，默认 GalToolText（实际路径 \\.\pipe\<名称>）
//    log=1|0                 是否同时落盘 texthook_log.txt（默认 1，便于无客户端时验证）
//    minlen=<n>              短于此长度的文本丢弃（默认 2）
//    dedup=<ms>              去重窗口，同一文本在该毫秒数内只上报一次（默认 200）
//
//  编译（MSVC）：
//    x64: cl /nologo /LD /O2 TextHookDll.c /link /OUT:TextHookDll-x64.dll
//    x86: cl /nologo /LD /O2 TextHookDll.c /link /OUT:TextHookDll-x86.dll
//    或直接用 test\TextHookDll\build.bat
//
//  已知限制（一阶段，详见设计文档）：
//    · 只覆盖走 IAT 的调用；引擎若用 GetProcAddress 动态取址则抓不到（需二阶段 Inline Hook）
//    · 不覆盖 DirectX 自绘引擎
//    · 不做句子重组（逐字显示会逐次上报），交由消费端处理
// ============================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>   // iswspace

// ---------------------------------------------------------------------------
// 引擎适配表
// ---------------------------------------------------------------------------

#define HOOK_IAT 0

typedef struct {
    const char* module;   // 提供函数的 DLL 名，如 "gdi32.dll"
    const char* func;     // 函数名
    int         kind;     // 挂钩方式（当前仅 HOOK_IAT）
} HookTarget;

typedef struct {
    const char*       name;
    UINT              codepage;     // 0 = 用系统 ANSI 代码页
    const HookTarget* targets;
    int               targetCount;
    int               minLen;
    DWORD             dedupMs;
} EngineProfile;

// 通用 GDI 目标：TextOut / ExtTextOut / DrawText 的 A/W 两个版本。
// 这六个函数覆盖了绝大多数 GDI 系 GalGame 的文本输出。
// 注意：TextOut / ExtTextOut 属于 gdi32.dll，而 DrawText 属于 user32.dll，
//       挂钩时必须按各自的真实来源模块去匹配目标模块的导入表。
static const HookTarget kGdiTargets[] = {
    { "gdi32.dll",  "TextOutA",    HOOK_IAT },
    { "gdi32.dll",  "TextOutW",    HOOK_IAT },
    { "gdi32.dll",  "ExtTextOutA", HOOK_IAT },
    { "gdi32.dll",  "ExtTextOutW", HOOK_IAT },
    { "user32.dll", "DrawTextA",   HOOK_IAT },
    { "user32.dll", "DrawTextW",   HOOK_IAT },
};

// 已确定使用宽字符输出的引擎：只挂 W 系列，减少一半开销
static const HookTarget kGdiUnicodeTargets[] = {
    { "gdi32.dll",  "TextOutW",    HOOK_IAT },
    { "gdi32.dll",  "ExtTextOutW", HOOK_IAT },
    { "user32.dll", "DrawTextW",   HOOK_IAT },
};

static const EngineProfile kProfiles[] = {
    { "generic-gdi",      0,    kGdiTargets,        6, 2, 200 },
    { "generic-gdi-sjis", 932,  kGdiTargets,        6, 2, 200 },
    { "generic-gdi-gbk",  936,  kGdiTargets,        6, 2, 200 },
    { "generic-unicode",  1200, kGdiUnicodeTargets, 3, 2, 200 },
};
static const int kProfileCount = (int)(sizeof(kProfiles) / sizeof(kProfiles[0]));

// ---------------------------------------------------------------------------
// 全局状态
// ---------------------------------------------------------------------------

static HMODULE             g_hDll        = NULL;
static const EngineProfile* g_profile    = &kProfiles[0];
static UINT                g_codepage    = 0;      // 0 = 用 profile / 系统默认
static int                 g_minLen      = 2;
static DWORD               g_dedupMs     = 200;
static BOOL                g_logToFile   = TRUE;
static BOOL                g_initialized = FALSE;
static char                g_pipeName[128] = "GalToolText";

static CRITICAL_SECTION    g_textCs;      // 保护去重状态
static wchar_t             g_lastText[2048];
static DWORD               g_lastTick    = 0;

// 原始函数地址（各模块 IAT 槽里存的是同一个 gdi32 函数地址，故共用一份即可）
typedef BOOL (WINAPI *pTextOutA)(HDC, int, int, LPCSTR, int);
typedef BOOL (WINAPI *pTextOutW)(HDC, int, int, LPCWSTR, int);
typedef BOOL (WINAPI *pExtTextOutA)(HDC, int, int, UINT, const RECT*, LPCSTR, UINT, const INT*);
typedef BOOL (WINAPI *pExtTextOutW)(HDC, int, int, UINT, const RECT*, LPCWSTR, UINT, const INT*);
typedef int  (WINAPI *pDrawTextA)(HDC, LPCSTR, int, LPRECT, UINT);
typedef int  (WINAPI *pDrawTextW)(HDC, LPCWSTR, int, LPRECT, UINT);

static pTextOutA    real_TextOutA    = NULL;
static pTextOutW    real_TextOutW    = NULL;
static pExtTextOutA real_ExtTextOutA = NULL;
static pExtTextOutW real_ExtTextOutW = NULL;
static pDrawTextA   real_DrawTextA   = NULL;
static pDrawTextW   real_DrawTextW   = NULL;

// 已打补丁的 IAT 槽（卸载时还原）
#define MAX_PATCHED 256
typedef struct { void** slot; void* original; } PatchedSlot;
static PatchedSlot g_patched[MAX_PATCHED];
static int         g_patchedCount = 0;

// ---------------------------------------------------------------------------
// 输出：日志文件
// ---------------------------------------------------------------------------

static void FileLogLine(const char* utf8Line)
{
    if (!g_hDll) return;

    wchar_t path[MAX_PATH];
    wchar_t dir[MAX_PATH];
    wchar_t file[MAX_PATH];

    if (!GetModuleFileNameW(g_hDll, path, MAX_PATH)) return;

    wcscpy_s(dir, MAX_PATH, path);
    wchar_t* slash = wcsrchr(dir, L'\\');
    if (slash) *(slash + 1) = 0;
    swprintf_s(file, MAX_PATH, L"%stexthook_log.txt", dir);

    // 以二进制追加写原始 UTF-8 字节（不能用 ccs=UTF-8，那是给宽字符准备的）
    FILE* f = NULL;
    if (_wfopen_s(&f, file, L"ab") != 0 || !f) return;
    fwrite(utf8Line, 1, strlen(utf8Line), f);
    fclose(f);
}

// ---------------------------------------------------------------------------
// 输出：命名管道（服务端 + 独立写线程）
//
// 关键设计：游戏线程只做「入队 + SetEvent」，绝不直接碰管道。
// 否则客户端一旦不读，阻塞的 WriteFile 会把游戏线程卡死。
// ---------------------------------------------------------------------------

#define QUEUE_LIMIT 1024

typedef struct QNode {
    struct QNode* next;
    char*         line;
} QNode;

static QNode*           g_qHead = NULL;
static QNode*           g_qTail = NULL;
static int              g_qCount = 0;
static CRITICAL_SECTION g_qCs;
static HANDLE           g_qEvent = NULL;

static HANDLE           g_hPipe = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_pipeCs;
static volatile LONG    g_pipeBroken = 0;
static volatile LONG    g_stop = 0;

static HANDLE           g_pipeThread = NULL;
static HANDLE           g_writerThread = NULL;

static void Enqueue(const char* line)
{
    QNode* n = (QNode*)malloc(sizeof(QNode));
    if (!n) return;

    size_t len = strlen(line) + 1;
    n->line = (char*)malloc(len);
    if (!n->line) { free(n); return; }
    memcpy(n->line, line, len);
    n->next = NULL;

    EnterCriticalSection(&g_qCs);
    if (g_qCount >= QUEUE_LIMIT) {
        // 队列满了：丢弃最旧的。宁可丢文本，也不能拖慢游戏。
        QNode* old = g_qHead;
        g_qHead = old->next;
        if (!g_qHead) g_qTail = NULL;
        g_qCount--;
        free(old->line);
        free(old);
    }
    if (g_qTail) g_qTail->next = n; else g_qHead = n;
    g_qTail = n;
    g_qCount++;
    LeaveCriticalSection(&g_qCs);

    if (g_qEvent) SetEvent(g_qEvent);
}

static DWORD WINAPI WriterThreadProc(LPVOID param)
{
    (void)param;
    while (!g_stop)
    {
        WaitForSingleObject(g_qEvent, 500);

        for (;;)
        {
            QNode* n = NULL;
            EnterCriticalSection(&g_qCs);
            if (g_qHead) {
                n = g_qHead;
                g_qHead = n->next;
                if (!g_qHead) g_qTail = NULL;
                g_qCount--;
            }
            LeaveCriticalSection(&g_qCs);
            if (!n) break;

            // 这里是独立线程，WriteFile 阻塞不会影响游戏
            EnterCriticalSection(&g_pipeCs);
            if (g_hPipe != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                if (!WriteFile(g_hPipe, n->line, (DWORD)strlen(n->line), &written, NULL))
                    g_pipeBroken = 1;   // 客户端断开：通知 accept 线程重建实例
            }
            LeaveCriticalSection(&g_pipeCs);

            if (g_logToFile) FileLogLine(n->line);

            free(n->line);
            free(n);
        }
    }
    return 0;
}

static DWORD WINAPI PipeThreadProc(LPVOID param)
{
    (void)param;

    char full[MAX_PATH];
    _snprintf_s(full, sizeof(full), _TRUNCATE, "\\\\.\\pipe\\%s", g_pipeName);

    while (!g_stop)
    {
        HANDLE h = CreateNamedPipeA(
            full,
            PIPE_ACCESS_OUTBOUND,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            1,                  // 单实例：文本 Hook 一般只需一个消费者
            64 * 1024,          // 出缓冲
            0,                  // 入缓冲（单向）
            0,
            NULL);

        if (h == INVALID_HANDLE_VALUE) { Sleep(500); continue; }

        BOOL connected = ConnectNamedPipe(h, NULL)
                       ? TRUE
                       : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (connected)
        {
            EnterCriticalSection(&g_pipeCs);
            g_hPipe = h;
            g_pipeBroken = 0;
            LeaveCriticalSection(&g_pipeCs);

            // 持有连接，直到写失败（客户端断开）或收到停止信号
            while (!g_pipeBroken && !g_stop) Sleep(150);

            EnterCriticalSection(&g_pipeCs);
            if (g_hPipe == h) g_hPipe = INVALID_HANDLE_VALUE;
            LeaveCriticalSection(&g_pipeCs);

            DisconnectNamedPipe(h);
        }
        CloseHandle(h);
    }
    return 0;
}

// ---------------------------------------------------------------------------
// 文本提取与上报
// ---------------------------------------------------------------------------

static void EmitText(const wchar_t* w, const char* hookName)
{
    if (!w || !*w) return;

    int n = (int)wcslen(w);
    while (n > 0 && iswspace(w[n - 1])) n--;          // 去掉尾部空白
    if (n < g_minLen) return;
    if (n > 2047) n = 2047;

    // 去重：游戏每帧重绘，同一句话每秒可能触发几十次
    EnterCriticalSection(&g_textCs);
    DWORD now = GetTickCount();
    if (wcsncmp(g_lastText, w, (size_t)n) == 0 && g_lastText[n] == 0 &&
        (now - g_lastTick) < g_dedupMs)
    {
        LeaveCriticalSection(&g_textCs);
        return;
    }
    wcsncpy_s(g_lastText, 2048, w, (size_t)n);
    g_lastTick = now;
    LeaveCriticalSection(&g_textCs);

    // 统一转 UTF-8 输出
    char utf8[8192];
    int m = WideCharToMultiByte(CP_UTF8, 0, w, n, utf8, (int)sizeof(utf8) - 1, NULL, NULL);
    if (m <= 0) return;
    utf8[m] = 0;

    char line[8704];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
                          "GalToolText\t%lu\t%s\t%s\n",
                          GetCurrentProcessId(), hookName, utf8);
    if (len > 0) Enqueue(line);
}

static void EmitAnsi(const char* s, int len, const char* hookName)
{
    if (!s) return;
    if (len < 0) len = (int)strlen(s);
    if (len <= 0) return;
    if (len > 2000) len = 2000;

    UINT cp = g_codepage;
    if (cp == 0) cp = g_profile ? g_profile->codepage : 0;
    if (cp == 0) cp = CP_ACP;

    wchar_t w[2048];
    int n = MultiByteToWideChar(cp, 0, s, len, w, 2047);
    if (n <= 0) return;
    w[n] = 0;
    EmitText(w, hookName);
}

static void EmitWide(const wchar_t* s, int len, const char* hookName)
{
    if (!s) return;
    if (len < 0) len = (int)wcslen(s);
    if (len <= 0) return;
    if (len > 2000) len = 2000;

    wchar_t w[2048];
    memcpy(w, s, (size_t)len * sizeof(wchar_t));
    w[len] = 0;
    EmitText(w, hookName);
}

// ---------------------------------------------------------------------------
// Hook 实现（转发给原始函数）
// ---------------------------------------------------------------------------

static BOOL WINAPI Hook_TextOutA(HDC hdc, int x, int y, LPCSTR s, int c)
{
    EmitAnsi(s, c, "TextOutA");
    return real_TextOutA ? real_TextOutA(hdc, x, y, s, c) : FALSE;
}

static BOOL WINAPI Hook_TextOutW(HDC hdc, int x, int y, LPCWSTR s, int c)
{
    EmitWide(s, c, "TextOutW");
    return real_TextOutW ? real_TextOutW(hdc, x, y, s, c) : FALSE;
}

static BOOL WINAPI Hook_ExtTextOutA(HDC hdc, int x, int y, UINT opt,
                                    const RECT* rc, LPCSTR s, UINT c, const INT* dx)
{
    EmitAnsi(s, (int)c, "ExtTextOutA");
    return real_ExtTextOutA ? real_ExtTextOutA(hdc, x, y, opt, rc, s, c, dx) : FALSE;
}

static BOOL WINAPI Hook_ExtTextOutW(HDC hdc, int x, int y, UINT opt,
                                    const RECT* rc, LPCWSTR s, UINT c, const INT* dx)
{
    EmitWide(s, (int)c, "ExtTextOutW");
    return real_ExtTextOutW ? real_ExtTextOutW(hdc, x, y, opt, rc, s, c, dx) : FALSE;
}

static int WINAPI Hook_DrawTextA(HDC hdc, LPCSTR s, int c, LPRECT rc, UINT fmt)
{
    EmitAnsi(s, c, "DrawTextA");
    return real_DrawTextA ? real_DrawTextA(hdc, s, c, rc, fmt) : 0;
}

static int WINAPI Hook_DrawTextW(HDC hdc, LPCWSTR s, int c, LPRECT rc, UINT fmt)
{
    EmitWide(s, c, "DrawTextW");
    return real_DrawTextW ? real_DrawTextW(hdc, s, c, rc, fmt) : 0;
}

// 按函数名取「替换函数」与「原始地址存储位置」
static void* ReplacementFor(const char* func, void*** pOriginalSlot)
{
    if (_stricmp(func, "TextOutA")    == 0) { *pOriginalSlot = (void**)&real_TextOutA;    return (void*)Hook_TextOutA; }
    if (_stricmp(func, "TextOutW")    == 0) { *pOriginalSlot = (void**)&real_TextOutW;    return (void*)Hook_TextOutW; }
    if (_stricmp(func, "ExtTextOutA") == 0) { *pOriginalSlot = (void**)&real_ExtTextOutA; return (void*)Hook_ExtTextOutA; }
    if (_stricmp(func, "ExtTextOutW") == 0) { *pOriginalSlot = (void**)&real_ExtTextOutW; return (void*)Hook_ExtTextOutW; }
    if (_stricmp(func, "DrawTextA")   == 0) { *pOriginalSlot = (void**)&real_DrawTextA;   return (void*)Hook_DrawTextA; }
    if (_stricmp(func, "DrawTextW")   == 0) { *pOriginalSlot = (void**)&real_DrawTextW;   return (void*)Hook_DrawTextW; }
    return NULL;
}

// ---------------------------------------------------------------------------
// IAT Hook 安装
// ---------------------------------------------------------------------------

static BOOL PatchModuleIat(HMODULE hMod, const char* dllName, const char* funcName)
{
    void** originalSlot = NULL;
    void*  replacement  = ReplacementFor(funcName, &originalSlot);
    if (!replacement || !originalSlot) return FALSE;

    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    IMAGE_DATA_DIRECTORY impDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return FALSE;

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);

    for (; imp->Name; imp++)
    {
        const char* modName = (const char*)(base + imp->Name);
        if (_stricmp(modName, dllName) != 0) continue;
        if (imp->FirstThunk == 0 || imp->OriginalFirstThunk == 0) continue;

        IMAGE_THUNK_DATA* orig =
            (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iat =
            (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);

        for (; orig->u1.AddressOfData; orig++, iat++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;

            IMAGE_IMPORT_BY_NAME* ibn =
                (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
            if (strcmp((const char*)ibn->Name, funcName) != 0) continue;

            if (g_patchedCount >= MAX_PATCHED) return FALSE;

            // 只在首次记录原始地址：各模块 IAT 槽里存的是同一个函数地址
            void* original = (void*)iat->u1.Function;
            if (*originalSlot == NULL) *originalSlot = original;

            DWORD oldProtect = 0;
            if (!VirtualProtect(&iat->u1.Function, sizeof(void*),
                                PAGE_READWRITE, &oldProtect))
                return FALSE;

            iat->u1.Function = (ULONG_PTR)replacement;

            DWORD tmp = 0;
            VirtualProtect(&iat->u1.Function, sizeof(void*), oldProtect, &tmp);

            g_patched[g_patchedCount].slot     = (void**)&iat->u1.Function;
            g_patched[g_patchedCount].original = original;
            g_patchedCount++;
            return TRUE;
        }
    }
    return FALSE;
}

// 系统 DLL 名单：挂它们的 IAT 没有意义，还可能引入递归风险
static const char* kDeniedModules[] = {
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "gdi32.dll", "gdi32full.dll",
    "user32.dll", "win32u.dll", "advapi32.dll", "msvcrt.dll", "ucrtbase.dll",
    "ole32.dll", "oleaut32.dll", "shell32.dll", "shlwapi.dll", "comctl32.dll",
    "uxtheme.dll", "imm32.dll", "msctf.dll", "version.dll", "psapi.dll",
    "rpcrt4.dll", "sechost.dll", "bcrypt.dll", "crypt32.dll", "comdlg32.dll",
    "winmm.dll", "dsound.dll", "d3d9.dll", "d3d11.dll", "dxgi.dll",
    "opengl32.dll", "texthookdll.dll"
};

static BOOL IsDeniedModule(const wchar_t* moduleName)
{
    char narrow[MAX_PATH];
    if (WideCharToMultiByte(CP_ACP, 0, moduleName, -1, narrow, MAX_PATH, NULL, NULL) <= 0)
        return TRUE;

    for (int i = 0; i < (int)(sizeof(kDeniedModules) / sizeof(kDeniedModules[0])); i++)
        if (_stricmp(narrow, kDeniedModules[i]) == 0) return TRUE;
    return FALSE;
}

static void HookAllTargets(HMODULE hMod)
{
    if (!hMod || !g_profile) return;
    for (int i = 0; i < g_profile->targetCount; i++)
    {
        const HookTarget* t = &g_profile->targets[i];
        if (t->kind != HOOK_IAT) continue;
        PatchModuleIat(hMod, t->module, t->func);
    }
}

// 挂钩主 EXE + 所有非系统模块。
// 引擎可能在 EXE 里，也可能在随游戏加载的某个 DLL 里，两者都要覆盖。
static void HookAllModules(void)
{
    HookAllTargets(GetModuleHandleW(NULL));

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do {
            if (IsDeniedModule(me.szModule)) continue;
            if ((HMODULE)me.modBaseAddr == g_hDll) continue;   // 绝不挂自己（会无限递归）
            HookAllTargets((HMODULE)me.modBaseAddr);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

static void UnhookAll(void)
{
    for (int i = 0; i < g_patchedCount; i++)
    {
        DWORD oldProtect = 0;
        if (!VirtualProtect(g_patched[i].slot, sizeof(void*), PAGE_READWRITE, &oldProtect))
            continue;
        *g_patched[i].slot = g_patched[i].original;
        DWORD tmp = 0;
        VirtualProtect(g_patched[i].slot, sizeof(void*), oldProtect, &tmp);
    }
    g_patchedCount = 0;
}

// ---------------------------------------------------------------------------
// 配置解析（兼容注入器的 -export InstallConfig 单字符串参数约定）
// ---------------------------------------------------------------------------

static const EngineProfile* FindProfile(const wchar_t* name)
{
    char narrow[128];
    if (WideCharToMultiByte(CP_ACP, 0, name, -1, narrow, 128, NULL, NULL) <= 0)
        return NULL;
    for (int i = 0; i < kProfileCount; i++)
        if (_stricmp(narrow, kProfiles[i].name) == 0) return &kProfiles[i];
    return NULL;
}

// 解析 "k=v|k=v"，返回解析出的键值对个数
static int ApplyConfig(const wchar_t* cfg)
{
    if (!cfg || !*cfg) return 0;

    // 用 _TRUNCATE 而非 wcscpy_s：本 DLL 会挂进正在运行的游戏进程，
    // 超长的 -exportarg 绝不能触发无效参数处理器把游戏带走。
    wchar_t copy[2048];
    wcsncpy_s(copy, 2048, cfg, _TRUNCATE);

    int count = 0;
    int minLenSet = 0, dedupSet = 0;   // 显式指定过就不再被 profile 默认值覆盖
    const EngineProfile* newProfile = NULL;

    wchar_t* ctx = NULL;
    wchar_t* pair = wcstok_s(copy, L"|", &ctx);
    while (pair && count < 32)
    {
        wchar_t key[128], val[1024];
        wchar_t* eq = wcschr(pair, L'=');
        if (eq) {
            *eq = 0;
            wcsncpy_s(key, 128,  pair,   _TRUNCATE);
            wcsncpy_s(val, 1024, eq + 1, _TRUNCATE);
        } else {
            wcsncpy_s(key, 128,  pair, _TRUNCATE);
            wcsncpy_s(val, 1024, L"",  _TRUNCATE);
        }

        if (_wcsicmp(key, L"engine") == 0)      { newProfile = FindProfile(val); }
        else if (_wcsicmp(key, L"cp") == 0)     { g_codepage = (UINT)_wtoi(val); }
        else if (_wcsicmp(key, L"log") == 0)    { g_logToFile = (_wtoi(val) != 0); }
        else if (_wcsicmp(key, L"minlen") == 0) { g_minLen = _wtoi(val); minLenSet = 1; }
        else if (_wcsicmp(key, L"dedup") == 0)  { g_dedupMs = (DWORD)_wtoi(val); dedupSet = 1; }
        else if (_wcsicmp(key, L"pipe") == 0) {
            if (WideCharToMultiByte(CP_ACP, 0, val, -1, g_pipeName, sizeof(g_pipeName), NULL, NULL) <= 0)
                strcpy_s(g_pipeName, sizeof(g_pipeName), "GalToolText");
        }

        count++;
        pair = wcstok_s(NULL, L"|", &ctx);
    }

    // profile 的默认值在最后应用，避免「engine= 写在 minlen= 之后」时把显式配置覆盖掉
    if (newProfile) {
        g_profile = newProfile;
        if (!minLenSet) g_minLen = newProfile->minLen;
        if (!dedupSet)  g_dedupMs = newProfile->dedupMs;
    }
    return count;
}

// ---------------------------------------------------------------------------
// 启动 / 停止
// ---------------------------------------------------------------------------

static BOOL StartHooks(void)
{
    if (g_initialized) return TRUE;

    InitializeCriticalSection(&g_textCs);
    InitializeCriticalSection(&g_pipeCs);
    InitializeCriticalSection(&g_qCs);

    g_qEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_qEvent) return FALSE;

    HookAllModules();

    g_writerThread = CreateThread(NULL, 0, WriterThreadProc, NULL, 0, NULL);
    g_pipeThread   = CreateThread(NULL, 0, PipeThreadProc,   NULL, 0, NULL);

    g_initialized = TRUE;

    char msg[1024];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "[TextHookDll] 已安装 profile=%s  cp=%u  挂钩槽=%d  管道=\\\\.\\pipe\\%s  PID=%lu\n",
                g_profile ? g_profile->name : "?",
                g_codepage ? g_codepage : (g_profile ? g_profile->codepage : 0),
                g_patchedCount, g_pipeName, GetCurrentProcessId());
    Enqueue(msg);
    return TRUE;
}

static void StopHooks(void)
{
    if (!g_initialized) return;

    g_stop = 1;
    if (g_qEvent) SetEvent(g_qEvent);

    // 有界等待：DllMain(DLL_PROCESS_DETACH) 里不能无限期阻塞
    if (g_writerThread) { WaitForSingleObject(g_writerThread, 1000); CloseHandle(g_writerThread); g_writerThread = NULL; }
    if (g_pipeThread)   { WaitForSingleObject(g_pipeThread,   1000); CloseHandle(g_pipeThread);   g_pipeThread = NULL; }

    UnhookAll();

    if (g_qEvent) { CloseHandle(g_qEvent); g_qEvent = NULL; }

    DeleteCriticalSection(&g_qCs);
    DeleteCriticalSection(&g_pipeCs);
    DeleteCriticalSection(&g_textCs);

    g_initialized = FALSE;
}

// ---------------------------------------------------------------------------
// 导出函数（与注入器 -export / -exportarg 约定一致：参数指向 UTF-16 字符串）
// ---------------------------------------------------------------------------

// 主入口：解析完整配置后安装挂钩。返回解析出的配置项个数（0 = 参数为空，按默认值安装）
__declspec(dllexport) DWORD WINAPI InstallConfig(LPVOID param)
{
    int n = ApplyConfig(param ? (const wchar_t*)param : NULL);
    StartHooks();
    return (DWORD)(n > 0 ? n : 1);
}

// 兼容入口：允许直接 -export InstallHook -exportarg "engine=..."，参数可选
__declspec(dllexport) DWORD WINAPI InstallHook(LPVOID param)
{
    if (param) ApplyConfig((const wchar_t*)param);
    return StartHooks() ? 1 : 0;
}

// 无参入口：按默认 profile（generic-gdi）安装
__declspec(dllexport) DWORD WINAPI Init(LPVOID param)
{
    (void)param;
    return StartHooks() ? 1 : 0;
}

// 卸载挂钩（可由注入器「卸载 DLL」前调用，也可不调，DllMain 会兜底）
__declspec(dllexport) DWORD WINAPI Unhook(LPVOID param)
{
    (void)param;
    StopHooks();
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        g_hDll = hinstDLL;   // 仅记录句柄，重活留到导出函数里做
    }
    else if (fdwReason == DLL_PROCESS_DETACH)
    {
        // 兜底清理。注意：此处持有加载器锁，故 StopHooks 内部只做有界等待。
        StopHooks();
    }
    return TRUE;
}
