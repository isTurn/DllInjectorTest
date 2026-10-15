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
//    engine=<profile 名>      见下方「引擎适配表」；默认 generic-gdi
//    profilefile=<路径>       指定 profile 文件（默认 DLL 同目录 TextHookDll.profiles.ini）
//    nofile=1                 不读 profile 文件，只用内置的 4 个（排查用）
//    cp=932|936|65001|1200    强制指定 *A 系列文本的代码页（覆盖 profile 默认值）
//    pipe=<名称>              管道名，默认 GalToolText（实际路径 \\.\pipe\<名称>）
//    log=1|0                  是否同时落盘 texthook_log.txt（默认 1，便于无客户端时验证）
//    minlen=<n>               短于此长度的文本丢弃（默认 2）
//    dedup=<ms>               去重窗口，同一文本在该毫秒数内只上报一次（默认 200）
//
//  引擎适配表（S3 起可外部化）：
//    内置 4 个 profile（generic-gdi / generic-gdi-sjis / generic-gdi-gbk /
//    generic-unicode）编译在 DLL 里，始终可用。DLL 同目录的
//    TextHookDll.profiles.ini 可以新增 profile，也可以**同名覆盖**内置的那一个
//    （例如写一个 [generic-gdi] 来调兜底行为）。文件格式见该 ini 内的注释。
//
//    ⚠ 能力边界：文件只能从框架**已知的 6 个函数**里挑选组合挂钩目标
//      （gdi32!TextOutA/W、gdi32!ExtTextOutA/W、user32!DrawTextA/W）。
//      文本提取逻辑（哪个参数是文本）是编译期写死在 ReplacementFor() 里的，
//      所以「写个文件就能适配任意引擎」暂时做不到——新增未知函数属于 S2/S4。
//      文件里写了框架不认识的函数名不会报错（IAT 里找不到而已），但也不会有任何效果。
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

// 用内联字符数组而不是 const char*：profile 现在既能来自编译期常量，
// 也能来自运行期读入的 INI 文件。内联数组让两条路径共用同一套结构，
// 文件加载的 profile 不需要堆分配，也就不存在「g_profile 指向已释放内存」的风险。
#define HT_MODULE_MAX 48
#define HT_FUNC_MAX   48

typedef struct {
    char module[HT_MODULE_MAX];   // 提供函数的 DLL 名，如 "gdi32.dll"
    char func[HT_FUNC_MAX];       // 函数名
    int  kind;                    // 挂钩方式（当前仅 HOOK_IAT）
} HookTarget;

#define PROFILE_NAME_MAX 48

typedef struct {
    char              name[PROFILE_NAME_MAX];
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
// 运行期 profile（S3：外部化）
//
// 从 DLL 同目录的 TextHookDll.profiles.ini 读入，改引擎适配不用重编译。
// 同名 profile 覆盖内置的那一个，所以 [generic-gdi] 可以用来调兜底行为。
//
// ★ 能力边界（必须如实告知，否则使用者会误以为「写个文件就能适配任何引擎」）：
//   文件只能**从框架已知的 6 个函数里挑选和组合**挂钩目标。
//   真正的文本提取逻辑（哪个参数是文本、哪个是长度）编译期写在
//   ReplacementFor() 里，所以文件里写 gdi32.dll,TextOutA 可以，
//   写一个框架不认识的函数则会挂钩失败——那属于 S2/S4 的工作。
// ---------------------------------------------------------------------------

#define MAX_FILE_PROFILES 32
#define MAX_FILE_TARGETS  16
#define MAX_DESC_LEN      128

typedef struct {
    EngineProfile prof;                    // 供 g_profile 指向；prof.targets 指向本结构的 targets
    HookTarget    targets[MAX_FILE_TARGETS];
    char          desc[MAX_DESC_LEN];      // 仅供人读，不参与逻辑
} FileProfile;

static FileProfile g_fileProfiles[MAX_FILE_PROFILES];
static int         g_fileProfileCount = 0;
static BOOL        g_profilesLoaded   = FALSE;   // 是否已经尝试过加载（无论成功与否，只试一次）
static BOOL        g_profileExplicit  = FALSE;   // engine= 是否被显式指定过

// profile 文件的加载结果描述 + 配置告警，由 StartHooks 在初始化完成后写入日志。
// 注意：ApplyConfig 阶段队列和临界区都还没建好，绝不能在那里 Enqueue。
static char g_profileFileMsg[768] = "";
static char g_configWarn[512]     = "";

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

            // 已经指向我们的替换函数说明这个槽挂过了，直接返回。
            // 必须有这道幂等检查：主 EXE 会先被 HookAllModules 显式挂一次，
            // 随后又出现在模块快照里被挂第二次。重复记录会让第二条把
            // original 记成**我们自己的替换函数**，卸载时就会把槽还原成
            // 替换函数——等于没卸，而 DLL 一旦被卸载就是跳进已释放内存。
            if ((void*)iat->u1.Function == replacement) return TRUE;

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
    HMODULE hMain = GetModuleHandleW(NULL);
    HookAllTargets(hMain);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do {
            // 主 EXE 上面已经显式处理过了，而模块快照**也包含它**，必须跳过，
            // 否则同一个 IAT 槽会被挂两次（PatchModuleIat 里的幂等检查是第二道防线）
            if ((HMODULE)me.modBaseAddr == hMain) continue;
            if (IsDeniedModule(me.szModule)) continue;
            if ((HMODULE)me.modBaseAddr == g_hDll) continue;   // 绝不挂自己（会无限递归）
            HookAllTargets((HMODULE)me.modBaseAddr);
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

static void UnhookAll(void)
{
    // 倒序还原：万一同一个槽被记了多条，先写回后记的那条（它可能是我们自己的
    // 替换函数），最后写回最早记下的真实地址，最终状态才正确。
    for (int i = g_patchedCount - 1; i >= 0; i--)
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

// 去掉首尾空白，并把行尾的 CR/LF 一起清掉（INI 可能是 CRLF 也可能是 LF）
static void TrimInPlace(char* s)
{
    if (!s) return;

    char* p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);

    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' '  || s[n - 1] == '\t' ||
                     s[n - 1] == '\r' || s[n - 1] == '\n'))
        s[--n] = 0;
}

// 把 "k=v" 拆开：键写入 key，返回值的指针；没有 '=' 则返回 NULL。
// 会就地修改 pair（把 '=' 写成 '\0'），所以两个 pass 必须各用一份拷贝。
static const wchar_t* SplitPair(wchar_t* pair, wchar_t* key, size_t keyCch)
{
    wchar_t* eq = wcschr(pair, L'=');
    if (!eq) { wcsncpy_s(key, keyCch, pair, _TRUNCATE); return NULL; }
    *eq = 0;
    wcsncpy_s(key, keyCch, pair, _TRUNCATE);
    return eq + 1;
}

// 按窄字符串名查找 profile。文件里的优先，同名可覆盖内置。
static const EngineProfile* FindProfileNarrow(const char* name)
{
    if (!name || !*name) return NULL;

    for (int i = 0; i < g_fileProfileCount; i++)
        if (_stricmp(name, g_fileProfiles[i].prof.name) == 0)
            return &g_fileProfiles[i].prof;

    for (int i = 0; i < kProfileCount; i++)
        if (_stricmp(name, kProfiles[i].name) == 0)
            return &kProfiles[i];

    return NULL;
}

static const EngineProfile* FindProfile(const wchar_t* name)
{
    char narrow[128];
    if (!name || !*name) return NULL;
    if (WideCharToMultiByte(CP_ACP, 0, name, -1, narrow, 128, NULL, NULL) <= 0)
        return NULL;
    return FindProfileNarrow(narrow);
}

// 列出所有可用 profile 名，供「engine= 写错」时给出可操作的提示
static void BuildProfileList(char* out, size_t cch)
{
    out[0] = 0;
    for (int i = 0; i < g_fileProfileCount; i++) {
        if (out[0]) strcat_s(out, cch, ", ");
        strcat_s(out, cch, g_fileProfiles[i].prof.name);
    }
    for (int i = 0; i < kProfileCount; i++) {
        // 文件里已定义的就不再重复列
        if (FindProfileNarrow(kProfiles[i].name) != &kProfiles[i]) continue;
        if (out[0]) strcat_s(out, cch, ", ");
        strcat_s(out, cch, kProfiles[i].name);
    }
}

// 没被 engine= 显式指定过时，把默认 profile 重新解析一遍。
// 这样文件里写了 [generic-gdi] 就能改掉「不传 engine= 时」的兜底行为。
static void RefreshDefaultProfile(void)
{
    if (g_profileExplicit) return;
    const EngineProfile* p = FindProfileNarrow("generic-gdi");
    g_profile = p ? p : &kProfiles[0];
}

// 默认 profile 文件位置：DLL 同目录（和 texthook_log.txt 同一个地方）
static void DefaultProfileFilePath(wchar_t* out, size_t cch)
{
    out[0] = 0;
    if (!g_hDll) return;

    wchar_t p[MAX_PATH];
    if (!GetModuleFileNameW(g_hDll, p, MAX_PATH)) return;

    wchar_t* slash = wcsrchr(p, L'\\');
    if (!slash) return;
    *(slash + 1) = 0;

    swprintf_s(out, cch, L"%s%s", p, L"TextHookDll.profiles.ini");
}

// ---------------------------------------------------------------------------
// INI 解析
//
// 格式：
//   [profile 名]                 名字必须是 ASCII（见下）
//   codepage=932                 *A 系列文本的代码页；0 = 系统 ANSI
//   minlen=2                     短于此长度的文本丢弃
//   dedup=200                    去重窗口（毫秒）
//   hook=gdi32.dll,TextOutA      挂钩目标，可重复；第三段是方式，缺省 iat
//   desc=任意说明文字            仅供人读
//
// 策略：全有或全无。任何一行出错就整份文件不生效、退回内置 profile。
// 半个 profile 生效比完全没生效更难排查，配置文件的一次性读取没必要容错。
// ---------------------------------------------------------------------------

static void LoadProfilesFromFile(const wchar_t* path)
{
    g_profilesLoaded    = TRUE;
    g_fileProfileCount  = 0;
    g_profileFileMsg[0] = 0;

    char narrowPath[MAX_PATH * 3];
    narrowPath[0] = 0;
    if (path && *path)
        WideCharToMultiByte(CP_UTF8, 0, path, -1, narrowPath, sizeof(narrowPath), NULL, NULL);

    if (!path || !*path) {
        _snprintf_s(g_profileFileMsg, sizeof(g_profileFileMsg), _TRUNCATE,
                    "profile 文件：未指定路径，使用内置 %d 个", kProfileCount);
        RefreshDefaultProfile();
        return;
    }

    FILE* f = NULL;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) {
        _snprintf_s(g_profileFileMsg, sizeof(g_profileFileMsg), _TRUNCATE,
                    "profile 文件 %s 不存在或无法读取，使用内置 %d 个", narrowPath, kProfileCount);
        RefreshDefaultProfile();
        return;
    }

    // 吃掉 UTF-8 BOM；没有 BOM 就回到文件头
    unsigned char bom[3] = { 0, 0, 0 };
    if (fread(bom, 1, 3, f) != 3 ||
        !(bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF))
        fseek(f, 0, SEEK_SET);

    char line[1024];
    int  cur     = -1;          // 当前正在填的 profile 下标，-1 = 还没遇到 [section]
    int  lineNo  = 0;
    char err[320];
    err[0] = 0;

    while (!err[0] && fgets(line, sizeof(line), f))
    {
        lineNo++;

        // 行过长判定：fgets 读满缓冲且末尾不是换行时，再偷看一个字符。
        // 只看长度会把「恰好 N-1 字节 + 换行」误判成过长的行。
        size_t ln = strlen(line);
        if (ln == sizeof(line) - 1 && line[ln - 1] != '\n') {
            int c = fgetc(f);
            if (c != '\n' && c != EOF) {
                while (c != '\n' && c != EOF) c = fgetc(f);
                _snprintf_s(err, sizeof(err), _TRUNCATE, "第 %d 行过长", lineNo);
                break;
            }
        }

        TrimInPlace(line);
        if (!line[0] || line[0] == ';' || line[0] == '#') continue;

        // ---- [section] ----
        if (line[0] == '[') {
            char* close = strrchr(line, ']');
            if (!close || close == line + 1 || close[1] != 0) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：[section] 格式不正确", lineNo);
                break;
            }
            *close = 0;
            char* nm = line + 1;
            TrimInPlace(nm);

            if (strlen(nm) >= PROFILE_NAME_MAX) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：profile 名过长（上限 %d 字符）", lineNo, PROFILE_NAME_MAX - 1);
                break;
            }

            // profile 名必须 ASCII。engine= 参数是 UTF-16，比对时按 CP_ACP 转窄，
            // 而文件是 UTF-8；非 ASCII 名字两边必然对不上，不如直接拒绝。
            BOOL ascii = TRUE;
            for (const unsigned char* q = (const unsigned char*)nm; *q; q++)
                if (*q >= 0x80) { ascii = FALSE; break; }
            if (!ascii) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：profile 名必须是 ASCII（非 ASCII 名字无法与 engine= 参数匹配）", lineNo);
                break;
            }

            if (g_fileProfileCount >= MAX_FILE_PROFILES) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "profile 数量超过上限 %d", MAX_FILE_PROFILES);
                break;
            }

            // 重名报错而不是后者覆盖前者：配置文件里的复制粘贴错误应该立刻暴露
            int dup = 0;
            for (int i = 0; i < g_fileProfileCount; i++)
                if (_stricmp(g_fileProfiles[i].prof.name, nm) == 0) { dup = 1; break; }
            if (dup) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：profile [%s] 重复定义", lineNo, nm);
                break;
            }

            cur = g_fileProfileCount++;
            memset(&g_fileProfiles[cur], 0, sizeof(g_fileProfiles[cur]));
            strcpy_s(g_fileProfiles[cur].prof.name, PROFILE_NAME_MAX, nm);
            g_fileProfiles[cur].prof.minLen    = 2;      // 与内置默认一致
            g_fileProfiles[cur].prof.dedupMs   = 200;
            g_fileProfiles[cur].prof.codepage  = 0;
            g_fileProfiles[cur].prof.targets   = g_fileProfiles[cur].targets;  // 指向自己的数组
            continue;
        }

        // ---- key=value ----
        char* eq = strchr(line, '=');
        if (!eq) {
            _snprintf_s(err, sizeof(err), _TRUNCATE,
                        "第 %d 行：既不是 [section] 也不是 key=value", lineNo);
            break;
        }
        *eq = 0;
        char* key = line;
        char* val = eq + 1;
        TrimInPlace(key);
        TrimInPlace(val);

        if (cur < 0) {
            _snprintf_s(err, sizeof(err), _TRUNCATE,
                        "第 %d 行：key=value 出现在任何 [section] 之前", lineNo);
            break;
        }
        FileProfile* fp = &g_fileProfiles[cur];

        if (_stricmp(key, "codepage") == 0 || _stricmp(key, "cp") == 0)
            fp->prof.codepage = (UINT)atoi(val);
        else if (_stricmp(key, "minlen") == 0)
            fp->prof.minLen = atoi(val);
        else if (_stricmp(key, "dedup") == 0)
            fp->prof.dedupMs = (DWORD)atoi(val);
        else if (_stricmp(key, "desc") == 0)
            strcpy_s(fp->desc, MAX_DESC_LEN, val);
        else if (_stricmp(key, "hook") == 0)
        {
            if (fp->prof.targetCount >= MAX_FILE_TARGETS) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：hook 数量超过上限 %d", lineNo, MAX_FILE_TARGETS);
                break;
            }

            // hook=<模块>,<函数>[,<方式>]
            char v[256];
            strcpy_s(v, sizeof(v), val);

            char* c1 = strchr(v, ',');
            if (!c1) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：hook 要写成 模块,函数[,方式]", lineNo);
                break;
            }
            *c1 = 0;
            char* mod  = v;
            char* fn   = c1 + 1;
            char* c2   = strchr(fn, ',');
            char* kind = NULL;
            if (c2) { *c2 = 0; kind = c2 + 1; }
            TrimInPlace(mod);
            TrimInPlace(fn);
            if (kind) TrimInPlace(kind);

            if (!mod[0] || !fn[0]) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：hook 的模块名或函数名为空", lineNo);
                break;
            }

            int k = HOOK_IAT;
            if (kind && kind[0]) {
                if (_stricmp(kind, "iat") == 0) {
                    k = HOOK_IAT;
                } else {
                    // inline / vtable 是 S2 / S5 的内容，还没实现。
                    // 必须报错而不是忽略：静默接受会让使用者以为挂钩装上了。
                    _snprintf_s(err, sizeof(err), _TRUNCATE,
                                "第 %d 行：挂钩方式 \"%s\" 尚未实现（当前仅支持 iat）", lineNo, kind);
                    break;
                }
            }

            if (strlen(mod) >= HT_MODULE_MAX || strlen(fn) >= HT_FUNC_MAX) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：模块名或函数名过长", lineNo);
                break;
            }

            HookTarget* t = &fp->targets[fp->prof.targetCount];
            strcpy_s(t->module, HT_MODULE_MAX, mod);
            strcpy_s(t->func,   HT_FUNC_MAX,   fn);
            t->kind = k;
            fp->prof.targetCount++;
        }
        // 其余键忽略：给前向兼容留空间（将来加 hint= 之类不会让老版本报错）
    }

    fclose(f);

    if (err[0]) {
        // 全有或全无：宁可退回内置，也不要半个 profile 生效
        g_fileProfileCount = 0;
        _snprintf_s(g_profileFileMsg, sizeof(g_profileFileMsg), _TRUNCATE,
                    "profile 文件 %s 加载失败（%s），已退回内置 %d 个",
                    narrowPath, err, kProfileCount);
    } else if (g_fileProfileCount == 0) {
        _snprintf_s(g_profileFileMsg, sizeof(g_profileFileMsg), _TRUNCATE,
                    "profile 文件 %s 已读取但没有定义任何 [profile]，使用内置 %d 个",
                    narrowPath, kProfileCount);
    } else {
        char names[384];
        names[0] = 0;
        for (int i = 0; i < g_fileProfileCount; i++) {
            if (names[0]) strcat_s(names, sizeof(names), ", ");
            strcat_s(names, sizeof(names), g_fileProfiles[i].prof.name);
        }
        _snprintf_s(g_profileFileMsg, sizeof(g_profileFileMsg), _TRUNCATE,
                    "profile 文件 %s 已加载 %d 个：%s",
                    narrowPath, g_fileProfileCount, names);
    }

    RefreshDefaultProfile();
}

// 只在第一次用到 profile 时加载默认文件（DllMain 里不能做这些事，持有加载器锁）
static void EnsureProfilesLoaded(void)
{
    if (g_profilesLoaded) return;

    wchar_t path[MAX_PATH];
    DefaultProfileFilePath(path, MAX_PATH);
    LoadProfilesFromFile(path);
}

// 解析 "k=v|k=v"，返回解析出的键值对个数
static int ApplyConfig(const wchar_t* cfg)
{
    if (!cfg || !*cfg) return 0;

    // ---- 第一遍：profilefile= / nofile= 必须先于 engine= 生效 ----
    // 否则 "engine=X|profilefile=Y" 和 "profilefile=Y|engine=X" 结果不一致。
    {
        wchar_t pass1[2048];
        wcsncpy_s(pass1, 2048, cfg, _TRUNCATE);

        wchar_t wantFile[MAX_PATH];
        wantFile[0] = 0;
        int noFile = 0;

        wchar_t* ctx = NULL;
        for (wchar_t* pair = wcstok_s(pass1, L"|", &ctx);
             pair;
             pair = wcstok_s(NULL, L"|", &ctx))
        {
            wchar_t key[128];
            const wchar_t* val = SplitPair(pair, key, 128);
            if (_wcsicmp(key, L"profilefile") == 0 && val && *val)
                wcsncpy_s(wantFile, MAX_PATH, val, _TRUNCATE);
            else if (_wcsicmp(key, L"nofile") == 0)
                noFile = (val == NULL) ? 1 : (_wtoi(val) != 0);
        }

        if (noFile) {
            // 明确要求不读文件，直接用内置（排查「是不是 profile 文件在作怪」时用）
            g_profilesLoaded   = TRUE;
            g_fileProfileCount = 0;
            _snprintf_s(g_profileFileMsg, sizeof(g_profileFileMsg), _TRUNCATE,
                        "profile 文件：已按 nofile=1 禁用，使用内置 %d 个", kProfileCount);
            RefreshDefaultProfile();
        } else if (wantFile[0]) {
            LoadProfilesFromFile(wantFile);
        } else {
            EnsureProfilesLoaded();
        }
    }

    // ---- 第二遍：常规键值对 ----
    // 用 _TRUNCATE 而非 wcscpy_s：本 DLL 会挂进正在运行的游戏进程，
    // 超长的 -exportarg 绝不能触发无效参数处理器把游戏带走。
    wchar_t copy[2048];
    wcsncpy_s(copy, 2048, cfg, _TRUNCATE);

    int count = 0;
    int minLenSet = 0, dedupSet = 0;   // 显式指定过就不再被 profile 默认值覆盖
    const EngineProfile* newProfile = NULL;

    wchar_t* ctx = NULL;
    for (wchar_t* pair = wcstok_s(copy, L"|", &ctx);
         pair && count < 32;
         pair = wcstok_s(NULL, L"|", &ctx))
    {
        wchar_t key[128];
        const wchar_t* val = SplitPair(pair, key, 128);
        const wchar_t* v = val ? val : L"";

        if (_wcsicmp(key, L"engine") == 0) {
            newProfile = FindProfile(v);
            if (newProfile) {
                g_profileExplicit = TRUE;
            } else {
                // 静默沿用默认值最难排查，这里给出可用清单
                char list[384];
                BuildProfileList(list, sizeof(list));
                _snprintf_s(g_configWarn, sizeof(g_configWarn), _TRUNCATE,
                            "engine= 指定的 profile 未找到，已沿用默认；可用：%s", list);
            }
        }
        else if (_wcsicmp(key, L"cp") == 0)     { g_codepage = (UINT)_wtoi(v); }
        else if (_wcsicmp(key, L"log") == 0)    { g_logToFile = (_wtoi(v) != 0); }
        else if (_wcsicmp(key, L"minlen") == 0) { g_minLen = _wtoi(v); minLenSet = 1; }
        else if (_wcsicmp(key, L"dedup") == 0)  { g_dedupMs = (DWORD)_wtoi(v); dedupSet = 1; }
        else if (_wcsicmp(key, L"pipe") == 0) {
            if (WideCharToMultiByte(CP_ACP, 0, v, -1, g_pipeName, sizeof(g_pipeName), NULL, NULL) <= 0)
                strcpy_s(g_pipeName, sizeof(g_pipeName), "GalToolText");
        }

        count++;
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

    // profile 决定挂哪些函数，必须先于 HookAllModules 就位。
    // InstallConfig 路径下 ApplyConfig 已经加载过，这里是给无参的 Init 兜底。
    EnsureProfilesLoaded();

    // ★ 重新安装时必须复位这两个标志。
    //   StopHooks 会把 g_stop 置 1，而它此前从没被清回过——
    //   于是「Unhook 之后再 InstallConfig」建出来的读写线程会立刻退出，
    //   DLL 看着装好了、实际一个字节都发不出来。
    g_stop         = 0;
    g_pipeBroken   = 0;
    g_patchedCount = 0;

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

    // profile 来源单独一行：使用者最常问的就是「我改的那个文件到底有没有被读到」
    if (g_profileFileMsg[0]) {
        char msg2[1024];
        _snprintf_s(msg2, sizeof(msg2), _TRUNCATE, "[TextHookDll] %s\n", g_profileFileMsg);
        Enqueue(msg2);
    }
    if (g_configWarn[0]) {
        char msg3[1024];
        _snprintf_s(msg3, sizeof(msg3), _TRUNCATE, "[TextHookDll] 警告：%s\n", g_configWarn);
        Enqueue(msg3);
    }
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
