// ============================================================================
//  TestTextHook.c — TextHookDll 的进程内端到端验证
//
//  为什么要有这个程序：
//    docs/text-hook-design.md §10 描述的验证链路要三个进程手工配合
//    （起客户端 → 注入器注入 → 目标程序输出文本），无法自动化。
//    本程序把整条链路收进一个进程：自己 LoadLibrary、自己调 InstallConfig
//    装钩子、自己用 GDI 输出文本、自己读 texthook_log.txt 判断结果。
//
//  覆盖的链路：
//    profile 加载 → IAT 挂钩 → 文本捕获 → 编码转换 → Sink → 落盘
//
//  用法：
//    TestTextHook.exe <TextHookDll 路径> [随仓库分发的 sample ini 路径]
//
//  退出码：0 = 全部通过，2 = 有失败，1 = 用法/加载错误
//
//  编译（MSVC）：
//    cl /nologo /O2 /utf-8 TestTextHook.c /link /OUT:TestTextHook-x64.exe \
//        /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
//    或直接用 test\TextHookDll\build.bat
//
//  ★ 本文件不含任何非 ASCII 字面量：期望值一律用 \uXXXX 转义写在宽字符串里。
//    这样「抓到的文本对不对」与源码文件编码完全无关，可以确定性判断。
// ============================================================================

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

// ---------------------------------------------------------------------------
// 期望值（全部用 \u 转义，不依赖源码编码）
// ---------------------------------------------------------------------------

// "こんにちは" 的 Shift-JIS 字节，由 TextOutA / ExtTextOutA / DrawTextA 输出
static const char kSjisHello[] = "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd";

// 期望从上面那串 SJIS 字节解出来的文本（cp=932）
static const wchar_t kExpectHello[] = L"\u3053\u3093\u306b\u3061\u306f";   // こんにちは

// 宽字符文本，**只**由 TextOutW 输出。场景 2 靠它是否出现来判断 profile 是否真的生效。
static const wchar_t kWideOnlyFromTextOutW[] = L"\u30ef\u30a4\u30c9\u6587\u5b57"; // ワイド文字

// 其它宽字符文本，用来确认 ExtTextOutW / DrawTextW 也在正常工作
static const wchar_t kWideExtTextOut[] = L"ExtTextOutW \u6d4b\u8bd5";
static const wchar_t kWideDrawText[]   = L"DrawTextW sample";

// ---------------------------------------------------------------------------
// 被测 DLL 的导出
// ---------------------------------------------------------------------------

typedef DWORD (WINAPI *pfnExport)(LPVOID);

static pfnExport g_InstallConfig = NULL;
static pfnExport g_Unhook        = NULL;

// ---------------------------------------------------------------------------
// 测试状态
// ---------------------------------------------------------------------------

static int g_failures = 0;

static void Check(int cond, const char* what)
{
    printf("    [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) g_failures++;
}

// ---------------------------------------------------------------------------
// 路径与文件工具
// ---------------------------------------------------------------------------

// 取 "D:\a\b\c.dll" 的目录部分（保留结尾的反斜杠）
static void DirOf(const wchar_t* path, wchar_t* out, size_t cch)
{
    out[0] = 0;
    wcsncpy_s(out, cch, path, _TRUNCATE);
    wchar_t* slash = wcsrchr(out, L'\\');
    if (slash) *(slash + 1) = 0;
}

// 把整份文件读进内存（二进制），返回 malloc 的缓冲区，调用方 free
//
// 用 Win32 而不是 _wfopen_s 的原因：DLL 的写线程是「每条日志一次
// fopen("ab")/fwrite/fclose」，它持有文件的瞬间，CRT 的 fopen 会撞上共享冲突。
// MSVC 把 ERROR_SHARING_VIOLATION 映射成 EACCES(errno 13)，于是我们会偶尔读出
// 「文件不存在」。以前 Sleep(1200) 把这段时间盖住了，改成轮询之后立刻暴露。
// 这里显式要求 FILE_SHARE_READ|WRITE，并在共享冲突时重试几次，把这个窗口吃干净。
static char* ReadWholeFile(const wchar_t* path, size_t* pSize)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int tries = 0; tries < 20; tries++)
    {
        h = CreateFileW(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD e = GetLastError();
        if (e != ERROR_SHARING_VIOLATION) return NULL;   // 真不存在就别重试
        Sleep(10);
    }
    if (h == INVALID_HANDLE_VALUE) return NULL;

    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li)) { CloseHandle(h); return NULL; }
    if (li.QuadPart < 0 || li.QuadPart > 64 * 1024 * 1024) { CloseHandle(h); return NULL; }

    size_t sz = (size_t)li.QuadPart;
    char* buf = (char*)malloc(sz + 1);
    if (!buf) { CloseHandle(h); return NULL; }

    size_t rd = 0;
    while (rd < sz)
    {
        DWORD chunk = 0;
        if (!ReadFile(h, buf + rd, (DWORD)(sz - rd), &chunk, NULL) || chunk == 0) break;
        rd += chunk;
    }
    CloseHandle(h);

    buf[rd] = 0;
    if (pSize) *pSize = rd;
    return buf;
}

// 写一份纯 ASCII 的文本文件（测试用的 ini 内容都是 ASCII）
static int WriteAsciiFile(const wchar_t* path, const char* text)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, path, L"wb") != 0 || !f) return 0;
    size_t n = strlen(text);
    size_t w = fwrite(text, 1, n, f);
    fclose(f);
    return w == n;
}

static void ToUtf8(const wchar_t* w, char* out, size_t cch)
{
    out[0] = 0;
    if (!w) return;
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cch, NULL, NULL);
}

// 有 needle 就返回 1；找不到时把日志全文打出来，方便在 CI 上看清原因
static int LogContains(const char* log, const char* needle)
{
    if (!log || !needle) return 0;
    if (strstr(log, needle)) return 1;
    printf("    ---- 日志全文（未找到 \"%s\"）----\n%s\n    ---- 日志结束 ----\n", needle, log);
    return 0;
}

// 负向断言：needle 不该出现。真出现了就把全文打出来。
static int LogAbsent(const char* log, const char* needle)
{
    if (!log || !needle) return 1;
    if (!strstr(log, needle)) return 1;
    printf("    ---- 日志全文（出现了不该出现的 \"%s\"）----\n%s\n    ---- 日志结束 ----\n",
           needle, log);
    return 0;
}

// ---------------------------------------------------------------------------
// 用 GDI 输出文本（不弹窗：内存 DC + 位图就够驱动 GDI 文本输出）
// ---------------------------------------------------------------------------

static void EmitAllText(void)
{
    HDC     hScreen = GetDC(NULL);
    HDC     hMem    = CreateCompatibleDC(hScreen);
    HBITMAP hBmp    = CreateCompatibleBitmap(hScreen, 800, 600);
    HGDIOBJ hOld    = SelectObject(hMem, hBmp);

    RECT rc;
    rc.left = 10; rc.top = 130; rc.right = 400; rc.bottom = 160;

    // 每个函数各输出一段，方便按函数定位问题
    TextOutA(hMem, 10, 10, kSjisHello, (int)strlen(kSjisHello));
    ExtTextOutA(hMem, 10, 40, 0, NULL, kSjisHello, (UINT)strlen(kSjisHello), NULL);
    TextOutW(hMem, 10, 70, kWideOnlyFromTextOutW, (int)wcslen(kWideOnlyFromTextOutW));
    ExtTextOutW(hMem, 10, 100, 0, NULL, kWideExtTextOut, (UINT)wcslen(kWideExtTextOut), NULL);
    DrawTextA(hMem, kSjisHello, (int)strlen(kSjisHello), &rc, DT_LEFT);
    DrawTextW(hMem, kWideDrawText, -1, &rc, DT_LEFT);

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);
}

// ---------------------------------------------------------------------------
// 直接检查主 EXE 的 IAT —— 验证 Unhook 是否真的把补丁还原了
//
// 为什么不能只看 Unhook 的返回值：它恒返回 1，证明不了任何事。
// 而卸载不干净的真实危害是 IAT 槽仍指向 DLL 内部的替换函数——
// DLL 一旦被卸载，游戏下次调用 TextOut 就是跳进已释放内存。
// ---------------------------------------------------------------------------

// 返回主 EXE 的 IAT 里 (dllName, funcName) 那个槽的当前值；找不到返回 NULL
static void* FindIatSlotValue(const char* dllName, const char* funcName)
{
    BYTE* base = (BYTE*)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    IMAGE_DATA_DIRECTORY impDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!impDir.VirtualAddress) return NULL;

    for (IMAGE_IMPORT_DESCRIPTOR* imp =
             (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);
         imp->Name; imp++)
    {
        if (_stricmp((const char*)(base + imp->Name), dllName) != 0) continue;
        if (!imp->OriginalFirstThunk || !imp->FirstThunk) continue;

        IMAGE_THUNK_DATA* orig = (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iat  = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);

        for (; orig->u1.AddressOfData; orig++, iat++)
        {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
            IMAGE_IMPORT_BY_NAME* ibn =
                (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
            if (strcmp((const char*)ibn->Name, funcName) == 0)
                return (void*)iat->u1.Function;
        }
    }
    return NULL;
}

// 被测 DLL 的加载地址范围
static void DllRange(HMODULE h, BYTE** lo, BYTE** hi)
{
    BYTE* base = (BYTE*)h;
    *lo = base;
    *hi = base;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    *hi = base + nt->OptionalHeader.SizeOfImage;
}

// 框架已知的 6 个挂钩目标，用来逐槽检查
static const struct { const char* mod; const char* fn; } kCheckTargets[] = {
    { "gdi32.dll",  "TextOutA"    },
    { "gdi32.dll",  "TextOutW"    },
    { "gdi32.dll",  "ExtTextOutA" },
    { "gdi32.dll",  "ExtTextOutW" },
    { "user32.dll", "DrawTextA"   },
    { "user32.dll", "DrawTextW"   },
};

// 返回还指向 DLL 内部的槽的数量（0 = 卸载干净）
static int CountIatSlotsInsideDll(HMODULE hDll)
{
    BYTE* lo = NULL;
    BYTE* hi = NULL;
    DllRange(hDll, &lo, &hi);
    if (!lo || lo == hi) return -1;

    int leaked = 0;
    for (int i = 0; i < (int)(sizeof(kCheckTargets) / sizeof(kCheckTargets[0])); i++)
    {
        void* v = FindIatSlotValue(kCheckTargets[i].mod, kCheckTargets[i].fn);
        if (!v) continue;                       // 本 EXE 没导入这个函数，跳过
        if ((BYTE*)v >= lo && (BYTE*)v < hi) {
            leaked++;
            printf("      泄漏的槽: %s!%s -> %p（落在 DLL 内 [%p,%p)）\n",
                   kCheckTargets[i].mod, kCheckTargets[i].fn, v, lo, hi);
        }
    }
    return leaked;
}

// 这两个全局状态被 WaitLog / HasLeakedSlots 用到，所以必须声明在使用点之前
static const wchar_t* g_logPath       = NULL;
static HMODULE        g_hDllUnderTest = NULL;

// 「还有槽没还原」——给 WaitWhileTrue 当回调用。
// 注意 CountIatSlotsInsideDll 的三态：0 = 干净，-1 = 取不到 DLL 范围，>0 = 泄漏数。
// -1 也算「不正常」，所以判据是 != 0；否则取不到范围时会被当成已还原。
static int HasLeakedSlots(void)
{
    return CountIatSlotsInsideDll(g_hDllUnderTest) != 0;
}

// ---------------------------------------------------------------------------
// 等待日志落盘
//
// 为什么不再用固定 Sleep：写线程是「队列一有东西就 SetEvent 立刻醒」的，
// 一行文本从入队到 fclose 通常只要几毫秒。原来的 Sleep(700) / Sleep(1200)
// 把最坏情况当成了常态，8 个场景累积下来就是几十秒纯等待——跑一轮全量回归
// 一半时间花在 Sleep 上。这里改成轮询：正常情况下立刻返回，超时预算还是
// 原来那个量，所以「等不到」的语义没变。
// ---------------------------------------------------------------------------

static int WaitLog(const char* needle, int timeoutMs)
{
    DWORD start = GetTickCount();
    for (;;)
    {
        size_t sz = 0;
        char* log = ReadWholeFile(g_logPath, &sz);
        int found = (log && needle && strstr(log, needle)) ? 1 : 0;
        free(log);
        if (found) return 1;
        if ((int)(GetTickCount() - start) >= timeoutMs) return 0;
        Sleep(20);
    }
}

// 等某个条件成立（用于「卸载后 IAT 必须还原」这类不需要读日志的检查）。
// g_Unhook 内部会同步等写线程和管道线程退出，正常情况下返回时就已经还原了；
// 留这个短窗口只是不想让断言依赖那个实现细节。
static void WaitWhileTrue(int (*stillBad)(void), int timeoutMs)
{
    DWORD start = GetTickCount();
    while (stillBad() && (int)(GetTickCount() - start) < timeoutMs) Sleep(20);
}

// ---------------------------------------------------------------------------
// 场景
// ---------------------------------------------------------------------------

typedef struct {
    const char*    title;
    const wchar_t* cfg;               // 传给 InstallConfig 的配置串
    const char*    expectBanner;      // 启动横幅里必须出现的子串（NULL = 不检查）
    const char*    expectAbsent;      // 启动横幅里必须**不**出现的子串（NULL = 不检查）
    int            expectHello;       // 是否应抓到 kExpectHello
    int            expectWide;        // 是否应抓到 kWideOnlyFromTextOutW
} Scenario;

// 跑一个场景：清日志 -> 装钩子 -> 输出文本 -> 查日志 -> 卸钩子
static void RunScenario(const Scenario* sc)
{
    printf("\n  --- %s ---\n", sc->title);

    // 每次场景都从空日志开始，否则上一个场景的文本会污染判断
    DeleteFileW(g_logPath);

    DWORD rc = g_InstallConfig((LPVOID)sc->cfg);
    Check(rc > 0, "InstallConfig 返回成功");

    // 等启动横幅整组落盘。锚点选「动态取址：」这一行，因为它固定排在
    // 逐目标报告行之后——只等「已安装 profile=」会在多线程抢跑时提前返回，
    // 后面的「N 个模块 / N 个槽」还没刷出来，断言就会误判成「没挂上」。
    WaitLog("动态取址：", 3000);

    size_t sz = 0;
    char* log = ReadWholeFile(g_logPath, &sz);
    Check(log != NULL, "texthook_log.txt 已生成");
    if (!log) return;

    if (sc->expectBanner)
        Check(LogContains(log, sc->expectBanner), sc->expectBanner);
    if (sc->expectAbsent)
        Check(LogAbsent(log, sc->expectAbsent), sc->expectAbsent);

    free(log);

    char utf8Hello[128], utf8Wide[128];
    ToUtf8(kExpectHello, utf8Hello, sizeof(utf8Hello));
    ToUtf8(kWideOnlyFromTextOutW, utf8Wide, sizeof(utf8Wide));

    // 输出文本，然后等**最后**一个应当被捕获的文本落盘（宽字符排在后面）
    EmitAllText();
    WaitLog(sc->expectWide ? utf8Wide : utf8Hello, 3000);

    log = ReadWholeFile(g_logPath, &sz);
    if (!log) { Check(0, "重新读取 texthook_log.txt"); return; }

    if (sc->expectHello) {
        Check(LogContains(log, utf8Hello), "抓到 TextOutA 的 SJIS 文本并正确转成 UTF-8");
    } else {
        Check(LogAbsent(log, utf8Hello), "不应抓到 SJIS 文本");
    }

    if (sc->expectWide) {
        Check(LogContains(log, utf8Wide), "抓到 TextOutW 的宽字符文本");
    } else {
        Check(LogAbsent(log, utf8Wide), "不应抓到 TextOutW 的文本（该 profile 没挂它）");
    }

    free(log);

    DWORD uh = g_Unhook(NULL);
    (void)uh;   // 恒返回 1，单看它证明不了什么，真正的验证在下面
    WaitWhileTrue(HasLeakedSlots, 2000);

    // 卸载是否真的生效：主 EXE 的 IAT 槽不应再指向 DLL 内部。
    // 这条检查就是用来抓「主 EXE 被重复挂钩 → 卸载时把槽还原成替换函数」的。
    Check(CountIatSlotsInsideDll(g_hDllUnderTest) == 0,
          "Unhook 后主 EXE 的 IAT 已完全还原（无槽指向 DLL 内部）");
}

// ---------------------------------------------------------------------------
// 场景 6：动态取址（GetProcAddress）
//
// 为什么必须有：IAT Hook 只改导入表。引擎若用
//     p = GetProcAddress(GetModuleHandleA("gdi32.dll"), "TextOutA");
// 自己取址再调用，导入表里根本没有这个函数，钩子就抓不到——而使用者看到的
// 现象是「钩子报告挂上了 N 个槽，但一句话都没有」。
//
// 这里的判据非常直接：装钩子后 GetProcAddress 返回的**不应**是 gdi32 里的
// 真实地址（应该被重定向到 DLL 内的替换函数）；卸载后必须还原成真实地址。
// 再补一条行为验证：通过这个指针真的调一次，文本必须被捕获。
// ---------------------------------------------------------------------------

static void RunDynamicScenario(void)
{
    printf("\n  --- 场景 6：动态取址（GetProcAddress 被重定向）---\n");

    DeleteFileW(g_logPath);

    // 先记下真实的 gdi32!TextOutA 地址（此时钩子还没装，取到的一定是真地址）
    HMODULE hGdi = GetModuleHandleA("gdi32.dll");
    void* realTextOutA = (void*)GetProcAddress(hGdi, "TextOutA");
    Check(realTextOutA != NULL, "能取到 gdi32!TextOutA 的真实地址（基线）");

    static const wchar_t cfg[] = L"engine=generic-gdi|cp=932|dedup=0|log=1";
    DWORD rc = g_InstallConfig((LPVOID)cfg);
    Check(rc > 0, "InstallConfig 返回成功（动态取址场景）");
    WaitLog("动态取址：", 3000);

    // 装好钩子后再取一次：必须被重定向到 DLL 内部
    void* dynTextOutA = (void*)GetProcAddress(hGdi, "TextOutA");
    BYTE* lo = NULL;
    BYTE* hi = NULL;
    DllRange(g_hDllUnderTest, &lo, &hi);

    Check(dynTextOutA != NULL && dynTextOutA != realTextOutA,
          "装钩子后 GetProcAddress 不再返回 gdi32 的真实地址");
    Check(dynTextOutA != NULL && (BYTE*)dynTextOutA >= lo && (BYTE*)dynTextOutA < hi,
          "GetProcAddress 返回的是 DLL 内的替换函数");

    // 行为验证：通过这个动态取得的指针真的调一次，文本必须被抓到。
    // 这条比地址比对更接近真实场景——引擎就是这么用的。
    if (dynTextOutA) {
        HDC hScreen = GetDC(NULL);
        HDC hMem    = CreateCompatibleDC(hScreen);
        HBITMAP hBmp = CreateCompatibleBitmap(hScreen, 800, 600);
        HGDIOBJ hOld = SelectObject(hMem, hBmp);

        typedef BOOL (WINAPI *pTextOutA)(HDC, int, int, LPCSTR, int);
        ((pTextOutA)dynTextOutA)(hMem, 10, 10, kSjisHello, (int)strlen(kSjisHello));

        SelectObject(hMem, hOld);
        DeleteObject(hBmp);
        DeleteDC(hMem);
        ReleaseDC(NULL, hScreen);
    }

    {
        char waitHello[128];
        ToUtf8(kExpectHello, waitHello, sizeof(waitHello));
        WaitLog(waitHello, 3000);
    }
    size_t sz = 0;
    char* log = ReadWholeFile(g_logPath, &sz);
    if (log) {
        char utf8Hello[128];
        ToUtf8(kExpectHello, utf8Hello, sizeof(utf8Hello));
        Check(LogContains(log, utf8Hello),
              "通过动态取得的地址调用，文本同样被捕获");
        // 启动横幅里应该报告动态取址的覆盖情况
        Check(LogContains(log, "动态取址"),
              "启动横幅报告了动态取址的覆盖情况");
        free(log);
    } else {
        Check(0, "重新读取 texthook_log.txt（动态取址场景）");
    }

    g_Unhook(NULL);
    WaitWhileTrue(HasLeakedSlots, 2000);

    // 卸载后必须还原：GetProcAddress 又要返回真实地址
    void* afterTextOutA = (void*)GetProcAddress(hGdi, "TextOutA");
    Check(afterTextOutA == realTextOutA,
          "Unhook 后 GetProcAddress 恢复返回真实地址");
}

// ---------------------------------------------------------------------------
// 场景 7：通用转发器（text= / len= / argc=）
//
// 为什么必须有：S3 完整版把「第几个参数是文本」也外部化了，这是**新代码里
// 最危险的一段**——它按 argc 与 conv 生成 128 个 thunk，用错一个就是弹歪栈。
// 而它的失败方式恰好是「崩溃」而不是「抓不到文本」，所以必须真的调一次。
//
// 设计上的取巧：拿框架**本来就认识**的 TextOutA 来测，但 profile 里故意不
// 写内置提取器能识别的形式——加上 text= / len= / argc= 之后，挂钩路径走的
// 就是通用转发器（`t->textArg > 0` 分支），与「框架不认识的函数」完全同一条
// 代码路径。好处是不用编一个测试 DLL 就能验证真实参数布局。
//
// TextOutA 的真实签名（5 个参数，文本在第 4 个，长度在第 5 个）：
//     BOOL WINAPI TextOutA(HDC hdc, int x, int y, LPCSTR s, int cch);
// ---------------------------------------------------------------------------

static void RunGenericScenario(const wchar_t* iniGeneric)
{
    printf("\n  --- 场景 7：通用转发器（profile 用 text=/len=/argc= 声明参数位置）---\n");

    DeleteFileW(g_logPath);

    wchar_t cfg[1024];
    swprintf_s(cfg, 1024,
               L"profilefile=%ls|engine=test-generic|dedup=0|log=1", iniGeneric);

    DWORD rc = g_InstallConfig((LPVOID)cfg);
    Check(rc > 0, "InstallConfig 返回成功（通用转发器场景）");
    WaitLog("动态取址：", 3000);

    size_t sz = 0;
    char* log = ReadWholeFile(g_logPath, &sz);
    if (log) {
        Check(LogContains(log, "已安装 profile=test-generic"),
              "启动横幅确认用了文件里的 test-generic");
        // 这一行是通用转发器是否真的接管的直接证据：
        // 挂上了就该报告「N 个模块 / N 个槽」，而不是「未挂钩」。
        Check(LogContains(log, "gdi32.dll!TextOutA → "),
              "启动横幅逐个报告了目标 TextOutA");
        Check(LogAbsent(log, "未挂钩"),
              "TextOutA 没有被判成「未挂钩」（说明通用转发器接住了它）");
        free(log);
    } else {
        Check(0, "读取 texthook_log.txt（通用转发器场景）");
    }

    // 真的调一次 TextOutA。如果 argc / conv 写错，这里会直接崩掉进程——
    // 也就是说「能走到下面那条断言」本身就是弹栈正确的证明。
    HDC     hScreen = GetDC(NULL);
    HDC     hMem    = CreateCompatibleDC(hScreen);
    HBITMAP hBmp    = CreateCompatibleBitmap(hScreen, 800, 600);
    HGDIOBJ hOld    = SelectObject(hMem, hBmp);
    TextOutA(hMem, 10, 10, kSjisHello, (int)strlen(kSjisHello));
    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);

    char utf8Hello[128];
    ToUtf8(kExpectHello, utf8Hello, sizeof(utf8Hello));
    WaitLog(utf8Hello, 3000);

    log = ReadWholeFile(g_logPath, &sz);
    if (log) {
        Check(LogContains(log, utf8Hello),
              "通用转发器按 text=4 / len=5 正确取到文本并转成 UTF-8");

        // 只挂 TextOutA，TextOutW 必须抓不到——否则说明 profile 的挂钩集合
        // 没被尊重（比如通用槽位串了）。
        char utf8Wide[128];
        ToUtf8(kWideOnlyFromTextOutW, utf8Wide, sizeof(utf8Wide));
        Check(LogAbsent(log, utf8Wide),
              "通用转发器场景没有顺带抓到 TextOutW（该 profile 没挂它）");
        free(log);
    } else {
        Check(0, "重新读取 texthook_log.txt（通用转发器场景）");
    }

    g_Unhook(NULL);
    WaitWhileTrue(HasLeakedSlots, 2000);
    Check(CountIatSlotsInsideDll(g_hDllUnderTest) == 0,
          "Unhook 后 IAT 已还原（通用转发器槽位也要还原干净）");
}

// ---------------------------------------------------------------------------
// 场景 8：文本里的控制字符必须被清洗
//
// 为什么值得单独一个场景：管道协议是「一行一条消息」（以 \n 分帧）。
// 文本里只要含一个换行，一条消息就被拆成两条；含 \t 则客户端按 tab 切字段
// 时会错位（表现为「hook 列里带着文本，且文本被打印两遍」）。
// GalGame 里一句话分多行显示非常常见，所以这是实战会遇到的问题，不是理论问题。
//
// 这个场景不需要新 profile —— 用内置 generic-gdi 就够，重点是把带 \t / \r / \n
// 的字节喂进去，然后断言日志里出现的是「用空格连接的一整行」。
// ---------------------------------------------------------------------------

// "こんにちは" + TAB + "こんにちは" + CRLF + "こんにちは"（全部 SJIS）
static const char kSjisWithControls[] =
    "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd"
    "\x09"
    "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd"
    "\x0d\x0a"
    "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd";

static void RunSanitizeScenario(void)
{
    printf("\n  --- 场景 8：文本里的 \\t / \\r / \\n 必须被替换成空格（不能拆行）---\n");

    DeleteFileW(g_logPath);

    DWORD rc = g_InstallConfig((LPVOID)L"engine=generic-gdi|cp=932|dedup=0|log=1");
    Check(rc > 0, "InstallConfig 返回成功（控制字符场景）");
    WaitLog("动态取址：", 3000);

    HDC     hScreen = GetDC(NULL);
    HDC     hMem    = CreateCompatibleDC(hScreen);
    HBITMAP hBmp    = CreateCompatibleBitmap(hScreen, 800, 600);
    HGDIOBJ hOld    = SelectObject(hMem, hBmp);
    TextOutA(hMem, 10, 10, kSjisWithControls, (int)strlen(kSjisWithControls));
    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);

    WaitLog("こんにちは", 3000);

    size_t sz = 0;
    char* log = ReadWholeFile(g_logPath, &sz);
    if (!log) {
        Check(0, "读取 texthook_log.txt（控制字符场景）");
        g_Unhook(NULL);
        return;
    }

    // 正向：三句 hello 被空格连成一整行。\t → 1 个空格，\r\n → 2 个空格。
    char hello[128];
    ToUtf8(kExpectHello, hello, sizeof(hello));
    char expect[256];
    sprintf_s(expect, sizeof(expect), "%s %s  %s", hello, hello, hello);
    Check(LogContains(log, expect),
          "\\t / \\r / \\n 被替换成空格，整段文本留在同一行");

    // 反向：逐行扫描，含 hello 的那条消息里不能再出现 tab / CR。
    // 只看「这一行是不是被拆开了」不够——拆开之后每一段都还是合法的 hello，
    // 所以必须直接检查分隔符有没有被清掉。
    int badLines = 0, helloLines = 0;
    for (const char* p = log; p && *p; ) {
        const char* e = strchr(p, '\n');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        char line[4096];
        if (n >= sizeof(line)) n = sizeof(line) - 1;
        memcpy(line, p, n);
        line[n] = 0;

        if (strstr(line, hello)) {
            helloLines++;
            // 消息格式是 "GalToolText\t<pid>\t<hook>\t<text>"，前三个 tab 是协议字段，
            // 第四个及以后才属于文本内容。
            int tabs = 0;
            for (const char* q = line; *q; q++) if (*q == '\t') tabs++;
            if (tabs > 3 || strchr(line, '\r')) badLines++;
        }
        if (!e) break;
        p = e + 1;
    }
    Check(helloLines > 0, "日志里确实有含 hello 的消息行");
    Check(badLines == 0, "文本字段内没有残留 tab / CR（消息没有被切碎）");

    free(log);

    g_Unhook(NULL);
    WaitWhileTrue(HasLeakedSlots, 2000);
    Check(CountIatSlotsInsideDll(g_hDllUnderTest) == 0,
          "Unhook 后 IAT 已还原（控制字符场景）");
}

// ---------------------------------------------------------------------------
// 场景 5：命名管道
//
// 为什么必须有：前面 4 个场景全程没有客户端连管道，只靠 texthook_log.txt
// 判断结果，于是「管道」这条主链路的生命周期完全没被验证过——而它恰好是
// 最容易出问题的地方：
//   管道线程平时阻塞在 ConnectNamedPipe 上（没有客户端时），而 g_stop 只是
//   一个被**轮询**的标志位，叫不醒它。卸载时它不退出就会变成僵尸，一直占着
//   \\.\pipe\<name> 那个实例（nMaxInstances=1），于是**下一次安装**的
//   CreateNamedPipeA 必然失败——表现为「卸载再重装之后，管道再也传不出一个字节」。
//
// 检查三件事：
//   a) 有客户端时文本能真的从管道出来（管道主链路可用）
//   b) 卸载后管道名彻底空闲（僵尸线程没了）—— 这一条就是上面那个 bug 的回归防线
//   c) 反复「无客户端安装 -> 卸载」后进程线程数不增长
// ---------------------------------------------------------------------------

static int CountProcessThreads(void)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    int n = 0;
    DWORD me = GetCurrentProcessId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == me) n++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return n;
}

// 作为客户端连上管道，带超时（实例还没建出来时 CreateFile 会失败，需要重试）
static HANDLE PipeConnect(const wchar_t* pipeName, DWORD timeoutMs)
{
    wchar_t full[MAX_PATH];
    swprintf_s(full, MAX_PATH, L"\\\\.\\pipe\\%s", pipeName);

    DWORD deadline = GetTickCount() + timeoutMs;
    for (;;) {
        HANDLE h = CreateFileW(full, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) return h;
        if ((long)(GetTickCount() - deadline) >= 0) return INVALID_HANDLE_VALUE;
        Sleep(50);
    }
}

// 读一行（到 '\n' 为止），带超时。返回读到的字节数，-1 = 超时/管道断开。
static int PipeReadLine(HANDLE h, char* out, size_t cch, DWORD timeoutMs)
{
    size_t used = 0;
    DWORD deadline = GetTickCount() + timeoutMs;
    out[0] = 0;

    while (used + 1 < cch) {
        DWORD avail = 0;
        if (!PeekNamedPipe(h, NULL, 0, NULL, &avail, NULL)) return -1;
        if (avail == 0) {
            if ((long)(GetTickCount() - deadline) >= 0) return -1;
            Sleep(20);
            continue;
        }
        DWORD got = 0;
        if (!ReadFile(h, out + used, (DWORD)(cch - 1 - used), &got, NULL) || got == 0)
            return -1;
        used += got;
        out[used] = 0;
        if (memchr(out, '\n', used)) return (int)used;
    }
    return (int)used;
}

// 管道名是否已经空闲：我们按同样的 nMaxInstances=1 自己建一个实例，
// 建得起来才说明原来那个实例真的被释放了。这是判断「管道线程是否退出」
// 最直接的观测方式——不需要去猜线程数，也不需要连上去试探。
static int PipeNameIsFree(const wchar_t* pipeName)
{
    wchar_t full[MAX_PATH];
    swprintf_s(full, MAX_PATH, L"\\\\.\\pipe\\%s", pipeName);

    HANDLE h = CreateNamedPipeW(full, PIPE_ACCESS_OUTBOUND,
                                PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 0, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    CloseHandle(h);
    return 1;
}

static void RunPipeScenario(void)
{
    printf("\n  --- 场景 5：命名管道（文本真的从管道出来 + 卸载后不留僵尸线程）---\n");

    // 带 PID 的唯一管道名：避免和真实游戏、或同时跑的另一个测试实例抢同名管道
    wchar_t pipeName[64];
    swprintf_s(pipeName, 64, L"GalToolTextTest_%lu", GetCurrentProcessId());

    wchar_t cfg[512];
    swprintf_s(cfg, 512, L"engine=generic-gdi|cp=932|dedup=0|log=0|pipe=%ls", pipeName);

    // ---- a) 有客户端时能真的收到文本 --------------------------------------
    DWORD rc = g_InstallConfig((LPVOID)cfg);
    Check(rc > 0, "InstallConfig 返回成功（管道场景）");

    HANDLE hCli = PipeConnect(pipeName, 3000);
    Check(hCli != INVALID_HANDLE_VALUE, "能作为客户端连上命名管道");
    if (hCli == INVALID_HANDLE_VALUE) { g_Unhook(NULL); return; }

    // 第二个消费者：多实例的意义就在这里。原先 nMaxInstances=1 时这次连接会
    // 直接被拒绝（CreateFile 拿不到实例），使用者只会看到「客户端连不上」。
    HANDLE hCli2 = PipeConnect(pipeName, 3000);
    Check(hCli2 != INVALID_HANDLE_VALUE, "第二个消费者也能连上（管道是多实例的）");

    Sleep(300);          // 等管道线程把 g_hPipe 装上再发文本
    EmitAllText();

    char line[4096];
    int n = PipeReadLine(hCli, line, sizeof(line), 5000);
    Check(n > 0, "从管道收到文本行");

    char utf8Hello[128];
    ToUtf8(kExpectHello, utf8Hello, sizeof(utf8Hello));
    Check(n > 0 && strstr(line, utf8Hello) != NULL,
          "管道收到的内容正确（SJIS -> UTF-8）");
    if (n > 0 && strstr(line, utf8Hello) == NULL)
        printf("      实际收到：%s\n", line);

    // 广播语义：第二个消费者必须收到**同一行**，而不是只有第一个能拿到
    if (hCli2 != INVALID_HANDLE_VALUE) {
        char line2[4096];
        int n2 = PipeReadLine(hCli2, line2, sizeof(line2), 5000);
        Check(n2 > 0 && strstr(line2, utf8Hello) != NULL,
              "第二个消费者也收到了同一行（广播而不是独占）");
        if (n2 > 0 && strstr(line2, utf8Hello) == NULL)
            printf("      第二个消费者收到：%s\n", line2);
        CloseHandle(hCli2);
    }

    CloseHandle(hCli);
    Sleep(300);          // 让管道线程发现客户端断开、重建实例

    // ---- b) 卸载后管道名必须彻底空闲 --------------------------------------
    //      修复前：管道线程还阻塞在 ConnectNamedPipe 里，实例没释放 -> 这里 FAIL
    g_Unhook(NULL);
    Sleep(600);
    Check(PipeNameIsFree(pipeName),
          "Unhook 后管道实例已释放（没有卡在 ConnectNamedPipe 的僵尸线程）");

    // ---- c) 反复「无客户端安装 -> 卸载」不应残留线程 -----------------------
    //      这是最贴近真实的路径：注入后没起客户端，然后重新注入。
    //      基线在**这里**取，不能取在进程启动时：GDI 首次使用（GetDC）会让系统
    //      懒加载一个线程，把进程线程数永久抬高 1 —— 拿它当基线会误报。
    //      这里测的是「安装/卸载本身带来的增量」，与环境无关。
    const int cycles = 3;
    int tBase = CountProcessThreads();
    for (int i = 0; i < cycles; i++) {
        g_InstallConfig((LPVOID)cfg);   // 故意不连客户端
        Sleep(500);                     // 给它足够时间阻塞在 ConnectNamedPipe 上
        g_Unhook(NULL);
        Sleep(400);
    }
    int tAfter = CountProcessThreads();

    Check(PipeNameIsFree(pipeName),
          "多轮「无客户端安装->卸载」之后管道名仍然空闲");
    printf("      线程数：%d -> %d（期间做了 %d 轮「无客户端安装->卸载」）\n",
           tBase, tAfter, cycles);
    Check(tAfter == tBase, "反复安装/卸载没有残留工作线程（线程数回到本轮基线）");
}

// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    // 关掉 stdout 缓冲。这个测试会在进程内真的挂钩、真的调 API，
    // 一旦某个场景把进程打崩（访问违例），块缓冲会把崩溃前所有 [PASS]/[FAIL]
    // 一起吞掉，只留下一个空文件和「什么都没打印」的假象——排查时最要命的
    // 就是分不清「没跑到」和「跑完了但输出丢了」。
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("TestTextHook — TextHookDll 进程内端到端验证\n");
    printf("================================================\n");

    if (argc < 2) {
        printf("用法: TestTextHook.exe <TextHookDll 路径> [sample ini 路径] [只跑的场景号 1-8]\n");
        return 1;
    }

    // 第三个参数用于调试：在全新进程里只跑某一个场景。
    // 这是区分「跨场景污染（Unhook 没还原干净）」和「该场景自身有问题」的关键手段。
    int only = (argc >= 4) ? atoi(argv[3]) : 0;
    if (only) printf("（只跑场景 %d）\n", only);

    // argv 是 ACP 编码，统一转宽字符后再处理路径
    wchar_t dllArg[MAX_PATH], sampleArg[MAX_PATH];
    dllArg[0] = sampleArg[0] = 0;
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, dllArg, MAX_PATH);
    if (argc >= 3) MultiByteToWideChar(CP_ACP, 0, argv[2], -1, sampleArg, MAX_PATH);

    wchar_t dllPath[MAX_PATH];
    if (!GetFullPathNameW(dllArg, MAX_PATH, dllPath, NULL)) {
        printf("[ERROR] 无法解析 DLL 路径\n");
        return 1;
    }

    wchar_t dir[MAX_PATH];
    DirOf(dllPath, dir, MAX_PATH);

    wchar_t logPath[MAX_PATH], iniGood[MAX_PATH], iniBad[MAX_PATH], iniGeneric[MAX_PATH];
    swprintf_s(logPath, MAX_PATH, L"%stexthook_log.txt", dir);
    swprintf_s(iniGood, MAX_PATH, L"%s_test_profiles_good.ini", dir);
    swprintf_s(iniBad,  MAX_PATH, L"%s_test_profiles_bad.ini", dir);
    swprintf_s(iniGeneric, MAX_PATH, L"%s_test_profiles_generic.ini", dir);
    g_logPath = logPath;

    printf("DLL      : %ls\n", dllPath);
    printf("工作目录 : %ls\n", dir);

    // ---- 1. 载入 DLL，按**无修饰**名取导出 ------------------------------------
    //      x86 下若缺 .def，WINAPI 会把导出名修饰成 _InstallConfig@4，
    //      这里就会拿到 NULL —— 这个检查是「导出名一致性」的回归防线。
    printf("\n  --- 导出表 ---\n");
    HMODULE h = LoadLibraryW(dllPath);
    if (!h) {
        printf("[ERROR] LoadLibrary 失败，GetLastError=%lu\n", GetLastError());
        return 1;
    }
    Check(h != NULL, "LoadLibrary 成功");
    g_hDllUnderTest = h;

    g_InstallConfig = (pfnExport)GetProcAddress(h, "InstallConfig");
    g_Unhook        = (pfnExport)GetProcAddress(h, "Unhook");
    Check(g_InstallConfig != NULL, "按无修饰名取到 InstallConfig（x86 下验证 .def 生效）");
    Check(g_Unhook        != NULL, "按无修饰名取到 Unhook");
    Check(GetProcAddress(h, "Init")        != NULL, "按无修饰名取到 Init");
    Check(GetProcAddress(h, "InstallHook") != NULL, "按无修饰名取到 InstallHook");
    if (!g_InstallConfig || !g_Unhook) {
        printf("[ERROR] 导出函数缺失，后续场景无法进行\n");
        return 1;
    }

    // ---- 2. 准备测试用 profile 文件 -------------------------------------------
    //      故意用 CRLF，覆盖 ini 解析里的换行处理
    static const char kIniGoodText[] =
        "; generated by TestTextHook\r\n"
        "[test-a-only]\r\n"
        "desc=only TextOutA\r\n"
        "codepage=932\r\n"
        "minlen=2\r\n"
        "dedup=0\r\n"
        "hook=gdi32.dll,TextOutA\r\n";

    // 故意用 LF，并故意用尚未实现的挂钩方式：
    // 框架必须**报错并整份文件不生效**，而不是默默忽略这一行、
    // 让使用者以为 inline hook 已经装上了。
    static const char kIniBadText[] =
        "[test-bad]\n"
        "codepage=932\n"
        "hook=gdi32.dll,TextOutA,inline\n";

    // 场景 7 用：把 TextOutA 当成一个「框架不认识的函数」重新声明一遍。
    // 函数本身是框架认识的，但这里**故意不靠内置提取器**——走 text= / len= /
    // argc= 的通用转发器。如果这条能抓到文本，说明通用转发器真的在工作，
    // 而且 argc=5 的 stdcall 弹栈是对的（弹错就直接崩，根本走不到断言）。
    static const char kIniGenericText[] =
        "[test-generic]\r\n"
        "desc=TextOutA declared generically\r\n"
        "codepage=932\r\n"
        "minlen=2\r\n"
        "dedup=0\r\n"
        "text=4\r\n"
        "len=5\r\n"
        "argc=5\r\n"
        "wide=0\r\n"
        "conv=stdcall\r\n"
        "hook=gdi32.dll,TextOutA\r\n";

    Check(WriteAsciiFile(iniGood, kIniGoodText), "写入测试用 profile 文件（CRLF）");
    Check(WriteAsciiFile(iniBad,  kIniBadText),  "写入故意写错的 profile 文件（LF）");
    Check(WriteAsciiFile(iniGeneric, kIniGenericText),
          "写入通用转发器用的 profile 文件（text= / len= / argc=）");

    // ---- 3. 场景 1：内置 profile ---------------------------------------------
    static const Scenario sc1 = {
        "场景 1：内置 generic-gdi（挂全部 6 个函数）",
        L"engine=generic-gdi|cp=932|dedup=0|log=1",
        "已安装 profile=generic-gdi",
        NULL,
        1, 1
    };
    if (!only || only == 1) RunScenario(&sc1);
    // ---- 4. 场景 2：文件 profile，只挂 TextOutA ------------------------------
    //      这是 S3 的关键验证：如果 profile 真的生效，TextOutW 就不该被抓到。
    wchar_t cfg2[1024];
    swprintf_s(cfg2, 1024, L"profilefile=%ls|engine=test-a-only|dedup=0|log=1", iniGood);
    const Scenario sc2 = {
        "场景 2：文件 profile test-a-only（只挂 TextOutA）",
        cfg2,
        "已安装 profile=test-a-only",
        NULL,
        1, 0          // 期望抓到 A 系列；**不该**抓到 TextOutW
    };
    if (!only || only == 2) RunScenario(&sc2);

    // ---- 5. 场景 3：写错的 profile 文件 → 整份退回内置 ------------------------
    wchar_t cfg3[1024];
    swprintf_s(cfg3, 1024, L"profilefile=%ls|engine=generic-gdi|dedup=0|log=1", iniBad);
    const Scenario sc3 = {
        "场景 3：profile 文件写错 → 应整份退回内置且仍能抓到文本",
        cfg3,
        "加载失败",     // 横幅里要说明加载失败
        "已安装 profile=test-bad",  // 出错的文件里那个 profile 绝不能被用上
        1, 1
    };
    if (!only || only == 3) RunScenario(&sc3);

    // ---- 6. 场景 4：随仓库分发的 sample ini ----------------------------------
    if (sampleArg[0]) {
        wchar_t sampleFull[MAX_PATH];
        if (GetFullPathNameW(sampleArg, MAX_PATH, sampleFull, NULL)) {
            wchar_t cfg4[1024];
            swprintf_s(cfg4, 1024,
                       L"profilefile=%ls|engine=generic-gdi|dedup=0|log=1", sampleFull);
            const Scenario sc4 = {
                "场景 4：随仓库分发的 TextHookDll.profiles.ini（模板全部注释掉）",
                cfg4,
                "已安装 profile=generic-gdi",
                NULL,
                1, 1
            };
            if (!only || only == 4) RunScenario(&sc4);
        }
    } else {
        printf("\n  --- 场景 4 跳过（未提供 sample ini 路径）---\n");
    }

    // ---- 7. 场景 7：通用转发器 ----------------------------------------------
    //      放在场景 5 之前：场景 5 会额外做多轮安装/卸载，前面的场景要保持各自干净。
    if (!only || only == 7) RunGenericScenario(iniGeneric);

    // ---- 7b. 场景 8：控制字符清洗 -------------------------------------------
    if (!only || only == 8) RunSanitizeScenario();

    // ---- 8. 场景 5：命名管道 ------------------------------------------------
    //      必须在最后跑：它会额外做多轮安装/卸载，前面的场景要保持各自干净。
    if (!only || only == 5) RunPipeScenario();

    // ---- 9. 场景 6：动态取址 ------------------------------------------------
    if (!only || only == 6) RunDynamicScenario();

    // ---- 10. 收尾 -----------------------------------------------------------
    DeleteFileW(iniGood);
    DeleteFileW(iniBad);
    DeleteFileW(iniGeneric);

    printf("\n================================================\n");
    if (g_failures == 0) {
        printf("RESULT: PASS\n");
        return 0;
    }
    printf("RESULT: FAIL（%d 项未通过）\n", g_failures);
    return 2;
}
