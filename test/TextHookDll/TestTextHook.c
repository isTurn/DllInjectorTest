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
static char* ReadWholeFile(const wchar_t* path, size_t* pSize)
{
    FILE* f = NULL;
    if (_wfopen_s(&f, path, L"rb") != 0 || !f) return NULL;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);

    char* buf = (char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }

    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = 0;
    fclose(f);
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

static const wchar_t* g_logPath     = NULL;
static HMODULE        g_hDllUnderTest = NULL;

// 跑一个场景：清日志 -> 装钩子 -> 输出文本 -> 查日志 -> 卸钩子
static void RunScenario(const Scenario* sc)
{
    printf("\n  --- %s ---\n", sc->title);

    // 每次场景都从空日志开始，否则上一个场景的文本会污染判断
    DeleteFileW(g_logPath);

    DWORD rc = g_InstallConfig((LPVOID)sc->cfg);
    Check(rc > 0, "InstallConfig 返回成功");

    // 等启动横幅落盘（写线程是独立线程，最快 500ms 一轮）
    Sleep(700);

    size_t sz = 0;
    char* log = ReadWholeFile(g_logPath, &sz);
    Check(log != NULL, "texthook_log.txt 已生成");
    if (!log) return;

    if (sc->expectBanner)
        Check(LogContains(log, sc->expectBanner), sc->expectBanner);
    if (sc->expectAbsent)
        Check(LogAbsent(log, sc->expectAbsent), sc->expectAbsent);

    free(log);

    // 输出文本，再等写线程刷出去
    EmitAllText();
    Sleep(1200);

    log = ReadWholeFile(g_logPath, &sz);
    if (!log) { Check(0, "重新读取 texthook_log.txt"); return; }

    char utf8Hello[128], utf8Wide[128];
    ToUtf8(kExpectHello, utf8Hello, sizeof(utf8Hello));
    ToUtf8(kWideOnlyFromTextOutW, utf8Wide, sizeof(utf8Wide));

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
    Sleep(400);

    // 卸载是否真的生效：主 EXE 的 IAT 槽不应再指向 DLL 内部。
    // 这条检查就是用来抓「主 EXE 被重复挂钩 → 卸载时把槽还原成替换函数」的。
    Check(CountIatSlotsInsideDll(g_hDllUnderTest) == 0,
          "Unhook 后主 EXE 的 IAT 已完全还原（无槽指向 DLL 内部）");
}

// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    printf("TestTextHook — TextHookDll 进程内端到端验证\n");
    printf("================================================\n");

    if (argc < 2) {
        printf("用法: TestTextHook.exe <TextHookDll 路径> [sample ini 路径] [只跑的场景号 1-4]\n");
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

    wchar_t logPath[MAX_PATH], iniGood[MAX_PATH], iniBad[MAX_PATH];
    swprintf_s(logPath, MAX_PATH, L"%stexthook_log.txt", dir);
    swprintf_s(iniGood, MAX_PATH, L"%s_test_profiles_good.ini", dir);
    swprintf_s(iniBad,  MAX_PATH, L"%s_test_profiles_bad.ini", dir);
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

    Check(WriteAsciiFile(iniGood, kIniGoodText), "写入测试用 profile 文件（CRLF）");
    Check(WriteAsciiFile(iniBad,  kIniBadText),  "写入故意写错的 profile 文件（LF）");

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

    // ---- 7. 收尾 ------------------------------------------------------------
    DeleteFileW(iniGood);
    DeleteFileW(iniBad);

    printf("\n================================================\n");
    if (g_failures == 0) {
        printf("RESULT: PASS\n");
        return 0;
    }
    printf("RESULT: FAIL（%d 项未通过）\n", g_failures);
    return 2;
}
