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
//    能力边界（两条路，写清楚以免误判）：
//      1) 走内置提取器：文件从框架已知的 6 个函数里挑
//         （gdi32!TextOutA/W、gdi32!ExtTextOutA/W、user32!DrawTextA/W），
//         「哪个参数是文本」由 ReplacementFor() 里编译期写好的提取器决定，
//         不用写参数位置。
//      2) 挂任意函数：在 hook= 所在段里补 text=<第几个参数是文本>
//         （可选 len=<第几个参数是长度>、argc=<参数总数>、wide=0|1、
//         conv=stdcall|cdecl），框架就用通用转发器去调，不需要改代码。
//         序号一律从 1 起。textArg 一旦给出，就走通用转发器；
//         不给则按函数名找内置提取器。
//      仍然做不到：句子重组、DirectX 自绘引擎（S5）、
//      「连 GetProcAddress 都自己从 kernel32 现取」的动态取址（需 S2 Inline Hook）。
//
//  编译（MSVC）：
//    x64: cl /nologo /LD /O2 TextHookDll.c /link /OUT:TextHookDll-x64.dll
//    x86: cl /nologo /LD /O2 TextHookDll.c /link /OUT:TextHookDll-x86.dll
//    或直接用 test\TextHookDll\build.bat
//
//  已知限制（详见设计文档）：
//    · IAT Hook 覆盖不到「不经过导入表」的调用；已补一层 GetProcAddress 重定向，
//      但引擎若连取址都动态现取仍会漏（需二阶段 Inline Hook）
//    · 不覆盖 DirectX 自绘引擎
//    · 不做句子重组（逐字显示会逐次上报），交由消费端处理
// ============================================================================

// CancelIoEx / 重叠 IO 需要 Vista 以上的声明（本 DLL 只用这些做「可中断的等待」）
#ifndef WIN32_WINNT
#define WIN32_WINNT 0x0600
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>   // tolower（hint= 通配匹配用）
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

// 通用挂钩支持的最大参数个数。
// 为什么要有上限：纯 C 里「把任意个参数原样转交给原函数」必须靠逐个
// 显式声明的函数指针类型（见 Fn1..Fn8），不能用变参函数——x86 的
// __stdcall 由**被调方**弹栈，参数个数对不上就会把栈弹歪。
#define HT_MAX_ARGC 8

typedef struct {
    char module[HT_MODULE_MAX];   // 提供函数的 DLL 名，如 "gdi32.dll"
    char func[HT_FUNC_MAX];       // 函数名
    int  kind;                    // 挂钩方式（当前仅 HOOK_IAT）

    // ---- 以下仅「通用挂钩」使用（S3 完整版：text/len 也外部化）----
    // textArg == 0 表示走编译期写死的专用提取器（内置 6 个 GDI 函数）。
    // textArg > 0  表示走通用转发器：按序号取文本、按序号取长度。
    // 序号一律 **1 起**（与 ini 里人写的保持一致），0 表示「没有这个参数」。
    int  textArg;                 // 文本参数序号（1 起；0 = 用专用提取器）
    int  lenArg;                  // 长度参数序号（1 起；0 = 文本以 NUL 结尾）
    int  argc;                    // 参数总数（textArg>0 时必填，1..HT_MAX_ARGC）
    int  wide;                    // 1 = 文本是 wchar_t*；0 = char*（按 code page 转）
    int  conv;                    // 0 = stdcall（WINAPI，绝大多数 Win32 API）；1 = cdecl
} HookTarget;

#define PROFILE_NAME_MAX 48

#define HT_HINT_MAX 96

typedef struct {
    char              name[PROFILE_NAME_MAX];
    UINT              codepage;     // 0 = 用系统 ANSI 代码页
    const HookTarget* targets;
    int               targetCount;
    int               minLen;
    DWORD             dedupMs;

    // ---- engine=auto 用的识别提示（都可留空 = 不参与判定）----
    // hintExe  可以是通配符（`krkr*.exe`），与目标进程自身的 exe 文件名比对；
    // hintClass 同样是通配符，与目标进程任意窗口的类名比对。
    // 两个都给时要求**同时**命中，否则判为不匹配。
    // 之所以要留 hintClass：同一引擎的不同游戏 exe 名千奇百怪，
    // 但窗口类名往往是引擎框架写死的（例如 "kirikiri"），识别率高得多。
    char              hintExe[HT_HINT_MAX];
    char              hintClass[HT_HINT_MAX];
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
//   文件**既能挑选框架已知的 6 个 GDI 函数，也能引入全新的函数**——只要在该
//   profile 段里用 text= / len= / argc=（必要时再加 wide= / conv=）说明清楚
//   「第几个参数是文本、第几个参数是长度」，就走通用转发器。
//   仍然做不到的：不做句子重组、不处理 DirectX 自绘、不覆盖 GetProcAddress
//   动态取址（那需要 Inline Hook，属于 S2）。
// ---------------------------------------------------------------------------

#define MAX_FILE_PROFILES 32
#define MAX_FILE_TARGETS  16
#define MAX_DESC_LEN      128

typedef struct {
    EngineProfile prof;                    // 供 g_profile 指向；prof.targets 指向本结构的 targets
    HookTarget    targets[MAX_FILE_TARGETS];
    char          desc[MAX_DESC_LEN];      // 仅供人读，不参与逻辑

    // 段内 `text=` / `len=` / `argc=` / `wide=` / `conv=` 的暂存值。
    // 这些键可以写在任意 hook= 之前或之后，所以先记在这里，等整段读完
    // 再统一填进每个 target（否则「键写在 hook 后面」就会静默失效）。
    int           pendingTextArg;
    int           pendingLenArg;
    int           pendingArgc;
    int           pendingWide;
    int           pendingConv;
} FileProfile;

static FileProfile g_fileProfiles[MAX_FILE_PROFILES];
static int         g_fileProfileCount = 0;
static BOOL        g_profilesLoaded   = FALSE;   // 是否已经尝试过加载（无论成功与否，只试一次）
static BOOL        g_profileExplicit  = FALSE;   // engine= 是否被显式指定过
static BOOL        g_autoRequested    = FALSE;   // engine=auto：请求按 hint 猜 profile
static BOOL        g_autoMatched      = FALSE;   // 上一轮 auto 是否真的猜中（用于横幅提示）

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

// 去重表：多槽而不是单槽。
// 为什么不能只记「最近一条」：GalGame 常见「背景框 + 对话框」每帧交替绘制两处
// 文本，单槽时两条互相顶掉，去重等于完全失效，队列会被 60 帧/秒灌满。
// 槽位用文本哈希定址，命中且未过期就丢弃，否则占用空槽/最旧槽。
#define DEDUP_SLOTS 8
typedef struct {
    unsigned int hash;      // hookName + 文本的 FNV-1a 哈希，0 = 空槽
    DWORD        tick;      // 该条上一次上报的时刻
} DedupSlot;
static DedupSlot           g_dedup[DEDUP_SLOTS];

// 统计：这三个数决定「抓不到文本」时该往哪个方向查。
// 全 0 = 钩子压根没被调用；filtered 大 = 抓到的是碎片（长度阈值太高）；
// dropped 大 = 消费端跟不上或管道卡住。
static volatile LONG       g_statEmitted  = 0;
static volatile LONG       g_statFiltered = 0;
static volatile LONG       g_statDropped  = 0;

// 上一轮的统计快照。StopHooks 时写进来，下一次 StartHooks 时作为横幅的一行输出：
// 卸载之后管道已经在关，再往队列里塞东西也发不出去，所以只能留到下一轮报。
static char                g_lastStats[256] = "";

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

    // 以二进制追加写原始 UTF-8 字节（不能用 ccs=UTF-8，那是给宽字符准备的）。
    //
    // 用 CreateFileW 而不是 _wfopen_s("ab")，有两个必须的理由：
    //   1) 共享冲突。._wfopen_s 默认以「独占」方式打开，任何别的进程正开着
    //      这个日志（tail、编辑器、我们的验证程序）时，fopen 直接失败，而
    //      下面的分支会**静默丢掉这一行**——表现为日志里少一条启动横幅，
    //      看起来像「钩子没装上」。加 FILE_SHARE_READ|WRITE 就没有这个问题。
    //   2) 便于重试。偶尔撞上真的独占者时，重试几次比丢一行要好。
    // FILE_APPEND_DATA 已经是原子追加语义，不需要再 SeekToEnd。
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int tries = 0; tries < 5; tries++)
    {
        h = CreateFileW(file, FILE_APPEND_DATA | SYNCHRONIZE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_SHARING_VIOLATION) return;
        Sleep(10);
    }
    if (h == INVALID_HANDLE_VALUE) return;

    size_t len = strlen(utf8Line);
    size_t done = 0;
    while (done < len)
    {
        DWORD chunk = 0;
        if (!WriteFile(h, utf8Line + done, (DWORD)(len - done), &chunk, NULL) || chunk == 0) break;
        done += chunk;
    }
    CloseHandle(h);
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

// 管道实例数。
// 为什么要多实例：原先 nMaxInstances=1，第二个消费者（比如同时开着翻译工具和
// 自己写的抓文本脚本）连上来会被直接拒绝，而使用者看到的现象是「客户端连不上」
// 却没有任何提示。多开几个实例后，每个实例各自 accept、各自持有连接，
// 同一行文本广播给所有已连接的消费者。
// 上限取 4：够覆盖「翻译工具 + 日志脚本 + 调试控制台」这种组合，
// 又不至于让每个消费者都占一个线程。
#define PIPE_INSTANCES 4

// 每个实例一份「已连接句柄」。INVALID_HANDLE_VALUE = 当前没有客户端。
// 静态存储默认是 0（不是 INVALID_HANDLE_VALUE），所以 StartHooks 里必须显式
// 复位一遍，否则写线程会把 0 当成一个真实句柄去 WriteFile。
static HANDLE           g_hPipe[PIPE_INSTANCES];
static CRITICAL_SECTION g_pipeCs;
static volatile LONG    g_pipeBroken[PIPE_INSTANCES];
static volatile LONG    g_stop = 0;

static HANDLE           g_pipeThread[PIPE_INSTANCES];
static HANDLE           g_writerThread = NULL;

// 停止信号：手动重置事件。g_stop 只能被**轮询**到，而管道线程可能正阻塞在
// ConnectNamedPipe 上——轮询对它无效，必须靠这个事件把等待唤醒。
// 与临界区一样「建一次就不销毁」：万一有线程没能在超时内退出，销毁它会让
// 那个线程在已释放的对象上继续等待。
static HANDLE           g_stopEvent = NULL;
static BOOL             g_syncInited = FALSE;   // 临界区是否已初始化（只初始化一次）
static HANDLE           g_writeEvent = NULL;    // 写管道用的重叠事件（只写线程使用）

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
        // 但必须计数——否则使用者只看到「文本少了」，分不清是钩子没抓到、
        // 编码错了、还是队列溢出，这是最难远程排查的一类问题。
        QNode* old = g_qHead;
        g_qHead = old->next;
        if (!g_qHead) g_qTail = NULL;
        g_qCount--;
        free(old->line);
        free(old);
        InterlockedIncrement(&g_statDropped);
    }
    if (g_qTail) g_qTail->next = n; else g_qHead = n;
    g_qTail = n;
    g_qCount++;
    LeaveCriticalSection(&g_qCs);

    // TOCTOU 防护：StopHooks 会在确认线程都退出后关闭 g_qEvent。这里不加锁
    // 就直接 SetEvent，一旦读到的是「关闭前那一刻的句柄值」，SetEvent 就作用在
    // 一个已关闭（甚至已被系统回收改作他用）的句柄上。
    // 先拷进局部变量再判空/SetEvent 不解决问题（仍然是两次读），
    // 所以让「取句柄」和「用句柄」都处在同一把锁里，StopHooks 也在同一把锁里清空。
    EnterCriticalSection(&g_qCs);
    HANDLE qev = g_qEvent;
    if (qev) SetEvent(qev);
    LeaveCriticalSection(&g_qCs);
}
// 往管道写一行。管道句柄是**重叠（overlapped）**打开的——这是为了让管道线程
// 的 ConnectNamedPipe 可以被停止事件打断——所以写也必须走重叠方式：
// 对重叠句柄调用 WriteFile 时传 NULL lpOverlapped 是未定义行为
// （MSDN 明确说会「错误地报告写完成」）。
//
// 两条曾经踩过的不变量，改这段代码前务必读一遍：
//
//  1) OVERLAPPED **绝不能放在本函数的栈帧里**。只要 WriteFile 返回
//     ERROR_IO_PENDING，内核就持有了这个结构的指针；函数返回后调用方继续跑，
//     那块栈内存会被后面的调用覆写，而内核稍后仍往里面写完成状态 —— 静默的
//     内存破坏，症状是「偶尔有条文本变成乱码」或管道实例莫名被判断开。
//     原实现超时后 CancelIoEx + 等 1 秒，1 秒也没等到就直接 return FALSE，
//     正好落进这个坑。现在的规则：只有确认 I/O 已经完成（GetOverlappedResult
//     返回，或 CancelIoEx 后等到完成）才 free；确认不了就**故意泄漏**这 64 字节，
//     让内核手里的指针始终有效。泄漏一次远好过破坏内存。
//
//  2) 共用的 g_writeEvent 是自动复位的，用前必须 ResetEvent。上一次被放弃的
//     写留下的残留信号会被下一次 WriteFile 立刻「吃掉」，于是
//     GetOverlappedResult(..., FALSE) 返回 ERROR_IO_INCOMPLETE，一个健康的
//     实例就被标成 g_pipeBroken[i] = 1 了。
static BOOL PipeWrite(HANDLE h, const char* data, DWORD len)
{
    if (h == INVALID_HANDLE_VALUE || !data || len == 0) return FALSE;
    if (!g_writeEvent) return FALSE;

    OVERLAPPED* ov = (OVERLAPPED*)calloc(1, sizeof(OVERLAPPED));
    if (!ov) return FALSE;
    ov->hEvent = g_writeEvent;

    // 吃掉上一次残留的信号（见上面第 2 条）。
    ResetEvent(g_writeEvent);

    DWORD written = 0;
    if (WriteFile(h, data, len, &written, ov)) { free(ov); return TRUE; }

    DWORD err = GetLastError();
    if (err != ERROR_IO_PENDING) { free(ov); return FALSE; }

    // 客户端只读不写，正常情况很快完成；给个上限免得写线程被卡死
    if (WaitForSingleObject(g_writeEvent, 2000) == WAIT_OBJECT_0) {
        BOOL ok = GetOverlappedResult(h, ov, &written, FALSE) ? TRUE : FALSE;
        free(ov);
        return ok;
    }

    // 超时：先请求取消，再等内核把完成通知交回来。
    // CancelIoEx 返回 FALSE 且 GetLastError()==ERROR_NOT_FOUND 说明这单其实
    // 已经完成了（只是信号被别的东西吃掉），那就照常取结果。
    if (!CancelIoEx(h, ov)) {
        if (GetLastError() == ERROR_NOT_FOUND) {
            ResetEvent(g_writeEvent);
            BOOL ok = GetOverlappedResult(h, ov, &written, FALSE) ? TRUE : FALSE;
            free(ov);
            return ok;
        }
    }
    if (WaitForSingleObject(g_writeEvent, 1000) == WAIT_OBJECT_0) {
        free(ov);           // 内核已写回完成状态，结构可以安全释放
        return FALSE;       // 但这次写本身按失败处理
    }

    // 仍然没有完成 → 内核还拿着 ov。故意泄漏，绝不 free。
    return FALSE;
}

static DWORD WINAPI WriterThreadProc(LPVOID param)
{
    (void)param;
    while (!g_stop)
    {
        WaitForSingleObject(g_qEvent, 500);

        for (;;)
        {
            // 内层排空循环必须检查 g_stop：StopHooks 只有 2 秒有界等待，
            // 而一次「消费者连上不读」就能让单条广播耗掉 3 秒（PipeWrite 的
            // 2000 + 1000）。不检查的话队列里积压 10 条就要 30 秒，StopHooks
            // 早就超时返回、CloseHandle 走人、UnhookAll 执行完，这个线程却仍在
            // 跑 —— 一旦 DLL 被 FreeLibrary，它就踩在已卸载的映像上。
            // 收到停止信号就丢弃剩余队列直接退出（残留的 QNode 随进程/映像消失，
            // 比「线程活过 DLL 生命期」便宜得多）。
            if (g_stop) return 0;

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

            // 广播给所有已连接的消费者。
            // 这里是独立线程，写管道阻塞不会影响游戏。
            // 注意：某个客户端不读时，它那一份写会等到 PipeWrite 的 2 秒超时才
            // 放弃，期间其它客户端这一行也会被拖慢。之所以不为此再拆一个线程池：
            // 消费者是本地进程，正常读取时几乎瞬间完成；真出现「连上不读」的
            // 客户端，超时后会把它标记为断开并释放实例，不会长期拖累别人。
            EnterCriticalSection(&g_pipeCs);
            for (int i = 0; i < PIPE_INSTANCES; i++)
            {
                if (g_hPipe[i] == INVALID_HANDLE_VALUE) continue;
                if (!PipeWrite(g_hPipe[i], n->line, (DWORD)strlen(n->line)))
                    g_pipeBroken[i] = 1;   // 客户端断开：通知对应 accept 线程重建实例
            }
            LeaveCriticalSection(&g_pipeCs);

            if (g_logToFile) FileLogLine(n->line);

            free(n->line);
            free(n);
        }
    }
    return 0;
}

// 每个实例一个 accept 线程。idx 用来定位自己那份 g_hPipe / g_pipeBroken，
// 这样某个客户端断开只会让**它自己**的实例重建，不影响其它消费者。
static DWORD WINAPI PipeThreadProc(LPVOID param)
{
    int idx = (int)(INT_PTR)param;
    if (idx < 0 || idx >= PIPE_INSTANCES) return 0;

    char full[MAX_PATH];
    _snprintf_s(full, sizeof(full), _TRUNCATE, "\\\\.\\pipe\\%s", g_pipeName);

    // 连接完成事件，配合 g_stopEvent 一起等 —— 这样阻塞中的 ConnectNamedPipe
    // 能被卸载流程唤醒（详见 StopHooks 的注释）。
    HANDLE hConn = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!hConn) return 0;

    while (!g_stop)
    {
        HANDLE h = CreateNamedPipeA(
            full,
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,   // 重叠打开：连接等待才可中断
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_INSTANCES,     // 允许最多这么多实例同时存在
            64 * 1024,          // 出缓冲
            0,                  // 入缓冲（单向）
            0,
            NULL);

        if (h == INVALID_HANDLE_VALUE) { Sleep(500); continue; }

        ResetEvent(hConn);

        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        ov.hEvent = hConn;

        BOOL connected = FALSE;
        if (ConnectNamedPipe(h, &ov)) {
            connected = TRUE;
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_PIPE_CONNECTED) {
                connected = TRUE;                 // 客户端在 ConnectNamedPipe 之前就连上了
            } else if (err == ERROR_IO_PENDING) {
                HANDLE waits[2] = { hConn, g_stopEvent };
                DWORD w = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
                if (w == WAIT_OBJECT_0) {
                    connected = TRUE;
                } else {
                    // 停止信号：撤销挂起的连接请求并等它真正结束，再关句柄。
                    // 顺序很重要——先 CloseHandle 再返回会让内核可能往已经消失的
                    // OVERLAPPED 上写完成状态（这里 ov 在栈上，返回即失效）。
                    CancelIoEx(h, &ov);
                    WaitForSingleObject(hConn, 1000);
                    CloseHandle(h);
                    break;
                }
            } else {
                CloseHandle(h);                   // 实例数已满等：等一会儿再试
                Sleep(500);
                continue;
            }
        }

        if (connected)
        {
            EnterCriticalSection(&g_pipeCs);
            g_hPipe[idx] = h;
            g_pipeBroken[idx] = 0;
            LeaveCriticalSection(&g_pipeCs);

            // 持有连接，直到写失败（客户端断开）或收到停止信号
            while (!g_pipeBroken[idx] && !g_stop) Sleep(150);

            EnterCriticalSection(&g_pipeCs);
            if (g_hPipe[idx] == h) g_hPipe[idx] = INVALID_HANDLE_VALUE;
            LeaveCriticalSection(&g_pipeCs);

            DisconnectNamedPipe(h);
        }
        CloseHandle(h);
    }

    CloseHandle(hConn);
    return 0;
}

// ---------------------------------------------------------------------------
// 文本提取与上报
// ---------------------------------------------------------------------------

// 把控制字符就地换成空格。
// 为什么必须做：管道协议是「一行一条消息」（以 \n 分帧），文本里只要含一个
// 换行，一条消息就被拆成两条；含 \t 则客户端按 tab 切字段时会错位，表现为
// 「hook 列里带着文本」。GalGame 里一句话分多行显示很常见，这不是理论问题。
// 只替换 C0/C1 控制字符，全角空格（U+3000）等可见空白保留。
static void SanitizeControls(wchar_t* w, int n)
{
    for (int i = 0; i < n; i++)
    {
        wchar_t c = w[i];
        if ((c < 0x20) || (c >= 0x7F && c < 0xA0))
            w[i] = L' ';
    }
}

// FNV-1a：给去重表算 key。不用 CRC32 是因为它要多一张表，这里只需要
// 「同一句话算同一个数」，分布好坏影响很小。
static unsigned int HashText(const char* hookName, const wchar_t* w, int n)
{
    unsigned int h = 2166136261u;
    for (const char* p = hookName; p && *p; p++)
        h = (h ^ (unsigned char)*p) * 16777619u;
    h = (h ^ 0xFFu) * 16777619u;          // 分隔符，避免 "ab"+"c" 与 "a"+"bc" 撞
    for (int i = 0; i < n; i++)
    {
        unsigned int c = (unsigned int)w[i];
        h = (h ^ (c & 0xFFu)) * 16777619u;
        h = (h ^ ((c >> 8) & 0xFFu)) * 16777619u;
    }
    return h ? h : 1u;                    // 0 留给「空槽」
}

static void EmitText(const wchar_t* w, const char* hookName)
{
    if (!w || !*w) return;

    int n = (int)wcslen(w);
    while (n > 0 && iswspace(w[n - 1])) n--;          // 去掉尾部空白
    if (n > 2047) n = 2047;

    // 去重和过滤都要用清洗后的文本，所以先拷一份再处理，
    // 避免改到调用方的缓冲区（有些引擎的缓冲区是只读的）。
    wchar_t clean[2048];
    memcpy(clean, w, (size_t)n * sizeof(wchar_t));
    clean[n] = 0;
    SanitizeControls(clean, n);

    if (n < g_minLen) { InterlockedIncrement(&g_statFiltered); return; }

    // 去重：游戏每帧重绘，同一句话每秒可能触发几十次。
    // 多槽按 hash 定址，先找同 key 的槽判断是否在窗口内，找不到就占用
    // 「空槽 / 最旧槽」。用最旧淘汰而不是清空重来，是为了让交替绘制的
    // 两条文本各自保留自己的时间戳。
    unsigned int key = HashText(hookName, clean, n);
    DWORD now = GetTickCount();
    EnterCriticalSection(&g_textCs);
    int freeIdx = -1, oldestIdx = 0;
    BOOL dup = FALSE;
    for (int i = 0; i < DEDUP_SLOTS; i++)
    {
        if (g_dedup[i].hash == 0) { if (freeIdx < 0) freeIdx = i; continue; }
        if (g_dedup[i].hash == key)
        {
            if ((now - g_dedup[i].tick) < g_dedupMs) { dup = TRUE; }
            else { g_dedup[i].tick = now; }
            freeIdx = i;
            break;
        }
        if ((int)(now - g_dedup[oldestIdx].tick) < (int)(now - g_dedup[i].tick))
            oldestIdx = i;   // 找 tick 最早的那个（模运算下用差值比较更稳）
    }
    if (dup)
    {
        LeaveCriticalSection(&g_textCs);
        InterlockedIncrement(&g_statFiltered);
        return;
    }
    int slot = (freeIdx >= 0) ? freeIdx : oldestIdx;
    if (g_dedup[slot].hash != key) { g_dedup[slot].hash = key; }
    g_dedup[slot].tick = now;
    LeaveCriticalSection(&g_textCs);

    // 统一转 UTF-8 输出
    char utf8[8192];
    int m = WideCharToMultiByte(CP_UTF8, 0, clean, n, utf8, (int)sizeof(utf8) - 1, NULL, NULL);
    if (m <= 0) { InterlockedIncrement(&g_statFiltered); return; }
    utf8[m] = 0;

    char line[8704];
    int len = _snprintf_s(line, sizeof(line), _TRUNCATE,
                          "GalToolText\t%lu\t%s\t%s\n",
                          GetCurrentProcessId(), hookName, utf8);
    if (len > 0) { Enqueue(line); InterlockedIncrement(&g_statEmitted); }
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

    // cp=1200（UTF-16）不是合法的 MultiByteToWideChar **输入**代码页：
    // 该函数拒绝 1200/1201（ERROR_INVALID_PARAMETER，实测 ret=0），因为它们描述的是
    // 「宽字符」而不是「字节流」。老版本把 1200 写进了文档和内置 profile，结果是
    // 只要引擎走 *A 函数，所有文本都在这里静默消失，而且连 g_statFiltered 都不加，
    // 现场表现与「钩子根本没挂上」完全无法区分。
    // 现在把 1200 当成「这就是 UTF-16 字节流，按小端直接搬」处理——这也正是
    // 调用方写 cp=1200 时的真实意图。
    if (cp == 1200 || cp == 1201)
    {
        int pairs = len / (int)sizeof(wchar_t);
        if (pairs > 2000) pairs = 2000;
        if (pairs <= 0) { InterlockedIncrement(&g_statFiltered); return; }
        if (cp == 1201) {   // UTF-16BE：逐对调字节序
            int k;
            for (k = 0; k < pairs; k++)
            {
                unsigned char a = (unsigned char)s[k * 2 + 0];
                unsigned char b = (unsigned char)s[k * 2 + 1];
                w[k] = (wchar_t)((unsigned short)((unsigned)a << 8) | b);
            }
        }
        else
        {
            memcpy(w, s, (size_t)pairs * sizeof(wchar_t));
        }
        w[pairs] = 0;
        EmitText(w, hookName);
        return;
    }

    int n = MultiByteToWideChar(cp, 0, s, len, w, 2047);
    if (n <= 0)
    {
        // 转换失败必须计数。否则「上报 0 条、过滤 0 次」这种自相矛盾的统计
        // 会让人误判成「钩子没被调用」，而真正的原因是代码页写错了。
        InterlockedIncrement(&g_statFiltered);
        return;
    }
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
// 通用转发器（S3 完整版：text=/len= 也外部化）
//
// 目的：让 ini 能挂钩**框架事先不认识**的函数，只要它的签名形状是
//       「若干整数/指针参数，其中第 N 个是文本、第 M 个是长度」。
//
// 为什么需要固定的一批 thunk，而不是一个变参函数：
//   x86 的 __stdcall 由**被调方**弹栈。如果 IAT 里的调用方按 4 个参数调用，
//   而我们的替换函数声明成 8 个参数，返回时就会多弹 16 字节栈 —— 直接崩溃。
//   所以「参数个数」必须在编译期固定，只能按 1..8 各生成一个。
//
// 已知取舍（写进文档，不假装没有）：
//   · 每个参数都按指针宽度传递。x86 上遇到 64 位参数（如 LONGLONG）会错位，
//     这类函数不在通用挂钩的支持范围内。
//   · 调用约定必须由 profile 声明：stdcall 与 cdecl 的弹栈方不同，两套 thunk
//     不能共用（写错 conv= 的表现是「调用一次就崩」，不是「抓不到文本」）。
//   · 通用挂钩每个 profile 最多 HT_MAX_GENERIC 个（够用，且便于排查）。
// ---------------------------------------------------------------------------

#define HT_MAX_GENERIC 8

typedef struct {
    void*       original;    // 原函数地址（首次挂钩时记录）
    int         textArg;     // 1 起；0 = 该槽未使用
    int         lenArg;      // 1 起；0 = NUL 结尾
    int         argc;
    int         wide;
    int         conv;        // 0 = stdcall（WINAPI，绝大多数 Win32 API）；1 = cdecl
    const char* name;        // 上报时用的 hook 名（指向 profile 里的 func 字段，生命周期同 DLL）
} GenericCtx;

// 转交原函数时用的函数指针类型：按「参数个数 × 调用约定」各一个。
// 不能用一个 8 参指针硬转去调少参数：x86 的 stdcall 由被调方弹栈，
// 声明 8 个参数而实际只传 1 个，返回时就会把栈弹歪 28 字节。
#define GEN_FN_TYPEDEF(n, ...)                                                 \
    typedef UINT_PTR (WINAPI *FnW##n)(__VA_ARGS__);                            \
    typedef UINT_PTR (__cdecl *FnC##n)(__VA_ARGS__);
GEN_FN_TYPEDEF(1, UINT_PTR)
GEN_FN_TYPEDEF(2, UINT_PTR, UINT_PTR)
GEN_FN_TYPEDEF(3, UINT_PTR, UINT_PTR, UINT_PTR)
GEN_FN_TYPEDEF(4, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR)
GEN_FN_TYPEDEF(5, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR)
GEN_FN_TYPEDEF(6, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR)
GEN_FN_TYPEDEF(7, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR)
GEN_FN_TYPEDEF(8, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR, UINT_PTR)
#undef GEN_FN_TYPEDEF

static GenericCtx        g_gen[HT_MAX_GENERIC];
static const HookTarget* g_genTargets[HT_MAX_GENERIC];   // id -> profile 里的目标（用于反查 id）

// 通用目标指针 → g_gen 下标（用指针相等，不额外占用 HookTarget 字段，
// 因为内置 profile 的 targets 是 const 常量数组，不能写运行期数据）
static int GenIdForTarget(const HookTarget* t)
{
    for (int i = 0; i < HT_MAX_GENERIC; i++)
        if (g_genTargets[i] == t) return i;
    return -1;
}

static UINT_PTR GenDispatch(int id, const UINT_PTR* a)
{
    const GenericCtx* c = &g_gen[id];
    if (c->textArg >= 1 && c->textArg <= HT_MAX_ARGC)
    {
        UINT_PTR p = a[c->textArg - 1];
        int len = -1;
        if (c->lenArg >= 1 && c->lenArg <= HT_MAX_ARGC) len = (int)a[c->lenArg - 1];
        if (p)
        {
            if (c->wide) EmitWide((const wchar_t*)p, len, c->name);
            else         EmitAnsi((const char*)p,   len, c->name);
        }
    }

    // 把参数原样交回原函数。必须按真实参数个数调用：x86 的 __stdcall
    // 由被调方弹栈，多传一个参数就会把栈弹歪；而 cdecl 目标又必须用
    // __cdecl 的函数指针调用，否则弹栈方向相反，一样崩。所以两种约定
    // 各自一套指针类型，按 argc 分派。
    void* fn = c->original;
    if (!fn) return 0;

    if (c->conv)
    {
        switch (c->argc)
        {
        case 1: return ((FnC1)fn)(a[0]);
        case 2: return ((FnC2)fn)(a[0], a[1]);
        case 3: return ((FnC3)fn)(a[0], a[1], a[2]);
        case 4: return ((FnC4)fn)(a[0], a[1], a[2], a[3]);
        case 5: return ((FnC5)fn)(a[0], a[1], a[2], a[3], a[4]);
        case 6: return ((FnC6)fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
        case 7: return ((FnC7)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
        case 8: return ((FnC8)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
        default: return 0;
        }
    }

    switch (c->argc)
    {
    case 1: return ((FnW1)fn)(a[0]);
    case 2: return ((FnW2)fn)(a[0], a[1]);
    case 3: return ((FnW3)fn)(a[0], a[1], a[2]);
    case 4: return ((FnW4)fn)(a[0], a[1], a[2], a[3]);
    case 5: return ((FnW5)fn)(a[0], a[1], a[2], a[3], a[4]);
    case 6: return ((FnW6)fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7: return ((FnW7)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    case 8: return ((FnW8)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    default: return 0;
    }
}

// 把 N 个参数填进定长数组。单独拆出来是为了让 thunk 的函数体只有一行，
// 避免宏里引用未声明的形参。
static void GenFill1(UINT_PTR* a, UINT_PTR a1) { a[0] = a1; }
static void GenFill2(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2) { a[0]=a1; a[1]=a2; }
static void GenFill3(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2, UINT_PTR a3) { a[0]=a1; a[1]=a2; a[2]=a3; }
static void GenFill4(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4) { a[0]=a1; a[1]=a2; a[2]=a3; a[3]=a4; }
static void GenFill5(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5) { a[0]=a1; a[1]=a2; a[2]=a3; a[3]=a4; a[4]=a5; }
static void GenFill6(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5, UINT_PTR a6) { a[0]=a1; a[1]=a2; a[2]=a3; a[3]=a4; a[4]=a5; a[5]=a6; }
static void GenFill7(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5, UINT_PTR a6, UINT_PTR a7) { a[0]=a1; a[1]=a2; a[2]=a3; a[3]=a4; a[4]=a5; a[5]=a6; a[6]=a7; }
static void GenFill8(UINT_PTR* a, UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5, UINT_PTR a6, UINT_PTR a7, UINT_PTR a8) { a[0]=a1; a[1]=a2; a[2]=a3; a[3]=a4; a[4]=a5; a[5]=a6; a[6]=a7; a[7]=a8; }

// 形参表按个数固定。宏参数不能直接写「UINT_PTR a1, UINT_PTR a2」——
// 预处理器会把里面的逗号当成参数分隔符，于是必须用宏名把逗号藏起来。
#define GEN_ARGS_1  UINT_PTR a1
#define GEN_ARGS_2  UINT_PTR a1, UINT_PTR a2
#define GEN_ARGS_3  UINT_PTR a1, UINT_PTR a2, UINT_PTR a3
#define GEN_ARGS_4  UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4
#define GEN_ARGS_5  UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5
#define GEN_ARGS_6  UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5, UINT_PTR a6
#define GEN_ARGS_7  UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5, UINT_PTR a6, UINT_PTR a7
#define GEN_ARGS_8  UINT_PTR a1, UINT_PTR a2, UINT_PTR a3, UINT_PTR a4, UINT_PTR a5, UINT_PTR a6, UINT_PTR a7, UINT_PTR a8

#define GEN_NAMES_1  a1
#define GEN_NAMES_2  a1, a2
#define GEN_NAMES_3  a1, a2, a3
#define GEN_NAMES_4  a1, a2, a3, a4
#define GEN_NAMES_5  a1, a2, a3, a4, a5
#define GEN_NAMES_6  a1, a2, a3, a4, a5, a6
#define GEN_NAMES_7  a1, a2, a3, a4, a5, a6, a7
#define GEN_NAMES_8  a1, a2, a3, a4, a5, a6, a7, a8

// 生成 thunk：每个 (id, argc, 调用约定) 组合一个，形参个数必须与 argc 严格一致。
// 调用约定也必须一致：x86 上 cdecl 由**调用方**弹栈、stdcall 由**被调方**弹栈，
// 用错一个就会多弹/少弹一个参数宽度的栈，直接崩。x64 只有一个约定，两者等价。
#define GEN_THUNK(id, N, CV, SUFFIX)                                           \
    static UINT_PTR CV Gen_##id##_##N##SUFFIX(GEN_ARGS_##N)                    \
    {                                                                          \
        UINT_PTR a[HT_MAX_ARGC] = { 0 };                                       \
        GenFill##N(a, GEN_NAMES_##N);                                          \
        return GenDispatch(id, a);                                             \
    }

#define GEN_THUNK_CV(id, N)                                                    \
    GEN_THUNK(id, N, WINAPI, )                                                 \
    GEN_THUNK(id, N, __cdecl, _cdecl)

#define GEN_THUNKS_FOR_ID(id)                                                  \
    GEN_THUNK_CV(id, 1)                                                        \
    GEN_THUNK_CV(id, 2)                                                        \
    GEN_THUNK_CV(id, 3)                                                        \
    GEN_THUNK_CV(id, 4)                                                        \
    GEN_THUNK_CV(id, 5)                                                        \
    GEN_THUNK_CV(id, 6)                                                        \
    GEN_THUNK_CV(id, 7)                                                        \
    GEN_THUNK_CV(id, 8)

GEN_THUNKS_FOR_ID(0)
GEN_THUNKS_FOR_ID(1)
GEN_THUNKS_FOR_ID(2)
GEN_THUNKS_FOR_ID(3)
GEN_THUNKS_FOR_ID(4)
GEN_THUNKS_FOR_ID(5)
GEN_THUNKS_FOR_ID(6)
GEN_THUNKS_FOR_ID(7)

// thunk 地址表：g_genThunks[conv][id][argc-1]，conv: 0=stdcall 1=cdecl
static const void* const g_genThunks[2][HT_MAX_GENERIC][HT_MAX_ARGC] = {
#define GEN_ROW(id) { (const void*)Gen_##id##_1, (const void*)Gen_##id##_2, \
                      (const void*)Gen_##id##_3, (const void*)Gen_##id##_4, \
                      (const void*)Gen_##id##_5, (const void*)Gen_##id##_6, \
                      (const void*)Gen_##id##_7, (const void*)Gen_##id##_8 }
    { GEN_ROW(0), GEN_ROW(1), GEN_ROW(2), GEN_ROW(3),
      GEN_ROW(4), GEN_ROW(5), GEN_ROW(6), GEN_ROW(7) },
#undef GEN_ROW
#define GEN_ROW(id) { (const void*)Gen_##id##_1##_cdecl, (const void*)Gen_##id##_2##_cdecl, \
                      (const void*)Gen_##id##_3##_cdecl, (const void*)Gen_##id##_4##_cdecl, \
                      (const void*)Gen_##id##_5##_cdecl, (const void*)Gen_##id##_6##_cdecl, \
                      (const void*)Gen_##id##_7##_cdecl, (const void*)Gen_##id##_8##_cdecl }
    { GEN_ROW(0), GEN_ROW(1), GEN_ROW(2), GEN_ROW(3),
      GEN_ROW(4), GEN_ROW(5), GEN_ROW(6), GEN_ROW(7) },
#undef GEN_ROW
};

static void* GenericReplacementFor(const HookTarget* t)
{
    int id = GenIdForTarget(t);
    if (id < 0) return NULL;
    if (t->argc < 1 || t->argc > HT_MAX_ARGC) return NULL;
    return (void*)g_genThunks[t->conv ? 1 : 0][id][t->argc - 1];
}
// ---------------------------------------------------------------------------
// IAT Hook 安装
// ---------------------------------------------------------------------------

// 把「目标」注册到通用转发器槽位里，返回 id；非通用目标返回 -1。
// 必须幂等：同一个 target 会被多个模块重复请求。
static int RegisterGeneric(const HookTarget* t)
{
    if (!t || t->textArg <= 0) return -1;

    int id = GenIdForTarget(t);
    if (id >= 0) return id;

    for (int i = 0; i < HT_MAX_GENERIC; i++)
    {
        if (g_genTargets[i] != NULL) continue;
        g_genTargets[i] = t;
        g_gen[i].textArg = t->textArg;
        g_gen[i].lenArg  = t->lenArg;
        g_gen[i].argc    = t->argc;
        g_gen[i].wide    = t->wide;
        g_gen[i].conv    = t->conv;
        g_gen[i].name    = t->func;
        return i;
    }
    return -1;   // 槽位用尽：调用方据此上报「未挂钩」，而不是静默失败
}

// 取目标函数的真实地址。用于按**地址**而不是按模块名匹配 IAT 槽。
// 为什么不用模块名匹配：API Set（api-ms-win-*）会把 gdi32/user32 的导入
// 改写成另一个模块名，按名字比对会整片匹配不到，表现为「profile 明明对了却抓不到」。
static void* ResolveTargetAddress(const HookTarget* t, HMODULE* phOwner)
{
    if (phOwner) *phOwner = NULL;

    HMODULE hMod = GetModuleHandleA(t->module);
    if (!hMod) hMod = LoadLibraryA(t->module);   // 目标模块可能还没被进程加载
    if (!hMod) return NULL;
    if (phOwner) *phOwner = hMod;

    return (void*)GetProcAddress(hMod, t->func);
}

// 在 hMod 的导入表里把**所有**指向 targetAddr 的槽换成 replacement。
// 返回打补丁的槽数；0 表示这个模块没有导入该函数（正常，不是错误）。
// t 只用于日志/语义，可以传 NULL（GetProcAddress 那条路径就没有 HookTarget）。
static int PatchModuleIat(HMODULE hMod, const HookTarget* t, void* targetAddr,
                          void* replacement, void** pOriginalSlot)
{
    if (!hMod || !targetAddr || !replacement) return 0;

    BYTE* base = (BYTE*)hMod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    IMAGE_DATA_DIRECTORY impDir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress == 0) return 0;

    IMAGE_IMPORT_DESCRIPTOR* imp =
        (IMAGE_IMPORT_DESCRIPTOR*)(base + impDir.VirtualAddress);

    int patched = 0;

    for (; imp->Name; imp++)
    {
        if (imp->FirstThunk == 0) continue;

        IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);

        // 名字表可能缺失（少数加壳/重建过的映像只有 FirstThunk），
        // 所以这里不能像原来那样要求 OriginalFirstThunk 必须存在。
        IMAGE_THUNK_DATA* orig = imp->OriginalFirstThunk
            ? (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk)
            : NULL;

        for (; iat->u1.Function; iat++, orig = orig ? orig + 1 : NULL)
        {
            if (orig && IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;

            void* cur = (void*)iat->u1.Function;

            // 已经指向我们的替换函数说明这个槽挂过了，跳过。
            // 必须有这道幂等检查：主 EXE 会先被 HookAllModules 显式挂一次，
            // 随后又出现在模块快照里被挂第二次。重复记录会让第二条把
            // original 记成**我们自己的替换函数**，卸载时就会把槽还原成
            // 替换函数——等于没卸，而 DLL 一旦被卸载就是跳进已释放内存。
            if (cur == replacement) continue;

            // ★ 按地址匹配而不是按模块名/函数名匹配：
            //   API Set 转发、函数名修饰（_TextOutA@20）、不同大小写写法
            //   全部自动兼容。
            if (cur != targetAddr) continue;

            if (g_patchedCount >= MAX_PATCHED) return patched;

            // 只在首次记录原始地址：各模块 IAT 槽里存的是同一个函数地址
            if (*pOriginalSlot == NULL) *pOriginalSlot = cur;

            // 写 IAT 槽前把所在页改成可写。
            // ★ 用 PAGE_EXECUTE_READWRITE 而不是 PAGE_READWRITE：
            //   加壳器常把 .rdata 合并进可执行段，此时整个页是 RX。改成 RW 会
            //   把可执行权限一并撤掉，而同一页里可能就有正在执行的代码——
            //   挂完钩子目标进程会在下一次取指时崩掉（表现为「一注入就闪退」）。
            //   RWX 保留执行位，写完立刻还原成 oldProtect，暴露窗口只有几条指令。
            DWORD oldProtect = 0;
            if (!VirtualProtect(&iat->u1.Function, sizeof(void*),
                                PAGE_EXECUTE_READWRITE, &oldProtect))
                continue;

            // ★ 用 InterlockedExchangePointer 而不是直接赋值。
            //   目标进程可能正在多线程跑：另一个线程随时可能从这个槽调函数。
            //   x86/x64 上对齐的指针写入本身是原子的（不会读到半新半旧的地址），
            //   真正的问题是**可见性顺序**——普通赋值可能被编译器或 CPU 的写缓冲
            //   推迟到后面那条 VirtualProtect 之后才真正落到内存，于是页面先恢复
            //   成 RX、槽还是旧值，这一小段时间的挂接等于没生效。
            //   Interlocked 版本带完整屏障，保证「槽已更新」先于「权限已还原」可见。
            //   另外：正在调用旧地址的线程不受影响——它拿到的仍是原始函数指针，
            //   会正常执行完；这里刻意**不**挂起其它线程，因为从 DLL 内部挂起线程
            //   有与加载器锁 / 堆锁互锁的风险，代价远大于收益。
            InterlockedExchangePointer((PVOID volatile*)&iat->u1.Function, replacement);

            DWORD tmp = 0;
            VirtualProtect(&iat->u1.Function, sizeof(void*), oldProtect, &tmp);
            g_patched[g_patchedCount].slot     = (void**)&iat->u1.Function;
            g_patched[g_patchedCount].original = cur;
            g_patchedCount++;
            patched++;
        }
    }
    return patched;
}

// ---------------------------------------------------------------------------
// 动态取址（GetProcAddress）补漏
//
// 为什么需要它：IAT Hook 只改**导入表**。引擎若用
//     auto p = (pTextOutA)GetProcAddress(GetModuleHandleA("gdi32.dll"), "TextOutA");
// 自己取址再调用，导入表里根本没有这个函数，钩子自然抓不到——
// 使用者看到的现象是「钩子装好了、也报告挂上了 N 个槽，但一句话都没有」。
//
// 为什么不用 Inline Hook：那需要在函数开头改写指令，必须先算清前几条指令的
// 长度（最小长度反汇编器）。本项目的硬约定是零第三方依赖，手写一个能正确
// 处理全部 x86/x64 指令前缀与 ModRM/SIB 的 LDE 风险远高于收益——算错一个
// 字节就是把目标进程打崩。
//
// 这里用的替代方案更简单也更安全：**把 GetProcAddress 本身也挂上**。
// 引擎动态取址时，我们拦截这次查询，若它要的正是我们挂钩的函数，
// 就直接返回我们的替换函数。不需要改任何指令字节，只改 IAT 槽，和既有机制完全同构。
// 局限（必须如实说明）：只覆盖**通过导入表调用 GetProcAddress** 的情形；
// 若引擎自己 LoadLibrary+GetProcAddress 从 kernel32 现取（即连 GetProcAddress
// 都是动态拿的），仍会漏——那种情况只能上 Inline Hook。
// ---------------------------------------------------------------------------

#define MAX_DYN_TARGETS 32

// 需要挂钩的模块清单（真正的定义在下面 CollectHookModules 之前）。
// 这里先声明，因为 HookGetProcAddress 要在它填好之后遍历它。
#define MAX_HOOK_MODULES 512
static HMODULE g_hookMods[MAX_HOOK_MODULES];
static int     g_hookModCount;

typedef struct {
    void* targetAddr;      // 原始函数地址（GetProcAddress 会返回的那个）
    void* replacement;     // 我们的替换函数
    void** pOriginalSlot;  // 原函数地址存放处（供替换函数转发）
} DynTarget;

static DynTarget g_dyn[MAX_DYN_TARGETS];
static int       g_dynCount = 0;

typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);
static pGetProcAddress real_GetProcAddress = NULL;

// 我们的 GetProcAddress 替身：先问真的要地址，再看它是不是我们挂钩的目标。
static FARPROC WINAPI Hook_GetProcAddress(HMODULE hMod, LPCSTR name)
{
    // 只读一次全局变量。写成 `real_GetProcAddress ? real_GetProcAddress(...) : NULL`
    // 会读两遍：UnhookAll 把 real_GetProcAddress 置 NULL 恰好发生在两次读之间时，
    // 就会去调一个空指针（谁都可能还留着这个替身的地址）。
    // 变量类型必须是 pGetProcAddress 而不是 FARPROC：在 x64 上 FARPROC 是
    // `INT_PTR (WINAPI*)()`、与带参的 pGetProcAddress 不同型，混用会触发 C4047。
    pGetProcAddress real = real_GetProcAddress;
    if (!real) return NULL;
    FARPROC result = real(hMod, name);
    if (!result) return NULL;

    void* p = (void*)result;
    for (int i = 0; i < g_dynCount; i++)
    {
        if (g_dyn[i].targetAddr != p) continue;

        // 首次命中时把原地址记下来，供替换函数转发调用。
        // 这一步不能提前做：目标模块可能在挂 GetProcAddress 之后才被加载，
        // 提前 GetProcAddress 会触发一次不必要的 LoadLibrary。
        if (g_dyn[i].pOriginalSlot && *g_dyn[i].pOriginalSlot == NULL)
            *g_dyn[i].pOriginalSlot = p;

        return (FARPROC)g_dyn[i].replacement;
    }
    return result;
}

// 登记一个「动态取址时要改写成 replacement」的目标。
static void RegisterDynTarget(void* targetAddr, void* replacement, void** pOriginalSlot)
{
    if (!targetAddr || !replacement || g_dynCount >= MAX_DYN_TARGETS) return;

    // 同一地址可能被多个 profile 目标命中（例如同时挂了 TextOutA 两次），去重
    for (int i = 0; i < g_dynCount; i++)
        if (g_dyn[i].targetAddr == targetAddr) return;

    g_dyn[g_dynCount].targetAddr     = targetAddr;
    g_dyn[g_dynCount].replacement    = replacement;
    g_dyn[g_dynCount].pOriginalSlot  = pOriginalSlot;
    g_dynCount++;
}

// 把各模块 IAT 里的 GetProcAddress 换成我们的替身。
// 必须在所有目标登记完之后调用（替身查表时表要已经填好）。
static int HookGetProcAddress(void)
{
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return 0;

    void* realAddr = (void*)GetProcAddress(hK32, "GetProcAddress");
    if (!realAddr) return 0;
    real_GetProcAddress = (pGetProcAddress)realAddr;

    int total = 0;
    for (int m = 0; m < g_hookModCount; m++)
        total += PatchModuleIat(g_hookMods[m], NULL, realAddr,
                                (void*)Hook_GetProcAddress,
                                (void**)&real_GetProcAddress);
    return total;
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

// 每个目标的挂钩结果统计。存在的意义：IAT Hook 最典型的失败是
// 「装好了、一条文本也没有」，而原先 PatchModuleIat 的返回值被直接丢弃，
// 使用者完全无从判断是 profile 写错、目标模块没加载、还是引擎根本没走 IAT。
// 现在把「解析到地址了吗、挂到几个槽」逐条打进启动横幅。
#define MAX_STATS 32
static int g_statResolved[MAX_STATS];   // 是否解析到目标函数地址
static int g_statSlots[MAX_STATS];      // 成功替换的 IAT 槽总数
static int g_statModules[MAX_STATS];    // 命中（有槽被替换）的模块数
static int g_statGpaSlots = 0;          // GetProcAddress 被替换的槽数（0 = 动态取址未覆盖）

// 收集需要挂钩的模块：主 EXE + 所有非系统模块。
// 引擎可能在 EXE 里，也可能在随游戏加载的某个 DLL 里，两者都要覆盖。
// （MAX_HOOK_MODULES / g_hookMods / g_hookModCount 的声明在上面
//   HookGetProcAddress 之前，这里不再重复定义。）

static void CollectHookModules(void)
{
    g_hookModCount = 0;

    HMODULE hMain = GetModuleHandleW(NULL);
    if (g_hookModCount < MAX_HOOK_MODULES) g_hookMods[g_hookModCount++] = hMain;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return;

    MODULEENTRY32W me;
    me.dwSize = sizeof(me);
    if (Module32FirstW(snap, &me))
    {
        do {
            // 主 EXE 上面已经加过了，而模块快照**也包含它**，必须跳过
            if ((HMODULE)me.modBaseAddr == hMain) continue;
            if (IsDeniedModule(me.szModule)) continue;
            if ((HMODULE)me.modBaseAddr == g_hDll) continue;   // 绝不挂自己（会无限递归）
            if (g_hookModCount >= MAX_HOOK_MODULES) break;
            g_hookMods[g_hookModCount++] = (HMODULE)me.modBaseAddr;
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
}

static void HookAllModules(void)
{
    if (!g_profile) return;

    CollectHookModules();

    int n = g_profile->targetCount;
    if (n > MAX_STATS) n = MAX_STATS;
    memset(g_statResolved, 0, sizeof(g_statResolved));
    memset(g_statSlots,    0, sizeof(g_statSlots));
    memset(g_statModules,  0, sizeof(g_statModules));
    g_statGpaSlots = 0;

    // 动态取址表每轮重装都要清空：上一轮的 targetAddr/replacement 指向的是
    // 上一轮的 profile，重装后可能整个 profile 都换了。
    g_dynCount = 0;

    // ★ 通用转发器槽位同样必须每轮清空，而且要在下面的 RegisterGeneric 之前。
    //   不清后果：GenIdForTarget 用指针相等认领 id，而 g_genTargets[i] 一旦写入
    //   就再也没人释放；于是「Unhook → 改 ini → 再次 InstallConfig」（文档明确
    //   宣传的免重编译工作流）会一直命中原槽位，沿用上一轮的 textArg/lenArg/argc/
    //   conv 和上一轮记录的函数指针。x86 上 argc 从 5 变成 2 就会把栈弹歪，直接 AV。
    //   另一个症状是连续用 8 个不同通用 profile 之后永久「通用挂钩槽位已满」。
    memset(g_gen,        0, sizeof(g_gen));
    // g_genTargets 是指针数组、元素带 const，直接传给 memset 会触发 C4090
    // （「不同的 const 限定符」）。这里只是把它清零，显式转型表明意图。
    memset((void*)g_genTargets, 0, sizeof(g_genTargets));

    for (int i = 0; i < n; i++)
    {
        const HookTarget* t = &g_profile->targets[i];
        if (t->kind != HOOK_IAT) continue;

        // 1) 决定替换函数，以及「原函数地址写到哪」
        void*  replacement = NULL;
        void** pSlot = NULL;

        if (t->textArg > 0)
        {
            // 通用挂钩：text=/len= 由 profile 声明
            int id = RegisterGeneric(t);
            if (id < 0) {
                // 槽位用尽：明确记录，绝不假装挂上了
                g_statResolved[i] = -1;
                continue;
            }
            replacement = GenericReplacementFor(t);
            pSlot = (void**)&g_gen[id].original;
        }
        else
        {
            replacement = ReplacementFor(t->func, &pSlot);
            if (!replacement || !pSlot) {
                // 内置提取器只认 6 个函数名；文件 profile 里写错名字会走到这里
                g_statResolved[i] = -1;
                continue;
            }
        }

        // 2) 解析真实地址（按地址匹配，天然兼容 API Set 与名字修饰）
        HMODULE hOwner = NULL;
        void* targetAddr = ResolveTargetAddress(t, &hOwner);
        if (!targetAddr) {
            g_statResolved[i] = -1;
            continue;
        }
        g_statResolved[i] = 1;

        // 3) 遍历所有模块打补丁（同一个函数可能被多个模块分别导入）
        for (int m = 0; m < g_hookModCount; m++)
        {
            int got = PatchModuleIat(g_hookMods[m], t, targetAddr, replacement, pSlot);
            if (got > 0) {
                g_statSlots[i] += got;
                g_statModules[i]++;
            }
        }

        // 4) 登记到动态取址表：即使当前没有任何模块导入它，引擎之后用
        //    GetProcAddress 现取时也能拿到我们的替换函数。
        RegisterDynTarget(targetAddr, replacement, pSlot);
    }

    // 5) 最后挂 GetProcAddress 本身。必须放在所有 RegisterDynTarget 之后，
    //    否则替身在被调用时表还没填好，会漏掉先发生的查询。
    if (g_dynCount > 0)
        g_statGpaSlots = HookGetProcAddress();
}

static void UnhookAll(void)
{
    // 倒序还原：万一同一个槽被记了多条，先写回后记的那条（它可能是我们自己的
    // 替换函数），最后写回最早记下的真实地址，最终状态才正确。
    for (int i = g_patchedCount - 1; i >= 0; i--)
    {
        DWORD oldProtect = 0;
        // 与挂接时对称：必须保留执行位（页面可能同时装着代码），并走 Interlocked
        // 保证「槽已还原」先于「权限已还原」对其它线程可见。
        if (!VirtualProtect(g_patched[i].slot, sizeof(void*),
                            PAGE_EXECUTE_READWRITE, &oldProtect))
            continue;
        InterlockedExchangePointer((PVOID volatile*)g_patched[i].slot, g_patched[i].original);
        DWORD tmp = 0;
        VirtualProtect(g_patched[i].slot, sizeof(void*), oldProtect, &tmp);
    }
    g_patchedCount = 0;

    // 动态取址表与 GetProcAddress 替身一起失效。
    // real_GetProcAddress 必须清空：替身里 `real_GetProcAddress ? ... : NULL`
    // 那道判断就是靠它来保证「卸载后即使还有别处留着替身指针，也不会拿旧表乱跳」。
    g_dynCount = 0;
    real_GetProcAddress = NULL;
    g_statGpaSlots = 0;
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

// 追加到定长缓冲区；放不下就截断（绝不返回错误，也不触发无效参数处理器）。
// 为什么不能直接用 strcat_s：本 DLL 挂在**正在运行的游戏**里，而 profile 名来自
// 用户随手写的 ini。32 个 profile × 47 字符远超 384 字节的提示缓冲区，strcat_s
// 一旦超界就会调用无效参数处理器，把游戏进程直接终止——这正是本轮修 desc= /
// hook= 时的同一类问题，只是换了个位置。这里改用 strncat_s + _TRUNCATE，
// 最坏情况只是提示里少列几个 profile 名。
static void AppendCapped(char* out, size_t cch, const char* s)
{
    if (!out || cch == 0 || !s) return;
    strncat_s(out, cch, s, _TRUNCATE);
}

// 列出所有可用 profile 名，供「engine= 写错」时给出可操作的提示
static void BuildProfileList(char* out, size_t cch)
{
    out[0] = 0;
    for (int i = 0; i < g_fileProfileCount; i++) {
        if (out[0]) AppendCapped(out, cch, ", ");
        AppendCapped(out, cch, g_fileProfiles[i].prof.name);
    }
    for (int i = 0; i < kProfileCount; i++) {
        // 文件里已定义的就不再重复列
        if (FindProfileNarrow(kProfiles[i].name) != &kProfiles[i]) continue;
        if (out[0]) AppendCapped(out, cch, ", ");
        AppendCapped(out, cch, kProfiles[i].name);
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

// ---------------------------------------------------------------------------
// engine=auto：按 hintExe / hintClass 猜 profile
//
// 为什么需要：真实引擎的 profile 只能对着实机逆向填出来，而使用者手里只有
// 一个游戏。让他在 ini 里写好 `hintExe=krkr*.exe` 之后，注入时**什么都不用传**
// 就能选中对的 profile —— 这是「改 ini 不用重编译」这条承诺真正兑现的地方。
//
// 判定规则（都已写进 ini 注释，这里保持一致）：
//   · 某个 profile 两个 hint 都为空 → 不参与 auto 判定（绝不误选）。
//   · hintExe 与目标进程 exe 文件名比对，允许 * 和 ? 通配。
//   · hintClass 与目标进程**任意**顶层窗口的类名比对，同样允许通配。
//   · 两个 hint 都写了 → 必须同时命中。
//   · 多个 profile 命中 → 取 ini 里靠前的那个（文件先于内置，符合覆盖语义）。
// ---------------------------------------------------------------------------

// 大小写无关的通配匹配，支持 *（任意长）与 ?（单字符）。
// 用迭代式回溯而不是递归：pattern/text 都来自用户 ini，递归深度不受控。
static BOOL HintMatch(const char* pat, const char* text)
{
    if (!pat || !text) return FALSE;
    if (!pat[0]) return TRUE;          // 空 pattern 视作「命中」，由调用方先判空

    const char* starPat = NULL;        // 最近一个 * 的位置
    const char* starTxt = NULL;

    while (*text) {
        if (*pat == '?' ||
            (*pat && tolower((unsigned char)*pat) == tolower((unsigned char)*text))) {
            pat++;
            text++;
        } else if (*pat == '*') {
            starPat = pat++;
            starTxt = text;
        } else if (starPat) {
            // 回退：让上一个 * 多吞一个字符
            pat  = starPat + 1;
            text = ++starTxt;
        } else {
            return FALSE;
        }
    }
    while (*pat == '*') pat++;
    return (*pat == 0);
}

// 目标进程自身的 exe 文件名（不含路径）
static void CurrentProcessExeName(char* out, size_t cch)
{
    out[0] = 0;
    wchar_t w[MAX_PATH];
    if (!GetModuleFileNameW(NULL, w, MAX_PATH)) return;
    wchar_t* slash = wcsrchr(w, L'\\');
    const wchar_t* base = slash ? slash + 1 : w;
    WideCharToMultiByte(CP_ACP, 0, base, -1, out, (int)cch, NULL, NULL);
}

// EnumWindows 回调：目标进程任意顶层窗口的类名命中就算匹配
typedef struct {
    DWORD       pid;
    const char* pattern;
    BOOL        matched;
} ClassProbe;

static BOOL CALLBACK ClassProbeProc(HWND hWnd, LPARAM lp)
{
    ClassProbe* p = (ClassProbe*)lp;
    DWORD pid = 0;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid != p->pid) return TRUE;

    char cls[256];
    if (GetClassNameA(hWnd, cls, (int)sizeof(cls)) <= 0) return TRUE;
    if (HintMatch(p->pattern, cls)) {
        p->matched = TRUE;
        return FALSE;                  // 找到一个就够，停止枚举
    }
    return TRUE;
}

static BOOL HasWindowClassMatching(const char* pattern)
{
    ClassProbe probe;
    probe.pid      = GetCurrentProcessId();
    probe.pattern  = pattern;
    probe.matched  = FALSE;
    EnumWindows(ClassProbeProc, (LPARAM)&probe);
    return probe.matched;
}

// 单个 profile 是否命中当前进程。两个 hint 都空 = 不参与判定。
static BOOL ProfileHintsCurrentProcess(const EngineProfile* p)
{
    if (!p) return FALSE;
    if (!p->hintExe[0] && !p->hintClass[0]) return FALSE;

    if (p->hintExe[0]) {
        char exe[MAX_PATH];
        CurrentProcessExeName(exe, sizeof(exe));
        if (!exe[0] || !HintMatch(p->hintExe, exe)) return FALSE;
    }
    if (p->hintClass[0] && !HasWindowClassMatching(p->hintClass)) return FALSE;
    return TRUE;
}

// 在「文件 profile + 内置 profile」里按顺序找第一个命中的。
// 顺序刻意与 FindProfileNarrow 一致：文件优先，同名覆盖内置。
static const EngineProfile* ResolveAutoProfile(void)
{
    for (int i = 0; i < g_fileProfileCount; i++)
        if (ProfileHintsCurrentProcess(&g_fileProfiles[i].prof))
            return &g_fileProfiles[i].prof;

    for (int i = 0; i < kProfileCount; i++)
        if (ProfileHintsCurrentProcess(&kProfiles[i]))
            return &kProfiles[i];

    return NULL;
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
        else if (_stricmp(key, "desc") == 0) {
            // 必须用 _TRUNCATE 而不是 strcpy_s：本 DLL 挂在**正在运行的游戏**里，
            // 用户在 ini 里写一行超长 desc= 就会让 strcpy_s 触发无效参数处理器
            // 直接终止游戏进程。desc 只是给人看的注释，截断是完全可以接受的。
            if (strlen(val) >= MAX_DESC_LEN) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：desc 过长（上限 %d 字节）", lineNo, MAX_DESC_LEN - 1);
                break;
            }
            strcpy_s(fp->desc, MAX_DESC_LEN, val);
        }
        else if (_stricmp(key, "text") == 0 || _stricmp(key, "textarg") == 0)
            fp->pendingTextArg = atoi(val);
        else if (_stricmp(key, "len") == 0 || _stricmp(key, "lenarg") == 0)
            fp->pendingLenArg = atoi(val);
        else if (_stricmp(key, "argc") == 0)
            fp->pendingArgc = atoi(val);
        else if (_stricmp(key, "wide") == 0)
            fp->pendingWide = (atoi(val) != 0);
        else if (_stricmp(key, "conv") == 0)
        {
            // ★ 这里必须按「cdecl 才置 1」来写，不能按「stdcall 置 1」。
            //   conv 的取值语义是 0 = stdcall、1 = cdecl（见 HookTarget.conv），
            //   而结构体默认零初始化 —— 写成 `stdcall ? 1 : 0` 就把两者对调了：
            //   用户在 ini 里老老实实写 conv=stdcall，拿到的却是 cdecl 的 thunk，
            //   x86 上调用一次就弹歪栈、整个游戏进程访问违例。
            //   这个错误在 x64 上完全看不出来（只有一个调用约定），只在 x86 上炸。
            if (_stricmp(val, "cdecl") == 0)      fp->pendingConv = 1;
            else if (_stricmp(val, "stdcall") == 0) fp->pendingConv = 0;
            else {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：conv 只能是 stdcall 或 cdecl（当前 \"%s\"）", lineNo, val);
                break;
            }
        }
        else if (_stricmp(key, "hint") == 0 || _stricmp(key, "hintclass") == 0 ||
                 _stricmp(key, "hintwindow") == 0)
        {
            // hint= / hintClass= 是同一个东西（窗口类名）。
            // 用 _TRUNCATE 而不是报错：hint 只是给 auto 用的猜路提示，
            // 写长了一点最多是识别不出来，没有任何理由让整个 profile 作废。
            strncpy_s(fp->prof.hintClass, HT_HINT_MAX, val, _TRUNCATE);
        }
        else if (_stricmp(key, "hintexe") == 0 || _stricmp(key, "hintprocess") == 0)
        {
            strncpy_s(fp->prof.hintExe, HT_HINT_MAX, val, _TRUNCATE);
        }
        else if (_stricmp(key, "hook") == 0)
        {            if (fp->prof.targetCount >= MAX_FILE_TARGETS) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：hook 数量超过上限 %d", lineNo, MAX_FILE_TARGETS);
                break;
            }

            // hook=<模块>,<函数>[,<方式>]
            // 同样不能 strcpy_s 硬边界：超长的一行 hook= 会直接终止游戏进程。
            char v[256];
            if (strlen(val) >= sizeof(v)) {
                _snprintf_s(err, sizeof(err), _TRUNCATE,
                            "第 %d 行：hook 过长（上限 %d 字节）", lineNo, (int)sizeof(v) - 1);
                break;
            }
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

    // ---- 收尾：把段内暂存的 text=/len=/argc=/wide=/conv= 填进每个 target ----
    // 放在整段读完之后，才能容忍这些键写在 hook= 之后。
    // 校验失败同样按「全有或全无」处理：写错的 text= 绝不能静默变成
    // 「挂上了钩子但永远抓不到文本」——那是最难排查的一种失败。
    if (!err[0]) {
        for (int i = 0; i < g_fileProfileCount && !err[0]; i++) {
            FileProfile* fp = &g_fileProfiles[i];
            for (int j = 0; j < fp->prof.targetCount; j++) {
                HookTarget* t = &fp->targets[j];
                t->textArg = fp->pendingTextArg;
                t->lenArg  = fp->pendingLenArg;
                t->argc    = fp->pendingArgc;
                t->wide    = fp->pendingWide;
                t->conv    = fp->pendingConv;

                if (t->textArg == 0) continue;   // 专用提取器，无需校验

                if (t->argc < 1 || t->argc > HT_MAX_ARGC) {
                    _snprintf_s(err, sizeof(err), _TRUNCATE,
                                "profile [%s] 的 %s：声明了 text= 就必须同时给 argc=（1..%d），当前 %d",
                                fp->prof.name, t->func, HT_MAX_ARGC, t->argc);
                    break;
                }
                if (t->textArg < 1 || t->textArg > t->argc ||
                    t->lenArg < 0 || t->lenArg > t->argc) {
                    _snprintf_s(err, sizeof(err), _TRUNCATE,
                                "profile [%s] 的 %s：text=/len= 参数序号超出 argc=%d（序号从 1 开始）",
                                fp->prof.name, t->func, t->argc);
                    break;
                }
            }
        }
    }

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
            if (names[0]) AppendCapped(names, sizeof(names), ", ");
            AppendCapped(names, sizeof(names), g_fileProfiles[i].prof.name);
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
    // engine=auto 是「本次配置」的意图，每次 ApplyConfig 都要重算。
    // 不复位的话：第一轮 engine=auto、第二轮 engine=generic-gdi 时
    // g_autoRequested 还留着 1，横幅会报一串假的 auto 结果。
    // g_profileExplicit 同理：只置不清会让「上一轮显式指定过」永久压住
    // 后面所有 auto 请求。
    g_autoRequested   = FALSE;
    g_profileExplicit = FALSE;

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
            if (_wcsicmp(v, L"auto") == 0) {
                // engine=auto：**不**置 g_profileExplicit，交给 StartHooks 去猜。
                // 猜的时机必须晚于 profile 文件加载（这里可能正好在加载文件），
                // 也晚于窗口创建——注入时游戏通常已经建好窗口了。
                g_autoRequested = TRUE;
            } else {
                newProfile = FindProfile(v);
                if (newProfile) {
                    g_profileExplicit = TRUE;
                } else {
                    // 静默沿用默认值最难排查，这里给出可用清单
                    char list[384];
                    BuildProfileList(list, sizeof(list));
                    _snprintf_s(g_configWarn, sizeof(g_configWarn), _TRUNCATE,
                                "engine= 指定的 profile 未找到，已沿用默认；可用：%s（或写 auto 自动识别）", list);
                }
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

    // engine=auto 的兜底解析放在这里而不是 ApplyConfig 里：
    // Init / InstallHook 这两条入口根本不经过 ApplyConfig，只有放在 StartHooks
    // 才能让 auto 对三个入口表现一致。g_profileExplicit 为真时这里什么都不做，
    // 所以显式 engine= 永远不会被 auto 抢走。
    //
    // 注意 g_autoMatched 是**每轮重算**的：使用者按文档改了 ini 里的 hint 之后
    // 重新 InstallConfig，横幅要如实反映这一轮到底猜中没有。
    if (!g_profileExplicit) {
        const EngineProfile* autoP = ResolveAutoProfile();
        g_autoMatched = (autoP != NULL);
        if (autoP) g_profile = autoP;
    } else {
        g_autoMatched = FALSE;
    }

    // ★ 重新安装时必须复位这些标志。
    //   StopHooks 会把 g_stop 置 1，而它此前从没被清回过——
    //   于是「Unhook 之后再 InstallConfig」建出来的读写线程会立刻退出，
    //   DLL 看着装好了、实际一个字节都发不出来。
    //   g_pipeBroken 是每实例一份的数组，在下面建线程前连同 g_hPipe 一起复位。
    g_stop         = 0;
    g_patchedCount = 0;

    // 去重表与统计计数器必须每轮清零。
    // 不复位去重表的后果：上一轮的最后几条还占着槽位和时间戳，重装后
    // 同样的文本会在窗口内被当成重复丢掉，表现为「重装之后头几句不见了」。
    memset(g_dedup, 0, sizeof(g_dedup));
    g_statEmitted  = 0;
    g_statFiltered = 0;
    g_statDropped  = 0;

    // 临界区只初始化一次，且**永不删除**。
    // 原因：StopHooks 是有界等待（DllMain 里不能无限期阻塞），万一某个线程
    // 没能在超时内退出，删掉临界区就等于让它在已释放的对象上 EnterCriticalSection。
    // 这三个对象只有几十字节、随 DLL 映像一起消失，泄漏的代价远小于崩溃。
    if (!g_syncInited) {
        InitializeCriticalSection(&g_textCs);
        InitializeCriticalSection(&g_pipeCs);
        InitializeCriticalSection(&g_qCs);
        g_syncInited = TRUE;
    }

    // 停止事件同样按需创建；每轮安装前复位（手动重置事件，不复位会立刻"已停止"）
    if (!g_stopEvent)  g_stopEvent  = CreateEventW(NULL, TRUE,  FALSE, NULL);
    if (!g_writeEvent) g_writeEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_stopEvent || !g_writeEvent) return FALSE;
    ResetEvent(g_stopEvent);

    g_qEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!g_qEvent) return FALSE;

    HookAllModules();

    // 每轮安装都要把「已连接句柄」复位成 INVALID_HANDLE_VALUE。
    // 静态数组默认是 0，而 0 是个合法句柄值——不复位的话写线程会对着 0 调
    // WriteFile，不但发不出文本，还可能误写别的对象。
    EnterCriticalSection(&g_pipeCs);
    for (int i = 0; i < PIPE_INSTANCES; i++) {
        g_hPipe[i]       = INVALID_HANDLE_VALUE;
        g_pipeBroken[i]  = 0;
    }
    LeaveCriticalSection(&g_pipeCs);

    g_writerThread = CreateThread(NULL, 0, WriterThreadProc, NULL, 0, NULL);
    for (int i = 0; i < PIPE_INSTANCES; i++)
        g_pipeThread[i] = CreateThread(NULL, 0, PipeThreadProc, (LPVOID)(INT_PTR)i, 0, NULL);

    g_initialized = TRUE;

    char msg[1024];
    _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                "[TextHookDll] 已安装 profile=%s  cp=%u  挂钩槽=%d  管道=\\\\.\\pipe\\%s  PID=%lu\n",
                g_profile ? g_profile->name : "?",
                g_codepage ? g_codepage : (g_profile ? g_profile->codepage : 0),
                g_patchedCount, g_pipeName, GetCurrentProcessId());
    Enqueue(msg);

    // engine=auto 的结果单独一行。这一行是「我写了 auto，到底猜中没有」的
    // 唯一直接证据——否则使用者只能靠「挂到几个槽」反推，而猜错 profile
    // 与引擎没走 IAT 在日志里是同一个现象。
    if (g_autoRequested) {
        char am[512];
        if (g_autoMatched) {
            _snprintf_s(am, sizeof(am), _TRUNCATE,
                        "[TextHookDll] engine=auto 已命中 profile=%s（按 hintExe / hintClass 匹配）\n",
                        g_profile ? g_profile->name : "?");
        } else {
            _snprintf_s(am, sizeof(am), _TRUNCATE,
                        "[TextHookDll] engine=auto 未能命中任何 profile（没有任何 profile 的 "
                        "hintExe= / hintClass= 与本进程匹配），已用默认 profile=%s；"
                        "请在 %s 里给对应 profile 补上 hintExe= 或 hintClass=\n",
                        g_profile ? g_profile->name : "?",
                        g_profileFileMsg[0] ? "TextHookDll.profiles.ini" : "profile 文件");
        }
        Enqueue(am);
    }

    // 逐条报告每个目标挂到了几个槽。
    // 为什么值得单独占一行：IAT Hook 最典型的失败是「装好了但一条文本也没有」，
    // 而原因可能是函数名写错、模块没加载、或引擎压根没走 IAT——
    // 把这三者区分开的唯一线索就是「解析到地址了吗 / 挂到几个槽」。
    if (g_profile) {
        int n = g_profile->targetCount;
        if (n > MAX_STATS) n = MAX_STATS;
        for (int i = 0; i < n; i++) {
            const HookTarget* t = &g_profile->targets[i];
            char line[512];
            if (g_statResolved[i] < 0) {
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "[TextHookDll]   %s!%s → 未挂钩（%s）\n",
                            t->module, t->func,
                            t->textArg > 0 ? "通用挂钩槽位已满"
                                           : "框架不认识该函数名（内置提取器只有 6 个）");
            } else if (g_statSlots[i] == 0) {
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "[TextHookDll]   %s!%s → 地址已解析，但当前没有模块导入它（已登记到动态取址表，引擎用 GetProcAddress 现取时仍能抓到）\n",
                            t->module, t->func);
            } else {
                _snprintf_s(line, sizeof(line), _TRUNCATE,
                            "[TextHookDll]   %s!%s → %d 个模块 / %d 个槽\n",
                            t->module, t->func, g_statModules[i], g_statSlots[i]);
            }
            Enqueue(line);
        }
    }

    // 动态取址覆盖情况单独一行：这一行是「钩子挂上了却抓不到文本」时
    // 判断「引擎是不是 GetProcAddress 现取」的直接依据。
    {
        char gpa[512];
        if (g_dynCount == 0) {
            _snprintf_s(gpa, sizeof(gpa), _TRUNCATE,
                        "[TextHookDll] 动态取址：未启用（没有可挂钩的目标）\n");
        } else if (g_statGpaSlots == 0) {
            _snprintf_s(gpa, sizeof(gpa), _TRUNCATE,
                        "[TextHookDll] 动态取址：已登记 %d 个目标，但没有模块通过 IAT 调用 GetProcAddress（引擎可能连取址都是动态的，需要 Inline Hook）\n",
                        g_dynCount);
        } else {
            _snprintf_s(gpa, sizeof(gpa), _TRUNCATE,
                        "[TextHookDll] 动态取址：已登记 %d 个目标，GetProcAddress 替换了 %d 个槽\n",
                        g_dynCount, g_statGpaSlots);
        }
        Enqueue(gpa);
    }

    // 运行期统计单独一行。这一行是「钩子装好了，但文本要么少、要么乱」时
    // 区分原因的直接依据：
    //   emitted=0                → 钩子根本没被调用（函数选错 / 引擎走的不是这条路）
    //   filtered 远大于 emitted  → 抓到的是碎片或重复（minlen 太高 / 同一句被反复重绘）
    //   dropped > 0              → 队列溢出，消费端跟不上或管道卡住
    // 报的是「上一轮卸载时」留下的快照（见 StopHooks）：本轮刚清零，报 0 没意义。
    if (g_lastStats[0]) {
        char stats[512];
        _snprintf_s(stats, sizeof(stats), _TRUNCATE,
                    "[TextHookDll] 上一轮统计：%s\n", g_lastStats);
        Enqueue(stats);
        g_lastStats[0] = 0;
    }

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

    // 先把统计快照存下来——管道马上要关，这些数字之后就没地方报了。
    // 用 _TRUNCATE 不用硬边界：这里在 DllMain(DETACH) 里也可能被调用，
    // 任何一次「无效参数」都是直接终止目标进程。
    _snprintf_s(g_lastStats, sizeof(g_lastStats), _TRUNCATE,
                "上报 %ld 条，过滤 %ld 次，队列溢出丢弃 %ld 条",
                (long)g_statEmitted, (long)g_statFiltered, (long)g_statDropped);

    g_stop = 1;
    // 取句柄与 SetEvent 都放进 g_qCs：Enqueue 也在同一把锁里读 g_qEvent，
    // 这样下面的 CloseHandle 不会与 SetEvent 撞车（见 Enqueue 里的 TOCTOU 注释）。
    EnterCriticalSection(&g_qCs);
    if (g_qEvent) SetEvent(g_qEvent);
    LeaveCriticalSection(&g_qCs);
    // ★ 关键：g_stop 只能被**轮询**，而管道线程可能正阻塞在 ConnectNamedPipe 上，
    //   永远轮询不到它。不唤醒的话 StopHooks 会超时返回，留下一个"僵尸"管道线程：
    //   它一直占着 \\.\pipe\<name> 的实例（每个实例都是一份占用），于是**下次安装**
    //   的 CreateNamedPipeA 会拿不到足够实例，重装之后管道传不出一个字节。
    //   同时它以后还会去碰已经被删掉的临界区。
    if (g_stopEvent) SetEvent(g_stopEvent);

    // 有界等待：DllMain(DLL_PROCESS_DETACH) 里不能无限期阻塞。
    // 每个实例线程单独等，任一超时就记 allGone = FALSE。
    //
    // 写线程的上限给到 5 秒而不是 2 秒：它可能正卡在一次 PipeWrite 里，
    // 而单次 PipeWrite 最坏要 3 秒（2000 等待 + 1000 取消确认）。
    // 2 秒的上限意味着「只要卸载时刚好有一个客户端连上不读，就必然超时」。
    // 排空循环内部也检查了 g_stop，所以正常情况下收到停止信号后
    // 至多再完成一次写就会退出。
    BOOL allGone = TRUE;
    if (g_writerThread) {
        allGone &= (WaitForSingleObject(g_writerThread, 5000) == WAIT_OBJECT_0);
        CloseHandle(g_writerThread); g_writerThread = NULL;
    }
    for (int i = 0; i < PIPE_INSTANCES; i++) {
        if (!g_pipeThread[i]) continue;
        // 管道线程等的就是 g_stopEvent（重叠 ConnectNamedPipe），响应很快。
        allGone &= (WaitForSingleObject(g_pipeThread[i], 2000) == WAIT_OBJECT_0);
        CloseHandle(g_pipeThread[i]); g_pipeThread[i] = NULL;
    }

    UnhookAll();

    // 只有在确认线程都退出后才关闭它们可能仍在引用的对象；
    // 否则宁可泄漏这几个句柄，也不能让存活线程等在已关闭的事件上。
    if (allGone) {
        EnterCriticalSection(&g_qCs);
        if (g_qEvent)    { CloseHandle(g_qEvent);    g_qEvent    = NULL; }
        LeaveCriticalSection(&g_qCs);
        if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = NULL; }
        if (g_writeEvent){ CloseHandle(g_writeEvent);g_writeEvent= NULL; }
    }
    else {
        // 有线程活过了有界等待。这里**无法**补救：CloseHandle 不终止线程，
        // 而一旦调用方随后 FreeLibrary，那条线程的 PC 还指着本映像的代码段，
        // 必然 AV。能做的只有两件事：
        //   1) 把事件对象全部留下不关（下面那条路已经做了），让存活线程不会
        //      等在已销毁的内核对象上；
        //   2) 明确报告出来，别让使用者以为是「干净卸载」。
        OutputDebugStringW(L"[TextHookDll] 警告: 有工作线程未能及时退出，"
                           L"此时卸载 DLL 可能导致目标进程崩溃。\n");
    }

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
