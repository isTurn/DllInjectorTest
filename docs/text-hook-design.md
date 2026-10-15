# 多引擎文本 Hook 适配 — 架构设计

> 面向 GalGame 注入链路的下一个阶段：从「能把 DLL 注进去」走到「能稳定拿到游戏正在显示的文本」。

---

## 1. 要解决的问题

现有注入器解决了**投送**问题：挂起启动 → 注入 → 恢复运行 → 调用导出函数初始化。
但拿不到文本。而不同 GalGame 引擎的文本输出路径完全不同：

| 引擎类型 | 文本输出方式 | 典型代表 |
| --- | --- | --- |
| GDI 系 | `TextOutA/W`、`ExtTextOutA/W`、`DrawTextA/W` | BGI、多数老引擎、部分 RealLive |
| 自绘 + GDI 混合 | 引擎自己排版，最终仍落到 GDI 输出 | 相当多的日系商业引擎 |
| DirectX 系 | 字形渲染成纹理，走 D3D 绘制 | 后期 KiriKiri、部分新引擎 |
| 引擎私有 | 引擎内部函数产出文本，渲染完全自管 | KiriKiri（TJS 层）、Artemis 等 |

**结论：不存在一个万能 hook 点。** 必须做成「**一套 Hook 框架 + 可插拔的引擎 profile**」，
新增引擎 = 新增一份 profile，而不是改框架。

---

## 2. 分层设计

```
┌──────────────────────────────────────────────────────────┐
│  TextHookClient.exe / 翻译工具 / 任何管道消费者            │  ← 消费层
└───────────────────────▲──────────────────────────────────┘
                        │ 命名管道 \\.\pipe\GalToolText[.<pid>]
┌───────────────────────┴──────────────────────────────────┐
│  Sink（输出通道）                                          │
│    · 管道服务端（后台线程 + 连接管理）                      │
│    · 可选文件落盘（log=1，便于无客户端时验证）              │
│    · 去重（同一文本 N ms 内只发一次）                       │
└───────────────────────▲──────────────────────────────────┘
┌───────────────────────┴──────────────────────────────────┐
│  Extractor（文本提取 + 编码转换）                           │
│    · 按 profile 声明从 hook 上下文取文本（参数下标 / 指针）  │
│    · SJIS(932) / GBK(936) / UTF-8(65001) → UTF-16 → UTF-8  │
│    · 过滤：长度阈值、空白、控制字符                         │
└───────────────────────▲──────────────────────────────────┘
┌───────────────────────┴──────────────────────────────────┐
│  HookEngine（挂钩执行层）                                   │
│    · IAT Hook（一阶段，默认）                               │
│    · Inline Hook（二阶段，需长度反汇编）                    │
│    · VTable Hook（三阶段，DirectX / C++ 虚函数）            │
└───────────────────────▲──────────────────────────────────┘
┌───────────────────────┴──────────────────────────────────┐
│  EngineProfile（引擎适配表）— 唯一的「引擎相关」部分         │
│    · 挂钩目标清单（模块!函数 + 挂钩方式）                    │
│    · 编码、文本提取规则、去重参数、匹配提示                  │
└──────────────────────────────────────────────────────────┘
```

**框架不认引擎，profile 才认引擎。** 这是整个设计的核心约束。

---

## 3. EngineProfile 抽象

```c
typedef struct {
    const char* module;     // "gdi32.dll"
    const char* func;       // "TextOutA"
    int         kind;       // HOOK_IAT / HOOK_INLINE / HOOK_VTABLE
    int         textArg;    // 文本在第几个参数（0 基）
    int         lenArg;     // 长度在第几个参数；-1 = 以 \0 结尾
} HookTarget;

typedef struct {
    const char*  name;          // "kirikiri" / "bgi" / "generic-gdi"
    UINT         codepage;      // 932 / 936 / 1200
    HookTarget   targets[16];
    int          targetCount;
    int          minLen;        // 短于此长度的文本丢弃（滤噪）
    DWORD        dedupMs;       // 去重窗口
    const char*  hintClass;     // 可选：窗口类名提示，用于 auto 识别
    const char*  hintExe;       // 可选：进程名提示
} EngineProfile;
```

### 内置 profile（一阶段随 DLL 编译进去）

| profile | 编码 | 挂钩目标 | 说明 |
| --- | --- | --- | --- |
| `generic-gdi` | 自动探测 | `gdi32!TextOutA/W`、`ExtTextOutA/W`、`DrawTextA/W` | **万能兜底**，覆盖面最广，先跑通再针对性优化 |
| `generic-gdi-sjis` | 932 | 同上 | 日文原版游戏，强制 Shift-JIS |
| `generic-gdi-gbk` | 936 | 同上 | 中文汉化版，强制 GBK |
| `generic-unicode` | 1200 | 只挂 `*W` 系列 | 已用宽字符输出的引擎 |

> 真实引擎 profile（KiriKiri / BGI / RealLive / Artemis…）需要**对着实机样本逆向**才能填出
> 正确的 `module!func` 与参数布局——这部分必须一台游戏一份地做，无法凭空推测。

### 3.1 实现现状与上面这张图的差距

上面是**目标形态**。当前 `TextHookDll.c` 里实际落地的 `HookTarget` / `EngineProfile` 是它的子集：

| 字段 | 状态 | 说明 |
| --- | --- | --- |
| `module` / `func` / `kind` | ✅ 已实现 | `kind` 目前只有 `HOOK_IAT` |
| `name` / `codepage` / `minLen` / `dedupMs` | ✅ 已实现 | 可外部化，见 §3.2 |
| `textArg` / `lenArg` | ❌ 未实现 | 「哪个参数是文本」目前写死在 `ReplacementFor()` 的「函数名 → 提取器」映射里 |
| `hintClass` / `hintExe` | ❌ 未实现 | `auto` 识别尚未落地，只能靠 `engine=` 显式指定 |

**这张表是理解 S3 能力边界的关键**：因为 `textArg` / `lenArg` 没外部化，
文件 profile 只能从框架**已知的 6 个函数**里挑，不能引入新函数。

### 3.2 外部化后的 profile 文件（S3）

DLL 从**自身所在目录**读取 `TextHookDll.profiles.ini`，也可用
`-exportarg "...|profilefile=<路径>"` 指定别处，或用 `nofile=1` 完全禁用。

```ini
[my-game-jp]
desc=某日文原版游戏
codepage=932
minlen=3
dedup=400
hook=gdi32.dll,TextOutA
hook=gdi32.dll,ExtTextOutA
hook=user32.dll,DrawTextA
```

规则：

| 项 | 行为 |
| --- | --- |
| 同名覆盖 | 文件里的 `[generic-gdi]` 会覆盖内置的那一个，可用来调兜底行为 |
| 全有或全无 | 任何一行出错则整份文件不生效、退回内置 profile，并在启动横幅说明原因 |
| 未实现的方式 | `hook=...,inline` / `hook=...,vtable` **报错**而不是忽略（避免误以为挂钩装上了） |
| profile 名 | 必须 ASCII。`engine=` 参数是 UTF-16、比对时按 `CP_ACP` 转窄，而文件是 UTF-8，非 ASCII 名必然对不上 |
| 未知键 | 忽略，给前向兼容留空间 |
| 可观测性 | 启动横幅单独一行报告「读了哪个文件、加载了几个、叫什么」；`engine=` 写错时告警列出全部可用名 |

---

## 4. Hook 策略分层

### 一阶段：IAT Hook（本次实现）

改目标模块导入表（IAT）里对应函数的地址，指向自己的实现，原地址存起来供转发。

- ✅ **不需要反汇编、不需要长度解码器**，实现可靠，不会被指令边界问题坑死
- ✅ 对目标进程零破坏性，卸载时还原即可
- ❌ **只覆盖走 IAT 的调用**：如果引擎用 `GetProcAddress` 拿指针再调，IAT 里看不到

对多数 GDI 系引擎，引擎是静态链接 gdi32 并走 IAT 的，**一阶段足以拿到大部分文本**。

### 二阶段：Inline Hook（后续）

在函数入口写 `jmp`，把被覆盖的指令搬到跳板（trampoline）里执行后再跳回。

- ✅ 覆盖所有调用方式，包括 `GetProcAddress` 动态解析
- ❌ **必须正确判断被覆盖字节里的完整指令长度**（x86 变长指令）——
  要么内嵌一个轻量长度反汇编器，要么用 `hde`/`Zydis` 之类的库，但本项目坚持零第三方依赖，
  所以需要自己写一个覆盖常见 prologue 的最小长度解码器

### 三阶段：VTable Hook（DirectX 系）

对 D3D 系引擎，文本不以字符串形式经过任何 API，必须挂在绘制层或直接读引擎内存。

- 这类引擎更适合**换思路**：不打 API 的主意，改从引擎的文本缓冲区读（需要逆向定位结构体）

---

## 5. 编码转换

GalGame 文本编码情况：

| 场景 | 编码 | Win32 代码页 |
| --- | --- | --- |
| 日文原版（绝大多数） | Shift-JIS | 932 |
| 中文汉化版（老游戏） | GBK / GB2312 | 936 |
| 中文汉化版（新引擎） | UTF-8 或 UTF-16 | 65001 / 1200 |
| 韩文 | EUC-KR | 949 |

处理路径：`MultiByteToWideChar(cp, ...)` → 内部统一 UTF-16 → 输出时 `WideCharToMultiByte(CP_UTF8, ...)`。

**`*A` 系列函数拿到的就是原始字节，编码由 profile 声明**——这是 profile 里 `codepage` 字段存在的原因。
`*W` 系列已经是 UTF-16，跳过转换。

> 坑：`MultiByteToWideChar` 对非法序列会静默替换，可能出现乱码但不报错。
> 一阶段先接受；后续可加「转换失败率」统计，用于自动纠正 codepage 猜测。

---

## 6. 输出通道：命名管道

选管道而不是文件/共享内存的理由：

- **流式**：翻译工具需要实时拿到文本，不能等文件 flush
- **零依赖**：`CreateNamedPipe` 是 Win32 原生，不需要额外组件
- **天然多客户端**：可以同时挂多个消费者

**协议**（按行分隔，UTF-8，`\t` 分隔字段）：

```
GalToolText\t<pid>\t<hook>\t<text>\n
```

例：
```
GalToolText	41016	TextOutW	こんにちは
```

- 管道名：`\\.\pipe\GalToolText`（默认，可用 `pipe=` 覆盖）；多开场景建议 `pipe=GalToolText.<pid>`
- 服务端由 DLL 在 `InstallConfig` 时创建，后台线程循环 `ConnectNamedPipe`
- 写失败（客户端断开）→ 关闭实例、重新 accept，不影响游戏运行

**去重是必须的**：游戏每帧重绘文本，同一句话每秒可能触发 60 次。
`dedupMs` 窗口内相同文本只发一次（默认 200ms），否则管道会被瞬间打爆。

---

## 7. 与现有注入器的集成 — **零改动**

这是这套设计最舒服的地方：现有注入器**已经具备**所需的一切能力。

```bat
:: 启动游戏 + 注入文本 Hook DLL + 下发引擎配置，一条命令
DllInjector-x64.exe -inject "游戏.exe" TextHookDll-x64.dll ^
    -export InstallConfig -exportarg "engine=generic-gdi|cp=932|pipe=GalToolText|log=1"
```

复用到的既有机制：

| 现有能力 | 在文本 Hook 中的角色 |
| --- | --- |
| 多 DLL 批量注入 | 文本 Hook DLL 与游戏 MOD DLL 可一起注入，顺序可控 |
| `-export InstallConfig` + `-exportarg "k=v\|k=v"` | **配置下发通道**——profile 选择、编码、管道名全靠它 |
| 启动时注入（挂起 → 注入 → 恢复） | DLL 在目标**挂起状态**下就被加载，DllMain 已执行；但挂钩动作由导出函数完成，见下方「执行顺序」说明 |
| `-injectpid` / `-injectname` 批量注入 | 对已运行的游戏补挂 |
| PE 体检 / 位数校验 | 提前拦掉位数不符、缺重定位段的 DLL |
| 手动映射注入（`-method mm`） | 反调试较强的引擎可用，不落盘、不进模块列表 |

**不需要给注入器加任何代码。** 注入器保持「通用投送器」定位，
引擎适配知识全部沉淀在 profile 里——这也符合它现有的单文件、零依赖设计。

### 执行顺序：挂钩动作发生在游戏开跑之后

读 `InjectorCore.Run` 的实际流程，顺序是这样的：

```
CreateProcess(SUSPENDED) → 逐个 LoadLibraryW 注入 DLL → ResumeThread → 调用导出函数(InstallConfig)
                                                          ▲                ▲
                                                     游戏开始运行      挂钩在这里才装上
```

即**恢复主线程发生在调用导出函数之前**（`ResumeThread` 在 `try/finally` 的 finally 里，
导出函数调用在 finally 之后）。因此：

- 挂钩完成前，游戏已经跑了一小段（实测量级约几十到一两百毫秒，取决于游戏启动开销）
- 这段窗口内输出的文本**抓不到**

**实际影响很小**：GalGame 启动后先出 logo / 厂商动画，第一句对白通常在数秒之后，
一百毫秒的缺口不会漏掉对白。

**若要彻底消除该缺口**，有两条路（都属于 S2）：

1. **在 `DllMain(DLL_PROCESS_ATTACH)` 里装挂钩**——此时进程仍挂起，能赶在游戏执行第一条指令前完成。
   但 DllMain 持有加载器锁，**不能**调用 `CreateToolhelp32Snapshot` 这类内部会取加载器锁的 API
   （会死锁），只能安全地做「主 EXE 的 IAT 补丁」这类纯内存写。而且此刻配置尚未下发，
   编码只能先按系统 ANSI 猜——需要把早期捕获的**原始字节**缓存下来，等 `InstallConfig` 给出 codepage 后再转换。
2. **改注入器，让导出函数在 `ResumeThread` 之前调用**——最干净，但会改变现有工具的行为
   （某些 DLL 的导出函数可能依赖目标进程已在运行），需要谨慎评估，建议做成可选开关。

当前实现选择**先接受这个缺口并把限制写清楚**，而不是塞一个半可用的 DllMain 挂钩进去。

---

## 8. 路线图

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| **S1** | 框架骨架 + IAT Hook + 编码转换 + 管道输出 + `generic-gdi` profile | ✅ 已实现 |
| **S2** | 最小长度反汇编器 + Inline Hook，覆盖 `GetProcAddress` 动态解析的引擎 | 待做 |
| **S3** | 外部化 profile（INI 文件，改引擎适配不用重编译 DLL） | ✅ 已实现 |
| **S4** | 具体引擎 profile：对实机样本逆向填 `module!func` 与参数布局 | 待做（需样本） |
| **S5** | VTable / DirectX 系适配，或改用「读引擎文本缓冲区」路线 | 待做 |

S3 完成后，profile 已从编译期挪到运行期：适配新引擎只要写一个文本文件，
不用重新编译、也不用重新分发 DLL。**但 S3 只外部化了「挑哪些函数、用什么编码、
去重与长度阈值」，没有外部化「怎么从函数参数里取文本」**——后者仍是编译期的，
见 §9「已知限制」里的能力边界说明。

---

## 9. 已知限制（一阶段）

- **启动后有一小段抓不到**：注入器的 `ResumeThread` 早于导出函数调用，
  挂钩装上之前游戏已跑了几十到一两百毫秒，这段文本会漏（详见第 7 节「执行顺序」）
- **只覆盖 IAT 调用**：走 `GetProcAddress` 的引擎抓不到，需等 S2 的 Inline Hook
- **profile 文件只能「挑函数」，不能「加函数」**：S3 之后文件可以决定挂哪几个函数、
  用什么编码、长度与去重阈值，但**「怎么从参数里取文本」仍是编译期的**
  （`ReplacementFor()` 里的「函数名 → 提取器」映射）。所以适配用了其它文本 API 的引擎
  仍然要改代码（属 S2 / S4）。文件里写框架不认识的函数名**不会报错，但也不会有任何效果**——
  这是 S3 最容易被人误解的地方，故在文件头、ini 注释与本文档三处都写明
- **导入表按模块名精确匹配**：只认 `gdi32.dll` / `user32.dll` 这类直连导入。
  若目标通过 `api-ms-win-*` API Set 间接导入文本函数，当前匹配不到——
  这类二进制需要额外做一层模块名归一化（`api-ms-win-gdi-*` → `gdi32`）
- **对运行中的进程补挂存在竞态**：IAT 补丁是逐槽写入的，目标进程此刻正在运行，
  极小概率命中「刚好读到半更新的导入表」。启动时注入（挂起态）无此问题
- **`auto` 识别很弱**：目前只按 profile 的 `hintExe` / `hintClass` 做简单匹配，
  真正的引擎识别需要更多样本特征（资源段特征、字符串特征、模块列表特征）
- **不做文本合并**：GalGame 常把一句话分多次输出（逐字显示），一阶段按次上报，
  句子重组交给消费端
- **管道单消费者**：管道只创建单实例，同时挂多个消费者需要改成多实例
- **管道线程在无人连接时会漏掉一个线程和一个管道实例**（已发现，**暂未修**）：
  `ConnectNamedPipe` 在阻塞句柄上会一直等客户端，而 `StopHooks` 的 1 秒有界等待超时后
  只 `CloseHandle` 了**线程句柄**——关线程句柄不会终止线程，于是该线程与它持有的管道实例
  一直留着。正常用法（注入一次、挂到游戏退出）只在进程收尾时发生一次，影响有限；
  但反复 `Unhook` / 重装会累积，且残留实例仍占着同名管道、可能抢先接走客户端。
  干净的修法是改用 `FILE_FLAG_OVERLAPPED` + 事件等待，让循环能及时看到 `g_stop`。
  之所以先记不修：这条路径需要「有客户端连接」才能真正验证，而当前自动化测试里没有
  客户端，`StopHooks` 的有界超时又会把实现缺陷掩盖成「只是慢一点」，改它的风险大于收益
- **不做翻译**：本层只负责「把文本拿出来」，翻译与回填是消费端的事
- **DirectX 系引擎无解**：一阶段完全不覆盖

---

## 10. 验证方式

分两层：**自动化进程内验证**（日常回归，一条命令）与**手工跨进程验证**（贴近真实注入链路）。

### 10.1 自动化：`TestTextHook`（主）

```bat
:: 编译两个架构，然后自动跑两个架构的验证
test\TextHookDll\build.bat
```

`build.bat` 编译完成后会自动执行 `TestTextHook-x64.exe` 与 `TestTextHook-x86.exe`，
任一架构失败即打印 `VERIFY_FAIL` 并以非零码退出。所以「x86 和 x64 都要测试」是命令保证的，
不是人工约定。

`TestTextHook` 把整条链路收进**一个进程**：自己 `LoadLibrary`、自己调 `InstallConfig`
装钩子、自己用 GDI 输出文本、自己读 `texthook_log.txt` 判断结果。它跑的 4 个场景：

| 场景 | 目的 |
| --- | --- |
| 内置 `generic-gdi` | 基线：6 个函数都能抓到，SJIS → UTF-8 正确 |
| 文件 profile 只挂 `TextOutA` | **S3 是否真正生效的关键断言**——`TextOutW` 不该被抓到 |
| 故意写错的 profile 文件 | 全有或全无：应整份退回内置，且仍能抓到文本 |
| 随仓库分发的模板 ini | 保证分发出去的模板本身可用 |

断言覆盖：无修饰导出名可取（x86 `.def` 的回归防线）、启动横幅内容、编码转换正确、
profile 对挂钩集合的实际约束、**卸载后主 EXE 的 IAT 已完全还原**
（逐槽检查有没有地址落在 DLL 映像范围内）。

> 最后那条断言是有来历的：它抓出了「主 EXE 被重复挂钩 → 卸载时把 IAT 槽还原成
> 我们自己的替换函数」这个缺陷——`Unhook` 恒返回 1，光看返回值完全看不出来。
> 这也说明**验证要检查副作用，而不是检查返回值**。

`TestTextTarget` / `TestTextHook` 都用**硬编码字节数组或 `\uXXXX` 转义**写期望文本，
不含任何非 ASCII 字面量，因此「抓到的文本对不对」与源码文件编码无关。

### 10.2 手工：跨进程真实注入链路（补充）

自动化测试走的是 `LoadLibrary`，而真实链路走的是注入器，值得偶尔手工确认一次：

```bat
:: 1. 起客户端监听管道
test_output\TextHookClient.exe

:: 2. 注入并启动目标程序（目标程序会主动用 GDI 输出日文/中文文本）
DllInjector-x64.exe -inject test_output\TextTarget_x64.exe test_output\TextHookDll-x64.dll ^
    -export InstallConfig -exportarg "engine=generic-gdi|cp=932|log=1"
```

预期：客户端实时打印捕获到的文本，同时 `texthook_log.txt` 落盘一份。

注意 `cp=` 是**进程级**的，一个进程只能有一种 `*A` 编码。`TextTarget` 默认输出 Shift-JIS；
要跑 GBK 就 `TextTarget_x64.exe gbk` 并传 `cp=936`。两者不匹配时 `*A` 文本必然乱码，这是设计使然。

### 10.3 验证 profile 文件是否真的被读到

看 `texthook_log.txt` 开头的启动横幅，它有两行：

```
[TextHookDll] 已安装 profile=my-game-jp  cp=932  挂钩槽=8  管道=\\.\pipe\GalToolText  PID=1234
[TextHookDll] profile 文件 D:\...\TextHookDll.profiles.ini 已加载 2 个：my-game-jp, my-game-cn
```

第二行直接回答「我改的那个文件到底有没有被读到、里面的 profile 认出来了没有」。
