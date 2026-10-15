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
| **S1** | 框架骨架 + IAT Hook + 编码转换 + 管道输出 + `generic-gdi` profile | ✅ 本次实现 |
| **S2** | 最小长度反汇编器 + Inline Hook，覆盖 `GetProcAddress` 动态解析的引擎 | 待做 |
| **S3** | 外部化 profile（INI/JSON 文件，改引擎适配不用重编译 DLL） | 待做 |
| **S4** | 具体引擎 profile：对实机样本逆向填 `module!func` 与参数布局 | 待做（需样本） |
| **S5** | VTable / DirectX 系适配，或改用「读引擎文本缓冲区」路线 | 待做 |

**S3 是性价比最高的下一步**：把 profile 从编译期挪到运行期，
以后适配新引擎只需要写一个文本文件、不用重新编译和重新分发 DLL。

---

## 9. 已知限制（一阶段）

- **启动后有一小段抓不到**：注入器的 `ResumeThread` 早于导出函数调用，
  挂钩装上之前游戏已跑了几十到一两百毫秒，这段文本会漏（详见第 7 节「执行顺序」）
- **只覆盖 IAT 调用**：走 `GetProcAddress` 的引擎抓不到，需等 S2 的 Inline Hook
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
- **不做翻译**：本层只负责「把文本拿出来」，翻译与回填是消费端的事
- **DirectX 系引擎无解**：一阶段完全不覆盖

---

## 10. 验证方式

配套提供了可复现的端到端验证链路（不依赖真实游戏）：

```bat
:: 1. 编译测试素材
test\TextHookDll\build.bat

:: 2. 起客户端监听管道
TextHookClient.exe

:: 3. 注入并启动目标程序（目标程序会主动用 GDI 输出日文/中文文本）
DllInjector-x64.exe -inject test_output\TextTarget_x64.exe test_output\TextHookDll-x64.dll ^
    -export InstallConfig -exportarg "engine=generic-gdi|cp=932|log=1"
```

预期：客户端实时打印捕获到的文本，同时 `texthook_log.txt` 落盘一份。

`TestTextTarget` 用**硬编码的 SJIS 字节数组**输出文本，避免源码文件编码影响测试结果——
这样「抓到的文本是否正确」是可以确定性判断的。
