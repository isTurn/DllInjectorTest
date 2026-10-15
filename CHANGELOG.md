# Changelog

本项目所有重要变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增
- **GalGame 文本 Hook（一阶段原型）**：新增 `test/TextHookDll/`——profile 驱动的 IAT 文本 Hook DLL，挂钩 `TextOutA/W`、`ExtTextOutA/W`、`DrawTextA/W`，把捕获文本从 Shift-JIS / GBK 统一转成 UTF-8 后经命名管道推送给外部消费者；配套 `TextHookClient.c`（管道消费者）与 `test/TestTextTarget/`（用 GDI 输出硬编码日文/中文的确定性验证目标）。**通过既有的 `-export InstallConfig` / `-exportarg` 机制下发引擎配置，注入器零改动**
  - 编码转换、去重（游戏每帧重绘必须去重）、队列 + 独立写线程（避免客户端不读时卡死游戏线程）、管道断线自动重建
  - 架构设计与演进路线见新增的 `docs/text-hook-design.md`
  - 新增 `test/TextHookDll/TextHookDll.def`：统一 x86/x64 的导出名（详见下方「修复」）
  - **已实机验证（x64 + x86 双架构）**：六个挂钩槽全部安装成功，`TextOutA` / `ExtTextOutA` / `TextOutW` / `ExtTextOutW` / `DrawTextA` / `DrawTextW` 六个 API 各自正确捕获，Shift-JIS 与宽字符均正确转为 UTF-8，去重、队列、命名管道投递与落盘全部工作
  - 已明确的限制：只覆盖走 IAT 的调用；挂钩发生在游戏开跑之后（注入器的 `ResumeThread` 早于导出函数调用，会漏掉启动后约百毫秒文本）；DirectX 自绘引擎不覆盖；具体引擎 profile 需对着实机样本逆向填写
- **构建与协作基建补全**：新增 `build.bat` 一键构建脚本（x64 + x86，发布参数与 CI 完全一致，并额外产出与 Release 同名的 `dist\DllInjector-x64.exe` / `dist\DllInjector-x86.exe`）、`.gitignore`、`SECURITY.md`（合法使用边界 / 杀软告警说明 / 私密漏洞上报通道）、`CONTRIBUTING.md`（构建方式、目录职责、代码约定、新增注入方式的步骤）以及 GitHub Issue / PR 模板——此前 README 已引用这些文件但仓库中并不存在（`SECURITY.md` 为死链）
- **`test/ManualMap/build_shellcode.bat`**：补齐手动映射 shellcode 的「汇编 → 提取字节」一键流程（`ml64` / `ml` + `gen_shellcode.py`），此前只有提取脚本、汇编需手工执行
- **`test/TestReflectiveDll/build.bat` 补齐 `TestLoader` 构建**：此前该目录只产出两个反射 DLL，而用于「进程内验证反射加载器」的 `TestLoader.c` 没有任何构建入口（两个 DLL 有产物、却无法验证）；现在一并编译出 `TestLoader-x64.exe` / `TestLoader-x86.exe`，构建结束打印验证命令
- **反射式注入（Reflective）**：新增第四种注入方式，针对自带 `ReflectiveLoader` 导出的**反射 DLL**，注入器只负责在目标进程内**按内存布局展开** DLL 映像（头部 + 各节按 VirtualAddress 复制）并创建远程线程启动 Loader，PE 映射 / 重定位 / 填 IAT / 调 DllMain 全由 DLL 自行完成，磁盘无落盘、绕开 LoadLibrary 链路，隐蔽性最强
  - x86 反射 DLL 采用绝对寻址 → 注入器优先把镜像分配在目标进程的**映像基址**（通常 `0x10000000`），被占用时明确报错；x64 走 RIP 相对寻址，映像基址占用时自动回退任意地址
  - GUI「注入方式」下拉框新增第 4 项「反射式注入（Reflective）」；CLI `-method` 新增 `rfi|reflect|reflective`
  - 新增测试示例 `test/TestReflectiveDll/`：自包含反射加载器（x64/x86 汇编入口 + C 核心），已编译 x64/x86 反射 DLL，加载成功后写 `C:\Windows\Temp\rfi_call_log.txt` 验证
- **自包含发布**：发布改为 `--self-contained true` 单文件，x86 版不再依赖系统安装 .NET 8.0 x86 运行时，任何电脑双击即用（体积增大属正常）
- **`test/TestHookDll/` 补齐构建入口并统一导出名**：此前该目录只有源码与已编译 DLL，没有任何构建脚本，且 x86 DLL 的导出名带 `__stdcall` 修饰。新增 `TestHookDll.def`（统一导出无修饰名）与 `build.bat`（`vswhere` 定位任意版本 VS、双架构编译、`/utf-8`、`/DEF`、结束后清理中间文件并打印验证命令），并重新编译提交 x64 / x86 两个 DLL
  - **已验证**：`dumpbin -exports` 两个架构都输出 `Init` / `InstallHook` / `InstallConfig` / `InstallMulti`；不带 `.def` 的对照组在 x86 上输出的是 `_Init@4` / `_InstallConfig@4` …，证实修复有效
  - **已验证（功能级，不只是看导出表）**：进程内加载后按**无修饰名** `GetProcAddress` 四个导出全部命中，实际调用返回码正确（`Init`→42、`InstallHook`→1、`InstallConfig`→3 组键值对、`InstallMulti`→3 个参数），并正确写出 `hook_call_log.txt`（含 `张三` 等宽字符参数）。x64 与 x86 均通过
- **引擎适配表外部化（S3）**：`TextHookDll` 的 profile 从编译期常量搬到运行期文件，改引擎适配不再需要重编译、重新分发 DLL
  - 新增 `test/TextHookDll/TextHookDll.profiles.ini` 模板（随 DLL 一起分发到 `test_output\`），DLL 从**自身所在目录**自动加载；也可用 `profilefile=<路径>` 指定别处、用 `nofile=1` 完全禁用
  - 段落内支持 `codepage` / `minlen` / `dedup` / `desc` 与多行 `hook=<模块>,<函数>[,<方式>]`；文件里的 profile 可**同名覆盖**内置的 4 个，因此写一个 `[generic-gdi]` 就能改掉「不传 `engine=` 时」的兜底行为
  - 解析策略为**全有或全无**：任何一行出错就整份文件不生效、退回内置 profile，并在启动横幅里说明原因。半个 profile 生效比完全没生效更难排查
  - 未实现的挂钩方式（`inline` / `vtable`，属 S2 / S5）在文件里**明确报错**而不是静默忽略——静默接受会让使用者以为挂钩装上了；`engine=` 写错时告警里直接列出全部可用 profile 名
  - 启动横幅新增一行报告 profile 文件路径与加载结果（读了哪个文件、加载了几个、叫什么），这是使用者最常问的问题
  - **能力边界已写入文件头与 ini 注释**：文件只能从框架**已知的 6 个函数**里挑选组合挂钩目标；「哪个参数是文本」是编译期写死在 `ReplacementFor()` 里的，所以「写个文件就能适配任意引擎」暂时做不到，新增未知函数属于 S2 / S4
  - `HookTarget` 的 `module` / `func` 由 `const char*` 改为内联字符数组，使编译期常量表与运行期文件加载共用同一套结构，文件加载的 profile 无需堆分配，也就不存在 `g_profile` 指向已释放内存的风险
- **`TestTextHook` 进程内端到端验证**：新增 `test/TextHookDll/TestTextHook.c`。设计文档 §10 原有的验证链路需要三个进程手工配合（起客户端 → 注入器注入 → 目标程序输出文本），无法自动化；本程序把整条链路收进一个进程：自己 `LoadLibrary`、自己调 `InstallConfig` 装钩子、自己用 GDI 输出文本、自己读 `texthook_log.txt` 判断结果
  - 4 个场景：内置 profile；文件 profile（**只挂 `TextOutA`，因此 `TextOutW` 不该被抓到**——这是 S3 是否真正生效的关键断言）；故意写错的 profile 文件（应整份退回内置且仍能抓到文本）；随仓库分发的模板 ini
  - 断言覆盖：无修饰导出名可取（x86 `.def` 的回归防线）、启动横幅内容、Shift-JIS → UTF-8 转换正确、profile 对挂钩集合的实际约束、**卸载后主 EXE 的 IAT 已完全还原**（逐槽检查有没有地址落在 DLL 映像范围内）
  - 期望值一律用 `\uXXXX` 转义写在宽字符串里，不含任何非 ASCII 字面量，因此「抓到的文本对不对」与源码文件编码无关
  - 支持只跑指定场景（第 3 个参数），用于在全新进程里把「跨场景污染」与「该场景自身的问题」区分开
  - `build.bat` 现在在编译完成后**自动跑两个架构的测试**，任一位数失败即 `VERIFY_FAIL` 并以非零码退出——「x86 和 x64 都要测试」从人工约定变成一条命令
  - **已验证**：x64 与 x86 均全部通过

### 修复
- **`Unhook` 从未真正卸载主 EXE 的 IAT，DLL 被卸载后游戏会跳进已释放内存**：`HookAllModules` 先显式挂钩主 EXE，随后又遍历模块快照——而快照**本身就包含主 EXE**，于是同一个 IAT 槽被挂了两次、在 `g_patched` 里记了两条。第二条把 `original` 记成了**我们自己的替换函数**，而 `UnhookAll` 顺序还原：第一条写回真实地址、第二条又把它写回替换函数，**最终槽仍指向 DLL 内部**
  - 真实后果：游戏 EXE 的 IAT 一直指向 `TextHookDll` 里的 `Hook_TextOutA`，DLL 一旦被卸载（或手动映射后被 `VirtualFree`）就是跳进已释放内存
  - 修复分两层，且**各自单独都足够**（已用三个变体构建交叉验证）：① 预防——`PatchModuleIat` 增加幂等检查（槽已指向替换函数则直接返回），并让 `HookAllModules` 在快照循环里跳过主 EXE；② 兜底——`UnhookAll` 改为**倒序**还原，万一同一个槽仍被记了多条，最后写回的也是最早记下的真实地址
  - **已验证**：`TestTextHook` 逐槽检查主 EXE 的 6 个 IAT 槽是否还落在 DLL 映像范围内。修复前的构建精确复现了症状（6 个槽全部泄漏、5 项断言失败、退出码 2），修复后 x64 / x86 均为 0 泄漏
- **`StopHooks` 之后重新安装会得到一个哑巴 DLL**：`StopHooks` 把 `g_stop` 置 1 让读写线程退出，但 `StartHooks` **从未把它清回 0**。于是「`Unhook` 之后再 `InstallConfig`」建出来的两个线程会立刻退出——DLL 看起来装好了、`InstallConfig` 也返回成功，实际一个字节都发不出去。现在 `StartHooks` 在创建线程前复位 `g_stop` 与 `g_pipeBroken`（并顺带复位 `g_patchedCount`）
- **`TestTextHook` 里的 `Unhook 返回成功` 是句废话**：`Unhook` 恒返回 1，该断言证明不了任何事——上面那个 IAT 泄漏 bug 正是在它「通过」的情况下发生的。已改为逐槽检查主 EXE 的 IAT 是否真的还原
- **编译中文注释的 C 源码时缺少 `/utf-8`，在中文 Windows 上构建直接失败**：`TextHookDll.c`、`TestTextTarget.c`、`TextHookClient.c`、`TestHookDll.c` 都含 UTF-8 中文注释，而 MSVC 默认按**系统代码页**（中文 Windows 为 936/GBK）解析源码。注释末尾的字节若构成 GBK 前导字节，会**吞掉行尾换行**，把下一行代码并进注释——表现为 `warning C4819` 加一堆莫名其妙的「未声明的标识符」，例如 `TestTextTarget.c` 报 11 个错误、`TextHookDll.c` 报数十个。已给全部 `cl` 命令行补 `/utf-8`（`test/build_test.bat`、`test/TestReflectiveDll/build.bat` 也一并补上，避免后续加中文注释时重蹈覆辙），并同步修正各源文件头部的手工编译说明
- **`TestTextTarget.c` 未链接 `gdi32.lib` / `user32.lib`，链接必然失败**：该文件直接调用 `TextOutA/W`、`ExtTextOutA/W`、`DrawTextA/W`、`GetDC` 等 GDI/user32 API，却没有 `#pragma comment(lib, ...)`，而 `build.bat` 的链接行也没有指定这两个库，导致 13 个 `__imp_*` 符号无法解析（`error LNK2019`）。已在两条链接命令补上 `gdi32.lib user32.lib`
- **`TextHookClient.c` 解析管道协议时漏了截断第三个字段，导致文本被打印两遍**：`PrintLine` 用 `*f1 = 0` / `*f2 = 0` 截断 pid 与 hook，却忘了 `*f3 = 0`，于是 `hook` 字段一路吞到行尾，把 hook 名和文本连成一片。实际表现为输出成 `[pid] TextOutA<TAB>こんにちは こんにちは`（hook 列里带着 TAB 和文本，文本重复），且因 hook 串超长导致 `%-14s` 不再补位。已补上截断
- **x86 版 DLL 的导出名被 `__stdcall` 修饰，`GetProcAddress` 按文档名取不到**：`WINAPI`(= `__stdcall`) 在 x86 下会把导出名修饰成 `_InstallConfig@4`，而 x64 只有一种调用约定、不修饰。于是同一个源文件编出的两个 DLL 导出名不一致，用 `GetProcAddress(h, "InstallConfig")` 在 x86 上拿到 `NULL`（注入器自身因 `PeHelper.GetExportRva` 会匹配 `_名称@数字` 而不受影响，但这是文档与实现之间的陷阱）。已新增 `test/TextHookDll/TextHookDll.def` 统一导出**无修饰**名字，x86/x64 导出表现已完全一致。`test/TestHookDll/TestHookDll-x86.dll` 存在同样问题，已一并修复（见下方「`TestHookDll` 补 `.def` 并重新编译」）
- **`TestTextTarget.c` 的验证预期自相矛盾**：它在**同一个进程**里既输出 Shift-JIS 文本（`TextOutA` / `DrawTextA`）又输出 GBK 文本（`ExtTextOutA`），而 TextHookDll 的 `cp=` 是**进程级**设置，一个进程只能有一种 `*A` 编码——两者必有一个被错误解码。已改为按命令行参数选择编码（默认 `sjis` 配 `cp=932`，传 `gbk` 配 `cp=936`），并把「用错编码必然乱码，这是设计使然」写进注释与 `build.bat` 的验证说明
- **`TextHookDll.c` 配置解析中的 `wcscpy_s` 硬边界会拖垮游戏进程**：`ApplyConfig` 用 `wcscpy_s(copy, 2048, cfg)` / `wcscpy_s(key, 128, ...)` / `wcscpy_s(val, 1024, ...)` 拷贝配置字符串，一旦 `-exportarg` 或某个 value 超过缓冲区长度，`wcscpy_s` 会调用无效参数处理器**直接终止被注入的进程**——而这个 DLL 正是要挂进运行中的 GalGame。三处统一改为 `wcsncpy_s(..., _TRUNCATE)`：超长输入截断处理，绝不崩溃
- **`dotnet restore` / 构建在缺少 `APPDATA`、`ProgramFiles` 环境变量的机器上必然失败**：报错为
  `NuGet.targets(745,5): error : Value cannot be null. (Parameter 'path1')`，信息完全不指向真实原因。经逐层定位，异常来自 NuGet 的**静态**构造函数——`XPlatMachineWideSetting..ctor()` → `NuGetEnvironment.GetFolderPath()` → `Path.Combine(null, ...)`，它在项目被读取之前就执行，因此**无法通过项目文件、`NuGet.Config` 或 MSBuild 属性绕过**（最小空工程同样失败，且已排除沙箱因素）
  - 真实原因：NuGet 6.x 的 `NuGetEnvironment` 用**环境变量**（而非 Win32 API）推导配置目录——`MachineWideSettingsBaseDirectory` 取 `ProgramFiles`、`UserSettingsDirectory` 取 `APPDATA`。在精简 / 加固 / 沙箱化的 shell 中这些变量可能整体缺失，`Environment.GetEnvironmentVariable` 返回 `null` 即触发
  - 逐变量二分验证：只补 `APPDATA` → `UserSettingsDirectory` 恢复；只补 `ProgramFiles` → `MachineWideSettingsBaseDirectory` 恢复；两者齐备后 `dotnet restore` 立即成功
  - 已让 `build.bat` 在启动时**防御性补回**缺失的 `APPDATA` / `ProgramFiles` / `ProgramW6432` / `ALLUSERSPROFILE`
  - **已验证**：`build.bat` 的两条 publish 命令（x64 + x86）均成功产出 `out\x64` / `out\x86`，复制出的 `dist\DllInjector-x64.exe` / `dist\DllInjector-x86.exe` 经 `dumpbin -headers` 确认位数分别为 x64 / x86；两个位数版本执行 `-checkdll` 均正确报告目标 DLL 的结构与**导出数量 4**
- **手动映射基址记录只增不减，PID 被复用时会去卸载无关进程**：`DllInjector.mmmap` 以 `pid|dll路径` 为键记住手动映射 DLL 的基址，供「卸载 DLL」跨进程使用。原实现 `LoadMmMap()` 启动时**全量载入、从不校验、从不清理**，而 `EjectDll` 在目标进程模块列表里找不到模块时（这正是手动映射的典型特征）会**直接按该基址执行卸载 shellcode**——`DllMain(DLL_PROCESS_DETACH)` + `VirtualFree`。一旦 PID 被复用，就会在一个**无关进程**里执行这套操作并破坏它
  - 现在记录中额外保存**目标进程的启动时间**（值格式 `基址十六进制|启动时间十六进制`，兼容只有基址的旧格式），并在两处校验：`LoadMmMap()` 启动时剔除失效记录并把清理结果写回文件；`EjectDll` 命中记录后、执行卸载前**再校验一次**（进程已退出或 PID 已被复用则拒绝，并顺手清掉该记录）
  - 启动时间读不到（旧格式记录、无权限）时**保守保留**，只做「进程是否存在」这一层判断，避免误删仍然有效的记录
  - **已验证**：构造 8 条记录（死 PID、PID 复用、旧格式+存活、旧格式+死 PID、key 格式错误、pid≤0、基址为 0、完全有效）跑 `-checkdll` 触发 `LoadMmMap()`，结果**只保留 2 条应有的记录**（有效的 + 旧格式但进程存活的），其余全部清理
- **测试素材中残留的硬编码绝对路径 `D:\Download\ToDLL\...` 已全部清除**：`test/TestTarget/TestTarget.c`（标记目录 `MARKER_DIR`）、`test/TestDll/TestDll.c`（同一 `MARKER_DIR`）、`test/TestReflectiveDll/TestLoader.c`（默认反射 DLL 路径）三处均改为运行时按自身模块位置推导，并在写入失败时打印警告而非静默失败。原缺陷的后果是：仓库一旦换目录，测试目标会静默写不出 `args_<pid>.txt` / `attach<A|B>_<pid>.txt`，导致「启动参数透传」「DllMain 是否在目标进程执行」这些功能看起来正常、实际根本没验证到
  - `TestDll.c` 的目录推导采用三级回退：**DLL 自身路径 → 宿主 EXE 路径 → `%TEMP%`**。中间一级是必需的：手动映射注入不会把映像注册进 PEB 模块列表，`GetModuleFileNameA(hModule)` 在该方式下会失败，而测试目标 EXE 与测试 DLL 同处 `test_output\`，回退后标记文件仍落在预期位置
  - 仍保留编译期 `MARKER_DIR` 覆盖能力（`/DMARKER_DIR=...`），只是不再有绝对路径的默认值
- **`test/build_test.bat` 与 `test/TestReflectiveDll/build.bat` 硬编码了过期绝对路径**（`D:\Download\ToDLL\...`）与 Visual Studio Community 的固定安装位置，仓库换到别的目录、或使用 Professional / Enterprise / Build Tools 时构建直接失败；改为按脚本自身位置（`%~dp0`）推导路径，并用 `vswhere.exe` 自动定位任意版本的 Visual Studio
- 窗口位置记忆可能导致窗口被恢复成超出屏幕的异常尺寸（如误记超大窗口），底部内容被截断且无法访问；现在恢复窗口位置时会自动限制在屏幕工作区内，保证窗口完整可见
- 64 位进程卸载失败：远程线程退出码仅 32 位导致模块句柄截断，改为注入器侧枚举目标进程模块取得完整 64 位基址
- 「刷新」按钮点击时的空引用异常（对象未设置为对象实例）
- **「注入并启动」部分 DLL 注入失败时 `allOk` 未置位**：导致日志永远显示「注入流程完成」、CLI 退出码误报成功（0），即使实际有 DLL 注入失败
- **记忆注入方式上限未含反射式**：`ConfigStore.Method` 校验 `m <= 2`，反射式（方式 3）无法被记忆，重启后丢失
- **CLI `-eject` 的 PID 未校验**：传入非数字时直接抛异常，改为 `int.TryParse` 并给出清晰错误
- **`NtCreateThreadEx` 失败时可能残留无效句柄**被调用方 `CloseHandle`，失败时显式置零
- 日志行数截断时每行残留回车符（`\r`），现在先归一 `\r\n` 再截断，日志更干净
- 增强：`-injectname` 进程名匹配支持 `.exe` 后缀（输入 `notepad` 或 `notepad.exe` 均可匹配）

### 变更
- **文档事实性修正**：`docs/index.html` 展示页「四种注入方式」改为「五种」（同页对比表实际有 5 行），CLI 特性补齐 `-injectname` / `-checkdll`；`CHANGELOG.md` 按 Keep a Changelog 约定把 `[Unreleased]` 移至文件顶部、统一版本标题格式；README 构建章节补充 `dist\` 产物与测试素材构建脚本说明
- **CI 发布启用单文件压缩**（`EnableCompressionInSingleFile`）：Release 体积从约 130MB 降至约 60MB，文件更小、下载更快
- **CI Release 改用固定说明文本**：移除 `generate_release_notes`，杜绝每次更新 Release 时重复追加「Full Changelog」
- **界面截图更新**：README 与 GitHub Pages 展示页同步更新为最新界面截图
- 展示页 CLI 示例修正：`-method` 补齐 `rfi`，移除重复出现的 `-eject` 行
- **构建参数对齐**：`.github/workflows/build.yml` 的 publish 命令补上 `IncludeNativeLibrariesForSelfExtract`，与 `build.bat` 以及文件内「本地与 CI 参数保持一致」的说明对齐（此前 CI 产物缺这一项，两处实际不一致）
- **移除仓库内重复截图**：`屏幕截图 2026-09-03 133127.png` 与 `screenshot.png` 内容完全相同（SHA256 均为 `d2a640eb…`），删除前者，只保留 `screenshot.png`
- **统一 `.bat` 行尾为 CRLF**：`.gitattributes` 声明了 `*.bat text eol=crlf`，但工作区里 `test\ManualMap\build_shellcode.bat`、`test\TestReflectiveDll\build.bat`、`test\build_test.bat` 以及新加的 `test\TextHookDll\build.bat` 都是 LF。因为 git 按 CRLF 检出，这次转换**不产生任何 diff**，只是让工作区与声明自洽，并保证不经 git 检出（例如直接下载 zip）时拿到的也是 CRLF

### 新增
- **SeDebugPrivilege 自动提权**：注入 / 卸载前自动尝试启用调试权限，以管理员运行时即可打开并注入 SYSTEM 等高权限 / 其他会话进程；普通权限令牌下仅提示、不阻断普通进程注入
- **批量化注入**：GUI「批量注入」弹出进程多选对话框（按名称筛选），勾选多个进程一次性注入并汇总成功/失败结果；CLI 新增 `-injectname <进程名>`（支持 `*` `?` 通配）与 `-injectpid` 多 PID 逗号分隔批量注入；位数不符的进程自动跳过
- **注入前 PE 体检**：注入前自动对每个 DLL 做结构体检（有效 PE、位数、是否为 DLL、导出表、重定位段、可执行段），不合格直接拦截并给出原因；CLI 新增 `-checkdll <dll...>` 单独体检命令
- **多 DLL 拖拽排序**：DLL 输入框旁新增「⇅ 排序」按钮，弹出对话框支持**拖拽重排 / 上移 / 下移 / 删除**，确定后按新顺序回写，从而自由控制多 DLL 的注入顺序
- **导出函数传多个参数**：调用参数内用 `||` 分隔多个参数，注入器在目标进程打包 **NULL 结尾的字符串指针数组**（`LPVOID* args`），导出函数逐个访问（如示例 DLL 新增的 `InstallMulti`）；单参数行为保持不变，完全向后兼容
- 注入后调用 DLL 导出函数：注入成功后自动远程调用指定导出函数（如 `InstallHook` / `Init`），可传入一个 UTF-16 字符串参数；「启动时注入」与「注入到运行中进程」均支持
- 导出函数通过本地 PE 导出表解析（RVA）+ 目标进程模块基址计算真实地址，规避 64 位句柄截断；同步等待完成并记录函数返回码
- 图形界面新增「导出函数」「调用参数」输入框；命令行模式新增 `-export <函数>` 与 `-exportarg <参数>`
- 发布参数新增 `IncludeNativeLibrariesForSelfExtract`，避免运行时解压到临时目录（更稳健）

### 变更
- 移除设置对话框与「设置」按钮：不再提供主题 / 注入超时 / 日志最大行数的手动调整
- 主题固定为暗色；注入等待超时固定 15 秒；日志最大行数固定 1000 行
- 修复设置对话框「日志最大行数」输入框在高 DPI 下数字显示不完整的问题（改用 TextBox 并移除手动 DPI 缩放；随设置功能移除一并消失）
- 注入到运行中进程：枚举当前进程列表（名称 + PID），选中后一键向正在运行的进程注入
- 卸载已注入 DLL：从运行中进程远程调用 FreeLibrary，形成「注入 / 卸载」闭环
- 命令行模式新增 `-injectpid <pid> <dll>` 与 `-eject <pid> <dll名>`
- 图形界面新增「刷新」按钮实时加载进程列表

### 修复
- 64 位进程卸载失败：远程线程退出码仅 32 位导致模块句柄截断，改为注入器侧枚举目标进程模块取得完整 64 位基址
- 「刷新」按钮点击时的空引用异常（对象未设置为对象实例）

## [1.0.0] - 2026-09-07

### 新增：第 5 种注入方式——手动映射注入（Manual Map）

- 新增注入方式 `mm`（GUI「注入方式」下拉框 + CLI `-method mm`）：不调用 `LoadLibrary`，
  由注入器内置的 shellcode 在目标进程内完成全部 PE 映射（校验 PE → PEB 定位 kernel32 →
  解析导出表 → VirtualAlloc 镜像 → 拷节 + BSS 补零 → 重定位 → 填 IAT → 调用 DllMain）。
- **普通 LoadLibrary 型 DLL 即可注入**，能绕开基于 LoadLibrary 挂钩的检测（EDR / 杀软常监控 LoadLibrary）。
- shellcode 为纯汇编手写：x64 1202 字节 / x86 956 字节，源码在 `test/ManualMap/`；
  64 位下模块基址经结果区完整回传（线程退出码只有 32 位，会截断）。
- 导出函数调用在手动映射模式下改用 shellcode 返回的完整模块基址 + 导出 RVA 直接计算地址
  （该模块不在目标进程模块列表，属正常）；x86 stdcall 导出名自动兼容 `_函数名@N` 装饰名。
- 实机验证：x64 / x86 双架构注入普通进程，`Init` 返回 42、`InstallHook` 返回 1。

### 新增：手动映射注入（MM）的卸载

- 「卸载 DLL」对手动映射注入的模块生效：MM DLL 不在目标进程模块列表（`FreeLibrary` 无效），
  卸载时改为在目标进程内执行**卸载 shellcode**——调用 `DllMain(DLL_PROCESS_DETACH)` 后按镜像整体 `VirtualFree` 释放。
- 卸载 shellcode 为纯汇编手写：x64 520 字节 / x86 451 字节（源码 `test/ManualMap/UnmapDll_*.asm`），
  复用已验证的 PEB → kernel32 → 导出表解析模式；入口参数仅为模块基址。
- **基址跨进程持久化**：手动映射注入成功后把 `PID | DLL 路径 → 模块基址` 写入同目录 `DllInjector.mmmap`，
  注入器进程重启后仍能按文件卸载（CLI 注入与卸载分属两次进程也可正常工作）；卸载成功后自动清理记录。
- 修复：x86 手动映射注入调用 `DllMain` 时 `hinst` 参数偏移错误（多 4 字节读到 delta 槽），
  修正为直接取映射基址——不影响 Init/InstallHook 返回值，但会让使用 `hinst` 定位自身路径的 DLL 行为异常。
- 实机验证：x64 / x86 双架构注入 32/64 位 `cmd.exe` 后卸载，shellcode 返回 1，
  `ReadProcessMemory` 读取原模块基址返回 `ERROR_PARTIAL_COPY`（内存已释放）。

## [P2] - 2026-09-03

### 新增
- 暗色 / 亮色主题：一键切换暗色主题，长时间使用不刺眼（设置对话框或配置文件均可调整）
- 设置对话框：集中调整主题、注入等待超时（3–120 秒）、日志最大行数（50–10000 行），即时生效并记忆
- 窗口位置记忆：自动记住上次窗口大小与位置，下次启动原位恢复
- 程序图标：内置自定义注射器图标（`app.ico` 嵌入可执行文件）

### 变更
- 配置文件升级为键值对格式（`key=value`），同时兼容旧版两行格式自动迁移
- 界面日志增加行数上限，按设置裁剪，避免长期运行内存占用过大

## [P1] - 2026-09-03

### 新增
- 多 DLL 批量注入：DLL 输入框用 `;` 分隔，可一次注入多个 DLL（GUI / CLI / 注入到进程均支持）
- 启动参数透传：启动目标程序时可附加命令行参数（GUI「启动参数」输入框 / CLI `-args`）
- 自动请求管理员权限（UAC）：图形界面非管理员启动时自动弹 UAC 提权，取消则按普通权限继续
- 注入方式可选：CreateRemoteThread / NtCreateThreadEx / QueueUserAPC（GUI 下拉框 / CLI `-method crt|ntc|apc`）
- 注入结果核验：注入后自动在目标进程模块列表核对 DLL 是否真正加载成功（带重试容忍枚举时序）
- 测试素材增强：TestDll 支持前缀宏区分多 DLL 变体（TestDllA/B），TestTarget 支持命令行参数回显与可告警等待
- 新增 `test/build_test.bat`：一键用 MSVC 编译测试素材

### 修复
- QueueUserAPC 注入崩溃：APC 为异步执行，LoadLibraryW 在目标主线程可告警后才运行；此前路径内存过早释放导致目标进程访问无效内存崩溃，改为 APC 方式保留路径内存（随进程退出回收）
- 记忆功能对多 DLL 失效：加载上次选择时对整串分号路径做 File.Exists 必然失败，改为按分号逐段校验，多 DLL 可完整带出

## [1.0.0] - 2026-09-01

### 新增
- 图形界面（WinForms）：选择目标 exe 与 dll，一键「注入并启动」
- 记忆上次选择：自动记住最近一次注入的 exe/dll，下次启动自动带出
- 命令行模式：`DllInjector.exe -inject <exe> <dll>`，退出码 `0`/`1`
- 位数自动校验：x64 / x86 不匹配时拦截并提示
- 支持中文路径：DLL 路径以 UTF-16 写入远程进程
- 完整日志：界面日志 + 同目录 `inject_log.txt`
- 自包含单文件发布，无需安装 .NET 运行时

### 修复
- 高 DPI（如 150% 缩放）下界面文字截断，改为手动 DPI 缩放自适应
- 文件选择对话框默认定位到注入器 EXE 所在目录

### 其他
- 注入原理：`CreateProcess(CREATE_SUSPENDED)` + 远程内存写入 + `CreateRemoteThread(LoadLibraryW)` + `ResumeThread`
