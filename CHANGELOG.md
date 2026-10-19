# Changelog

本项目所有重要变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增
- **文本 Hook 的 profile 现在能挂「框架不认识」的函数**：`HookTarget` 新增 `textArg` / `lenArg` / `argc` / `wide` / `conv`，ini 里用 `text=` / `len=` / `argc=` / `wide=` / `conv=` 声明「第几个参数是文本、第几个是长度、参数总数、窄/宽字符、调用约定」。此前「哪个参数是文本」写死在 `ReplacementFor()` 的「函数名 → 提取器」映射里，文件 profile 只能从框架已知的 6 个 GDI 函数里挑；现在任何导出函数都能挂
  - 实现方式是按「参数个数 × 调用约定」生成 8 × 2 = 16 种函数指针类型与 128 个转发 thunk（`GenDispatch` 按 `argc` 与 `conv` 选对应原型转发），仍然零第三方依赖
  - 为什么必须区分 `conv`：x86 `stdcall` 由被调方弹栈，用 `cdecl` 原型调用会弹歪栈、进程直接崩；`argc` 同理——它决定转发时压多少参数
  - 校验是「全有或全无」：`argc` 不在 1..8、`text`/`len` 超出 `argc`、值不是数字，整份文件都不生效并退回内置 profile
  - 这几个键可以写在段内任意位置，整段读完再统一填进该段的每个 `hook=`（否则「键写在 hook 后面」会静默失效）
- **IAT 槽改为按地址匹配**：挂钩时先用 `GetProcAddress` 解析真实地址，再遍历各模块导入表找**值等于该地址**的槽，不再按「模块名 + 函数名」比对。API Set 转发（`api-ms-win-*`）、名字修饰（`_TextOutA@20`）、大小写差异全部自动兼容——按名字比对时这些情况会整片匹配不到，表现为「profile 明明写对了却抓不到」。同时不再要求 `OriginalFirstThunk` 必须存在（少数加壳/重建过的映像只有 `FirstThunk`）
- **覆盖 `GetProcAddress` 动态取址**：引擎若用 `p = GetProcAddress(GetModuleHandleA("gdi32.dll"), "TextOutA")` 自己取地址再调用，导入表里根本没有这个函数，IAT Hook 抓不到。现在把所有模块 IAT 里的 `GetProcAddress` 换成替身：先问真实地址，若是我们挂钩的目标就返回替换函数
  - 仍然只改 IAT 槽、不碰任何指令字节，与既有机制完全同构（Inline Hook 需要长度反汇编器，与「零第三方依赖」的约定冲突）
  - 启动横幅新增一行「已登记 N 个目标，GetProcAddress 替换了 M 个槽」——「钩子挂上了却没文本」时，看这一行就能判断是不是动态取址
  - 仍有一个缺口并已如实记录：若引擎连 `GetProcAddress` 都自己从 kernel32 现取，这条也拦不住，那种情况只能上 Inline Hook（S2）
- **命名管道改为多实例（默认 4 个）**：每个实例一个 accept 线程、各自持有自己的连接，同一行文本**广播**给所有已连接的消费者。此前 `nMaxInstances=1`，第二个消费者连上来会被直接拒绝，而使用者看到的现象只是「客户端连不上」，没有任何提示
  - 某个实例的客户端断开只会让它自己重建，不影响其它消费者
  - `TestTextHook` 场景 5 新增两条断言：第二个消费者也能连上、第二个消费者收到同一行（验证是广播而不是独占）
- **`TextHookClient` 断线自动重连**：此前 `ReadFile` 失败就直接 `break` 退出进程，而断线在真实使用里是常态——游戏重新注入一次（`StopHooks` 会关掉全部实例）、游戏崩溃后重开、四个实例被别的客户端占满把自己挤掉，使用者看到的现象都只是「客户端自己关了」，游戏却还在跑。现在断开后重新 `ConnectPipe` 等待最多 60 秒并接着收，重连时丢弃可能读到的一半行（半行拼上下一次的开头会变成乱码）
  - 连接循环改用 `WaitNamedPipe` 处理 `ERROR_PIPE_BUSY`：四个实例全被占满时内核会在有空闲实例的瞬间唤醒，比固定 100ms 轮询更快也更省 CPU
- **C# 侧纯逻辑回归测试**：新增 `test/DllInjectorTests/`，覆盖那些「错了不会崩、但会静默给出错误结果」的逻辑——PE 位数识别、导出表 RVA 解析、DLL 路径分隔、`-method` 解析（含全部别名与未知值回退）、进程名通配（含正则元字符转义）、PE 体检
  - 刻意**不引入 NuGet 测试框架**（零第三方依赖的约定），用自带断言的控制台程序；把 `DllInjector/Program.cs` **原样链接进来**编译，而不是引用 `DllInjector.exe`——这样测试跑的就是发布出去的那份代码，也不会出现「测的是另一份拷贝」的假通过
  - 51 项断言，`test\DllInjectorTests\build.bat` 一条命令跑完，不需要 MSVC（只要 .NET 8 SDK）
  - 为此把 `ParseMethod` / `WildcardMatch` 从 `private` 改为 `internal`（同程序集内可见，不扩大公开 API）
- **`TestTextHook` 新增场景 7：通用转发器**：此前 `text=` / `len=` / `argc=` / `wide=` / `conv=` 这条路径**完全没有自动化覆盖**（`grep` 确认测试里从没出现过 `text=`），而它恰好是新代码里最危险的一段——按「参数个数 × 调用约定」生成 128 个 thunk，写错一个就弹歪栈，失败方式是**崩溃**而不是「抓不到文本」
  - 取巧之处：拿框架本来就认识的 `TextOutA` 来测，但 profile 里故意写 `text=4 / len=5 / argc=5 / wide=0 / conv=stdcall`，于是走的就是 `t->textArg > 0` 的通用分支，与「框架不认识的函数」完全同一条代码路径，不必编测试 DLL 就能验证真实参数布局
  - 断言「真的调一次 `TextOutA` 并抓到文本」——**能走到这条断言本身就是弹栈正确的证明**，光看启动横幅报「挂上了 N 个槽」没有意义
  - 上线后立刻在 x86 上炸出来，而 x64 全绿（见下方「修复」里的 `conv=` 那条）
  - 顺带给 `TestTextHook` 的 `main` 加了 `setvbuf(stdout, NULL, _IONBF, 0)`：这个测试会真的挂钩、真的调 API，一旦某场景把进程打崩，块缓冲会把崩溃前所有 `[PASS]`/`[FAIL]` 一起吞掉，只留一个空文件——排查时最要命的就是分不清「没跑到」和「跑完了但输出丢了」。**这次正是靠它才看到 x86 究竟断在哪一条断言之后**
- **`test/ManualMap/build_shellcode.bat --check`**：只比对不写入。重新汇编 `.asm`、提取字节，再和 `DllInjector/Program.cs` 里同名的 `byte[]` 逐字节比较，不一致时以非零码退出并打出 `NAME: obj=N bytes, Program.cs=M bytes`。CI 用它挡住「改了 `.asm` 却忘了重新生成」
- **CLI `-help` / `-version`**：打印完整用法 / 版本号后以 `0` 退出，不注入、不写日志。`-help` 接受 `-h` / `--help` / `/?`，`-version` 接受 `-v` / `--version`；版本号读程序集元数据（`AssemblyInformationalVersion`），不在源码里再写死一份

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
  - **能力边界已写入文件头与 ini 注释**（本轮已放开，见上方 `### 新增` 第一条）：当时文件只能从框架**已知的 6 个函数**里挑选组合挂钩目标，「哪个参数是文本」写死在 `ReplacementFor()` 里；现在补上 `text=` / `len=` / `argc=` / `wide=` / `conv=` 之后，框架不认识的导出函数也能挂
  - `HookTarget` 的 `module` / `func` 由 `const char*` 改为内联字符数组，使编译期常量表与运行期文件加载共用同一套结构，文件加载的 profile 无需堆分配，也就不存在 `g_profile` 指向已释放内存的风险
- **`TestTextHook` 进程内端到端验证**：新增 `test/TextHookDll/TestTextHook.c`。设计文档 §10 原有的验证链路需要三个进程手工配合（起客户端 → 注入器注入 → 目标程序输出文本），无法自动化；本程序把整条链路收进一个进程：自己 `LoadLibrary`、自己调 `InstallConfig` 装钩子、自己用 GDI 输出文本、自己读 `texthook_log.txt` 判断结果
  - 4 个场景：内置 profile；文件 profile（**只挂 `TextOutA`，因此 `TextOutW` 不该被抓到**——这是 S3 是否真正生效的关键断言）；故意写错的 profile 文件（应整份退回内置且仍能抓到文本）；随仓库分发的模板 ini
  - 第 5 个场景**命名管道**：作为客户端真的连上管道并真的读到文本（SJIS → UTF-8 内容正确）；`Unhook` 后管道实例必须已释放（用「自己按 `nMaxInstances=1` 建同名实例能否成功」判断，比猜线程数直接得多）；反复「无客户端安装 → 卸载」后管道名仍空闲、线程数回到本轮基线。前面 4 个场景只靠 `texthook_log.txt` 判断结果、全程没有客户端连管道，管道线程的生命周期一直没被验证过，这一条补上了这个空白
  - 线程数基线取在场景 5 内部而非进程启动时：GDI 首次使用（`GetDC`）会让系统懒加载一个线程、把进程线程数永久抬高 1，拿它当基线会误报成「泄漏」（这一点是被一次失败的自校准发现的，不是猜的）
  - 断言覆盖：无修饰导出名可取（x86 `.def` 的回归防线）、启动横幅内容、Shift-JIS → UTF-8 转换正确、profile 对挂钩集合的实际约束、**卸载后主 EXE 的 IAT 已完全还原**（逐槽检查有没有地址落在 DLL 映像范围内）
  - 期望值一律用 `\uXXXX` 转义写在宽字符串里，不含任何非 ASCII 字面量，因此「抓到的文本对不对」与源码文件编码无关
  - 支持只跑指定场景（第 3 个参数），用于在全新进程里把「跨场景污染」与「该场景自身的问题」区分开
  - `build.bat` 现在在编译完成后**自动跑两个架构的测试**，任一位数失败即 `VERIFY_FAIL` 并以非零码退出——「x86 和 x64 都要测试」从人工约定变成一条命令
  - **已验证**：x64 与 x86 均全部通过
- **CI 补上 C 代码与发布产物的验证**：此前 CI 只跑 `dotnet publish`，**从未编译过仓库里任何一行 C 代码**——`test/` 下的 6 个 `.bat` 构建脚本全靠人工执行，`.def` 缺失、漏链 `gdi32.lib`、漏 `/utf-8` 这类问题 CI 一律发现不了
  - 新增 `native` job：在 Windows runner 上跑 `test\build_test.bat` 与 `test\TextHookDll\build.bat`（后者自带双架构端到端验证），产物作为 artifact 上传
  - 新增「发布产物冒烟测试」步骤：用 `-checkdll <同位数探针 DLL>` 校验发布出来的 exe 真的能加载对应位数的 DLL，并以退出码判定成败（`-checkdll` 带参数，因此不会触发 UAC 重新拉起，也不会因为解析本地化输出而误判）
  - 构建矩阵改为 `include:` 形式，为每个 `rid` 配一个**同位数**的探针 DLL，避免出现「用 x64 探针验 x86 产物」这种假通过
  - `release` 改为 `needs: [build, native]`，发布说明改用 `${{ github.ref_name }}`（此前硬编码 `v1.0.0`，打任何 tag 都会生成错误的标题）

- **SeDebugPrivilege 自动提权**：注入 / 卸载前自动尝试启用调试权限，以管理员运行时即可打开并注入 SYSTEM 等高权限 / 其他会话进程；普通权限令牌下仅提示、不阻断普通进程注入
- **批量化注入**：GUI「批量注入」弹出进程多选对话框（按名称筛选），勾选多个进程一次性注入并汇总成功/失败结果；CLI 新增 `-injectname <进程名>`（支持 `*` `?` 通配）与 `-injectpid` 多 PID 逗号分隔批量注入；位数不符的进程自动跳过
- **注入前 PE 体检**：注入前自动对每个 DLL 做结构体检（有效 PE、位数、是否为 DLL、导出表、重定位段、可执行段），不合格直接拦截并给出原因；CLI 新增 `-checkdll <dll...>` 单独体检命令
- **多 DLL 拖拽排序**：DLL 输入框旁新增「⇅ 排序」按钮，弹出对话框支持**拖拽重排 / 上移 / 下移 / 删除**，确定后按新顺序回写，从而自由控制多 DLL 的注入顺序
- **导出函数传多个参数**：调用参数内用 `||` 分隔多个参数，注入器在目标进程打包 **NULL 结尾的字符串指针数组**（`LPVOID* args`），导出函数逐个访问（如示例 DLL 新增的 `InstallMulti`）；单参数行为保持不变，完全向后兼容
- 注入后调用 DLL 导出函数：注入成功后自动远程调用指定导出函数（如 `InstallHook` / `Init`），可传入一个 UTF-16 字符串参数；「启动时注入」与「注入到运行中进程」均支持
- 导出函数通过本地 PE 导出表解析（RVA）+ 目标进程模块基址计算真实地址，规避 64 位句柄截断；同步等待完成并记录函数返回码
- 图形界面新增「导出函数」「调用参数」输入框；命令行模式新增 `-export <函数>` 与 `-exportarg <参数>`
- 发布参数新增 `IncludeNativeLibrariesForSelfExtract`，避免运行时解压到临时目录（更稳健）

### 修复
- **`test/TextHookDll/TextHookDll.c` 的 `desc=` / `hook=` 解析用硬边界拷贝，超长会终止被注入的游戏进程**：`strcpy_s(fp->desc, MAX_DESC_LEN, val)` 与 `strcpy_s(v, sizeof(v), val)` 在超长时触发无效参数处理器，而这个 DLL 正是要挂进运行中的 GalGame。改为先判长度、超长则按「全有或全无」报错并整份退回内置 profile（与既有的 `wcscpy_s` → `wcsncpy_s(_TRUNCATE)` 修复同一类问题）
- **同一类问题的最后一处：列出 profile 名时的 `strcat_s`**：`BuildProfileList` 与「已加载 N 个」横幅把最多 32 个 profile 名（每个上限 47 字符）拼进 384 字节的缓冲区，用 `strcat_s` 一旦超界同样会调用无效参数处理器。改为新增的 `AppendCapped`（`strncat_s(..., _TRUNCATE)`），最坏情况只是提示里少列几个名字，绝不终止游戏进程
- **`conv=` 的取值判断写反了，x86 上写 `conv=stdcall` 会让游戏直接崩**：`conv` 的语义是 `0 = stdcall`、`1 = cdecl`（结构体零初始化即 stdcall），但解析时写的是 `(_stricmp(val, "stdcall") == 0) ? 1 : 0` —— 用户老老实实写 `conv=stdcall`，拿到的却是 cdecl 的 thunk。x86 上 stdcall 由被调方弹栈、cdecl 由调用方弹栈，差一个参数宽度的栈就会把返回地址弹歪，表现为「调用一次就访问违例」。x64 只有一个调用约定，所以这个错误在 x64 上完全看不出来（新增的场景 7 正是先在 x86 上炸出来才发现）。改为按 `cdecl` 置 1、`stdcall` 置 0，并对其它取值直接报错
- **IAT 槽写入撤掉执行权限会让目标进程在下次取指时崩掉**：挂接与还原原先把页改成 `PAGE_READWRITE`，但加壳器常把 `.rdata` 合并进可执行段、整页是 RX，改成 RW 会把执行位一并撤掉。改为 `PAGE_EXECUTE_READWRITE`（保留执行位，写完立刻还原 `oldProtect`，暴露窗口只有几条指令）
- **IAT 槽写入的可见性顺序**：普通赋值可能被编译器或 CPU 写缓冲推迟到「权限已还原」之后才落内存，于是页面先恢复 RX、槽还是旧值，这一小段时间的挂接等于没生效。改用 `InterlockedExchangePointer`（带完整屏障，保证「槽已更新」先于「权限已还原」可见）。挂接与还原两侧对称修改。刻意**不**挂起其它线程——从 DLL 内部挂起线程有与加载器锁 / 堆锁互锁的风险
- **`EjectDll` 在 `FreeLibrary` 返回 0 时仍报告成功**：`FreeLibrary` 返回 0 是**失败**（引用计数没减到 0，或传入的基址根本不是已加载模块），原实现只打日志、仍然 `return true`，GUI/CLI 会报告「卸载成功」而 DLL 其实还在目标进程里跑着。现在返回 false，并保留「模块仍在模块列表中」的第二道确认
- **`test/TextHookDll/build.bat` 的提示文本里混进了字面 `echo`**：`echo ... ^` 续行会把下一行的 `echo` 一起拼进输出（`...TextTarget_x64.exe echo            test_output\...`）。改为 3 条独立 `echo`；同时确认 `-exportarg` 示例里的 `|` 在双引号内不需要 caret 转义
- **窗口位置记忆在高 DPI 下被整份丢弃**：`RestoreWindowPos` 原先用 `MinimumSize` 做「太小就丢弃」的门槛，而 `ApplyDpiScale()` 已经把 `MinimumSize` 放大到 `Scale(620)/Scale(600)`，于是 96 DPI 下记住的 720×700 在 150% 缩放下被判过小、位置和大小一起丢掉。现在只丢弃明显无效的值（非正数、不在任何屏幕内），尺寸交给后面的工作区钳制步骤处理。顺带把构造函数里的 `(620,660)` 与 `LayoutAll` 里的 `(620,600)` 统一成常量 `MinWinW` / `MinWinH`——此前 660 从来没起过作用，只会误导后来改布局的人
- **注入失败时释放远程缓冲区是 use-after-free**：`LoadLibraryIntoProcess` 等远程线程超时 / 等待失败后返回 `false`，而调用方（`InjectorCore.Run` 与 `InjectToProcess`）原先无条件 `VirtualFreeEx(remoteBuf)`。超时意味着远程线程**可能仍在跑**，它马上要读的 DLL 路径就在这块内存里——释放后 `LoadLibraryW` 读到的是已解映射的页，轻则加载失败、重则目标进程被访问违例打死。现在 `LoadLibraryIntoProcess` 通过 `out bool bufBusy` 报告「线程状态未知」，调用方据此决定是否保留该缓冲区（保留时打印一行提示，交给目标进程退出时回收）
- **`CallExport` 超时后仍释放参数缓冲区**：同一个缺陷的第二处。`WaitForSingleObject` 返回非 0 时原实现只打一句「等待超时」就 `return false`，`finally` 里照样 `VirtualFreeEx(argBuf)`——而远程线程此刻正在读 `argBuf` 里的 `LPVOID` 数组。现在区分 `WAIT_TIMEOUT` 与 `WAIT_FAILED`（原先用 `!= 0` 把两者混为一谈），两种情况都置 `argBufBusy` 跳过释放
- **六个 `build.bat` 全部隐含依赖当前目录**：`cl` / `ml` 把 `.obj` 写在**当前目录**，而链接行按 `%SRC%` 找 `.obj`。于是从仓库根执行 `test\TestReflectiveDll\build.bat` 会报 `LNK1181: 无法打开输入文件 ...\ReflectiveLoader_x64.obj`。六个脚本里只有 `build_shellcode.bat` 有 `cd /d "%SRC%"`，现已全部补上（这也是仓库根会残留 `.obj` / `.exp` / `.lib` 的真正原因——`.gitignore` 的 `test/**` 规则盖不住根目录）
- **`test/TestHookDll/build.bat` 的提示文本混进字面 `echo`，且 `^|` 被原样打印**：`echo ... ^` 续行会把下一行的 `echo` 拼进输出；另外 cmd 在**双引号内不吃 caret**，`"server=1.2.3.4^|port=8080"` 会连 caret 一起打印。改为两条独立 `echo`、引号内直接写 `|`。同批修掉 `test/ManualMap/build_shellcode.bat` 与 `test/TextHookDll/build.bat` 里两行**中文注释**——项目约定 `.bat` 只用 ASCII（cmd 按控制台代码页读脚本，中文必乱码），这两行是历史遗留
- **`Log()` 每追加一行都重切整段文本（O(n²)）**：原实现每条日志都 `_log.Text.Split('\n')`，超过上限再 `string.Join` 重写整段。注入过程动辄数百条日志，界面在高频日志下明显卡顿。改为维护 `_logLines` 计数、只在超过 `LogMaxLines + LogTrimSlack`（1000 + 200）时裁剪一次，裁剪时一次砍掉 200 行而不是每行都砍
- **手动映射 / 反射注入的可执行内存一律 RWX**：shellcode 与反射镜像原先直接按 `PAGE_EXECUTE_READWRITE` 分配，等于全程留着一块可写可执行的内存（对安全软件是显眼特征，也放大了写坏代码的后果）。改为先 `PAGE_READWRITE` 写入、再 `VirtualProtectEx(PAGE_EXECUTE_READ)` + `FlushInstructionCache` 封成只读可执行（新增 `SealShellcodePage` 助手）。反射镜像的封页放在 loader 线程退出**之后**——loader 运行期间要写自己的全局变量

- **管道线程会卡死在 `ConnectNamedPipe` 里不退出，「卸载再重装」之后管道永久失效**：`StopHooks` 用 `g_stop` 这个**轮询**标志位通知线程退出，但管道线程平时正阻塞在 `ConnectNamedPipe` 上等客户端——轮询对它无效。1 秒有界等待超时后 `StopHooks` 只 `CloseHandle` 了**线程句柄**（关线程句柄不会终止线程），于是该线程与它持有的管道实例一起留了下来
  - 真实后果比"漏一个线程"严重得多：残留实例占着 `\\.\pipe\<name>`，而管道是 `nMaxInstances=1`，因此**下一次安装的 `CreateNamedPipeA` 必然失败**——表现为「卸载后再注入，DLL 装上了、`InstallConfig` 也返回成功，但管道再也传不出一个字节」；那个僵尸线程之后还会去 `EnterCriticalSection` 一个已经被 `DeleteCriticalSection` 删掉的临界区
  - 触发条件正是最常见的用法：注入后**没有**启动客户端，然后重新注入
  - 修法三处，互相独立：① 管道改用 `FILE_FLAG_OVERLAPPED` 打开，`ConnectNamedPipe` 挂起后用 `WaitForMultipleObjects(连接完成事件, g_stopEvent)` 等待，停止信号能立刻打断它（相应地 `WriteFile` 也必须走重叠方式——对重叠句柄传 `NULL lpOverlapped` 是未定义行为，MSDN 明确说会"错误地报告写完成"）；② 临界区与停止事件改为「建一次就不销毁」，且只有两个工作线程都确认退出后才关闭事件；③ 有界等待 1s → 2s，并显式区分「线程真的退出了」与「超时了」，超时则宁可泄漏几个句柄也不关闭线程仍可能引用的对象
  - **已验证**：新增 `TestTextHook` 场景 5（详见下方「新增」）。反向验证——把修复前的源码编成独立 DLL 再跑同一个测试——确认修复前 `FAIL`（2 项断言失败、线程数 4→5），修复后 x64 / x86 均 `PASS`
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
- 64 位进程卸载失败：远程线程退出码仅 32 位导致模块句柄截断，改为注入器侧枚举目标进程模块取得完整 64 位基址
- 「刷新」按钮点击时的空引用异常（对象未设置为对象实例）

### 变更
- **`.editorconfig` 与 `.gitattributes` 的行尾约定统一**：原 `[*] end_of_line = crlf` 与 `.gitattributes` 的 `*.cs/*.c/*.h/*.md text eol=lf` 冲突（编辑器按 crlf 保存、git 按 lf 检出，每次保存都产生纯换行 diff）。改为 `[*] end_of_line = lf`，并显式声明 `[*.{bat,cmd,ps1}] end_of_line = crlf`
- **`.gitattributes` 给 `.editorconfig` / `.gitignore` / `.yml` / `.ini` / `.html` / `.py` 补上 `eol=lf`**：这些文件原先落在 `* text=auto` 之下，在 `core.autocrlf=true` 的 Windows 克隆里会被检出成 CRLF——与 `.editorconfig` 自己声明的 `lf` 相矛盾，`git diff` 还会刷一串 `LF will be replaced by CRLF the next time Git touches it` 警告。现在两处声明一致，`git status` 干净
- **`.gitignore` 补上仓库根目录的 MSVC 中间文件**：`cl.exe` 把 `.obj` / `.exp` / `.lib` 写在**当前工作目录**（不是源码旁边），从仓库根跑一次编译就会在根目录留下六个文件，而原有规则是 `test/**/*.obj`，盖不住根目录。新增 `/*.obj` `/*.exp` `/*.lib` 等
- **`ConfigStore.Method` 注释漏了手动映射**：原注释写「0=CRT / 1=NTC / 2=APC / 3=RFI」，实际校验上限早已是 `INJECT_MM`。改为引用常量并说明「新增只能追加末尾」，同时把魔法数字换成 `NativeMethods.INJECT_*`
- **README 说清 `|` 的两种含义**：作为 DLL 分隔符时 `;` / `|` / 换行都行；而 `-exportarg` 里的 `|` 只是普通字符（`InstallConfig` 正用它分隔键值对）。此前两处都用 `|` 却没解释，容易误以为要转义
- **CI 覆盖全部构建脚本**：`native` job 新增 `test\TestHookDll\build.bat`（会真的调一遍导出函数，`__stdcall` 修饰名问题当场暴露）、`test\TestReflectiveDll\build.bat`、`test\ManualMap\build_shellcode.bat --check`（`git diff --exit-code` 断言字节数组与 `.asm` 同步）；`build` job 新增 `test\DllInjectorTests\build.bat`，放在 publish 之前跑
- **文档三处联动更新**：`README.md`、`docs/index.html`、`docs/text-hook-design.md` 同步新的能力边界（能挂未知函数、动态取址已覆盖、管道多实例）、测试场景数（5 → 6）、`-help`/`-version`、C# 测试入口

- **文档事实性修正**：`docs/index.html` 展示页「四种注入方式」改为「五种」（同页对比表实际有 5 行），CLI 特性补齐 `-injectname` / `-checkdll`；`CHANGELOG.md` 按 Keep a Changelog 约定把 `[Unreleased]` 移至文件顶部、统一版本标题格式；README 构建章节补充 `dist\` 产物与测试素材构建脚本说明
- **CI 发布启用单文件压缩**（`EnableCompressionInSingleFile`）：Release 体积从约 130MB 降至约 60MB，文件更小、下载更快
- **CI Release 改用固定说明文本**：移除 `generate_release_notes`，杜绝每次更新 Release 时重复追加「Full Changelog」
- **界面截图更新**：README 与 GitHub Pages 展示页同步更新为最新界面截图
- 展示页 CLI 示例修正：`-method` 补齐 `rfi`，移除重复出现的 `-eject` 行
- **构建参数对齐**：`.github/workflows/build.yml` 的 publish 命令补上 `IncludeNativeLibrariesForSelfExtract`，与 `build.bat` 以及文件内「本地与 CI 参数保持一致」的说明对齐（此前 CI 产物缺这一项，两处实际不一致）
- **移除仓库内重复截图**：`屏幕截图 2026-09-03 133127.png` 与 `screenshot.png` 内容完全相同（SHA256 均为 `d2a640eb…`），删除前者，只保留 `screenshot.png`
- **统一 `.bat` 行尾为 CRLF**：`.gitattributes` 声明了 `*.bat text eol=crlf`，但工作区里 `test\ManualMap\build_shellcode.bat`、`test\TestReflectiveDll\build.bat`、`test\build_test.bat` 以及新加的 `test\TextHookDll\build.bat` 都是 LF。因为 git 按 CRLF 检出，这次转换**不产生任何 diff**，只是让工作区与声明自洽，并保证不经 git 检出（例如直接下载 zip）时拿到的也是 CRLF

- 移除设置对话框与「设置」按钮：不再提供主题 / 注入超时 / 日志最大行数的手动调整
- 主题固定为暗色；注入等待超时固定 15 秒；日志最大行数固定 1000 行
- 修复设置对话框「日志最大行数」输入框在高 DPI 下数字显示不完整的问题（改用 TextBox 并移除手动 DPI 缩放；随设置功能移除一并消失）
- 注入到运行中进程：枚举当前进程列表（名称 + PID），选中后一键向正在运行的进程注入
- 卸载已注入 DLL：从运行中进程远程调用 FreeLibrary，形成「注入 / 卸载」闭环
- 命令行模式新增 `-injectpid <pid> <dll>` 与 `-eject <pid> <dll名>`
- 图形界面新增「刷新」按钮实时加载进程列表

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
