# DLL 注入器 (DLL Injector)

[![Release](https://img.shields.io/github/v/release/isTurn/DllInjectorTest?style=flat-square&logo=github)](https://github.com/isTurn/DllInjectorTest/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/isTurn/DllInjectorTest/build.yml?style=flat-square&logo=githubactions&logoColor=white&label=build)](https://github.com/isTurn/DllInjectorTest/actions)
[![License](https://img.shields.io/github/license/isTurn/DllInjectorTest?style=flat-square)](LICENSE)
[![Language](https://img.shields.io/github/languages/top/isTurn/DllInjectorTest?style=flat-square)](https://github.com/isTurn/DllInjectorTest)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20x86-0078D6?style=flat-square&logo=windows)]()

一个带图形界面的 Windows 工具：选择目标 exe 和要注入的 dll，点击「注入并启动」，工具会以**挂起方式启动目标程序 → 批量注入 DLL → 恢复运行**；也可以**向运行中的进程直接注入**，或**卸载已注入的 DLL**。支持 **x64 / x86** 双架构、**多 DLL 批量注入**、**启动参数透传**、**三种注入方式**、**注入后调用 DLL 导出函数**与**注入结果自动核验**。

## 界面预览

![DLL Injector 界面](screenshot.png?v=2)

## 功能特性

- **图形界面**：直观的 WinForms 界面，支持直接把文件拖进输入框（多文件可一次拖入）
- **启动时注入**：以挂起方式启动目标程序 → 批量注入 DLL → 恢复运行
- **多 DLL 批量注入**：DLL 输入框内用 `;` 分隔多个 DLL，一次性全部注入（GUI / CLI 均支持）；GUI 提供「⇅ 排序」对话框（支持拖拽重排 / 上移 / 下移 / 删除），可自由调整多 DLL 的注入顺序
- **启动参数透传**：启动目标程序时可附加命令行参数（GUI「启动参数」输入框 / CLI `-args`）
- **注入后调用 DLL 导出函数**：注入成功后自动远程调用指定导出函数（如 `InstallHook` / `Init`），可传入一个字符串参数，**也支持多参数**（调用参数内用 `||` 分隔，DLL 侧以字符串指针数组接收）；「启动时注入」与「注入到运行中进程」均支持（GUI「导出函数」「调用参数」输入框 / CLI `-export` / `-exportarg`）
- **注入方式可选**：`CreateRemoteThread`（兼容性最好）、`NtCreateThreadEx`（底层、隐蔽性较好）、`QueueUserAPC`（仅启动时注入，隐蔽性最好）
- **注入到运行中进程**：点击「刷新」枚举当前进程（名称 + PID），选中后一键注入（OpenProcess + 远程 LoadLibraryW）
- **批量注入（多进程）**：GUI「批量注入」弹出进程多选对话框（支持按名称筛选），勾选多个进程一次性注入并**汇总成功/失败结果**；CLI 用 `-injectname <进程名>`（支持 `*` `?` 通配）或 `-injectpid <pid1,pid2,...>`（逗号分隔多 PID）批量注入，位数不符的进程自动跳过
- **注入前 PE 体检**：注入前自动对每个 DLL 做结构体检（有效 PE、位数、是否为 DLL、导出表、重定位段、可执行段），不合格直接拦截并给出原因；也可用 `-checkdll <dll...>` 单独体检
- **卸载已注入 DLL**：从目标进程远程调用 FreeLibrary，实现注入 / 卸载闭环
- **注入结果核验**：注入后自动在目标进程模块列表中核对 DLL 是否真正加载成功
- **SeDebugPrivilege 自动提权**：注入/卸载前自动尝试启用调试权限，以管理员运行时即可访问并注入 **SYSTEM 等高权限 / 其他会话**的进程；普通权限令牌下仅提示、不阻断普通进程注入
- **自动请求管理员权限（UAC）**：以非管理员身份打开图形界面时自动弹出 UAC 提权，取消则按普通权限继续
- **记忆上次选择**：自动记住最近一次注入的 exe/dll（多 DLL 完整记忆），下次启动直接带出（配置文件 `DllInjector.config`）
- **暗色主题**：内置深色主题，长时间使用不刺眼
- **窗口位置记忆**：自动记住上次的窗口大小与位置，下次启动原位恢复
- **程序图标**：内置自定义注射器图标，任务栏 / 快捷方式统一显示
- **命令行模式**：`-inject` / `-injectpid` / `-injectname` / `-eject` / `-checkdll`，支持多 DLL、启动参数、注入方式与批量注入选择，便于脚本自动化，退出码明确区分成败
- **位数自动校验**：位数不匹配时拦截并给出清晰提示，避免目标程序白屏/崩溃
- **完整日志**：界面日志 + 日志文件（`inject_log.txt`）双通道记录每一步结果
- **支持中文路径**：DLL 路径以 UTF-16 写入远程进程，兼容中文目录/文件名
- **自包含单文件**：免安装 .NET 运行时，双击即用（体积较大属正常）

## 快速开始

### 下载

从 [Releases](https://github.com/isTurn/DllInjectorTest/releases) 下载对应版本：

| 文件 | 适用目标 |
| --- | --- |
| `DllInjector-x64.exe` | 64 位目标程序 |
| `DllInjector-x86.exe` | 32 位目标程序 |

> 提示：文件选择对话框默认定位在**注入器 EXE 所在文件夹**。建议把目标 exe 和 dll 与注入器放在同一目录，选择起来更方便。

### 图形界面使用

**方式一：启动时注入**

1. 打开注入器（选择与目标程序同位数 的版本）；
2. 「目标程序」→「浏览...」选择要启动的 exe（也可直接把文件拖进输入框）；
3. 「DLL 文件」→「浏览...」选择要注入的 dll，**多个 DLL 用 `;` 分隔**（或一次多选）；点击「⇅ 排序」可在对话框中**拖拽 / 上移 / 下移 / 删除**调整注入顺序；
4. （可选）在「启动参数」输入框填写附加给目标程序的命令行参数；
5. （可选）在「导出函数」输入框填写注入成功后要调用的 DLL 导出函数名（如 `InstallHook`），在「调用参数」填写传给该函数的参数（**单个字符串**，或**用 `||` 分隔多个参数**，可留空 = 传 NULL）；
6. 在「注入方式」下拉框选择注入方式（默认 `CreateRemoteThread`）；
7. 点击「注入并启动」，下方日志实时显示每一步结果，注入完成后自动核验。

**方式二：注入到运行中进程 / 卸载 / 批量注入**

1. 在「运行中进程」右侧点击「刷新」，下拉框列出当前所有进程（名称 + PID）；
2. 下拉选择目标进程；
3. 点击「注入到进程」向它注入当前 DLL 输入框中的文件（可多个）；
4. 或点击「卸载 DLL」把该进程中已加载的 DLL（以输入框文件名为准）卸载掉；
5. **批量注入**：点击「批量注入」弹出进程多选对话框（列表显示 名称 + PID + 位数，可按名称筛选），勾选多个进程后确定，工具逐一注入并在日志中**汇总成功/失败结果**（位数不符的进程会自动跳过）。

> 注：注入其它进程（尤其以管理员/其它用户运行的进程）可能提示权限不足。图形界面非管理员启动时会自动弹出 UAC 提权；CLI 模式如遇权限不足请用管理员命令行运行。
> 注入前工具会对每个 DLL 自动做 **PE 体检**（有效 PE / 位数 / 是否为 DLL / 导出表 / 重定位 / 可执行段），不合格直接拦截并给出原因。

### 命令行模式（自动化 / 脚本）

```
DllInjector-x64.exe -inject <exe路径> <dll1> [dll2 ...] [-args <参数>] [-method crt|ntc|apc] [-export <函数>] [-exportarg <参数>]
DllInjector-x64.exe -injectpid <pid1[,pid2...]> <dll1> [dll2 ...] [-method crt|ntc] [-export <函数>] [-exportarg <参数>]
DllInjector-x64.exe -injectname <进程名> <dll1> [dll2 ...] [-method crt|ntc] [-export <函数>] [-exportarg <参数>]
DllInjector-x64.exe -eject <pid> <dll文件名>
DllInjector-x64.exe -checkdll <dll1> [dll2 ...]
```

- `-args`：附加给目标程序的命令行参数（可含空格）
- `-method`：注入方式，`crt`（默认，CreateRemoteThread）/ `ntc`（NtCreateThreadEx）/ `apc`（QueueUserAPC，仅启动时）
- `-export`：注入成功后要调用的 DLL 导出函数名（可空）
- `-exportarg`：传给该导出函数的参数；多个参数用 `||` 分隔（UTF-16，可空）
- `-injectpid`：支持**多个 PID 用逗号分隔**，逐个批量注入并汇总结果
- `-injectname`：按**进程名**批量注入，支持 `*` / `?` 通配（如 `cmd*`），位数不符自动跳过
- `-checkdll`：**只做注入前 PE 体检**，不执行注入（返回 0 = 全部合格）
- 退出码：`0` = 成功，`1` = 失败
- 详细日志写入同目录下 `inject_log.txt`

> 想快速体验「导出函数调用」？直接用仓库 `test/TestHookDll/`（或 Releases 附件）里编译好的示例 DLL（导出 `InstallHook` / `Init` / `InstallConfig` / `InstallMulti`）：
> ```
> DllInjector-x64.exe -inject 你的目标.exe test\TestHookDll\TestHookDll-x64.dll -export InstallHook -exportarg "hello"
> DllInjector-x64.exe -inject 你的目标.exe test\TestHookDll\TestHookDll-x64.dll -export InstallConfig -exportarg "server=192.168.1.10|port=8080|autostart=1"
> DllInjector-x64.exe -inject 你的目标.exe test\TestHookDll\TestHookDll-x64.dll -export InstallMulti -exportarg "张三||2024-01-01||admin"
> ```
> 注入成功后，DLL 会在自身同目录生成 `hook_call_log.txt` 记录本次调用与参数，注入器日志会显示返回码。
> `InstallConfig` 演示「复杂参数」：把多个键值对用 `|` 分隔编码进单个字符串参数，DLL 侧解析还原成结构体字段。
> `InstallMulti` 演示「多参数」：注入器把 `||` 分隔的多个参数打包成 **NULL 结尾的字符串指针数组**，导出函数按 `LPVOID* args` 逐个访问，返回参数个数。

## 注入方式对比

| 方式 | 启动时注入 | 运行中进程 | 特点 |
| --- | :---: | :---: | --- |
| `CreateRemoteThread` | ✅ | ✅ | 兼容性最好，最常见的注入手法，较易被检测 |
| `NtCreateThreadEx` | ✅ | ✅ | 直接调用 ntdll 底层线程创建，绕过部分 API 钩子，隐蔽性较好 |
| `QueueUserAPC` | ✅（推荐） | ❌（自动降级 CRT） | 不创建新线程，隐蔽性最好；要求目标主线程处于**可告警等待**（SleepEx / 消息循环），否则 APC 不会执行 |

> 说明：`QueueUserAPC` 仅适用于「启动时注入」——注入器在挂起状态下把 `LoadLibraryW` 排入目标主线程的 APC 队列，目标程序恢复运行并进入可告警等待时执行。若目标程序主线程从不进入可告警等待，该方式不会生效，此时请改用另两种方式。

## 注入原理

### 启动时注入

```
CreateProcess(CREATE_SUSPENDED)
      │  以挂起方式启动目标进程（不执行入口）
      ▼
VirtualAllocEx + WriteProcessMemory
      │  在目标进程内分配内存，写入每个 DLL 的绝对路径（UTF-16，支持中文）
      ▼
CreateRemoteThread / NtCreateThreadEx / QueueUserAPC(LoadLibraryW)
      │  逐个 DLL 远程执行 LoadLibraryW，触发各自 DllMain
      ▼
WaitForSingleObject(15s)（APC 方式跳过等待，改为恢复后核验）
      │  等待 DLL 初始化完成
      ▼
ResumeThread
      │  恢复目标进程主线程，程序正常运行
      ▼
核验模块列表
      │  确认每个 DLL 已出现在目标进程模块列表
      ▼
  注入完成
```

### 注入到运行中进程 / 卸载

```
OpenProcess(PROCESS_ACCESS_FOR_INJECT)          OpenProcess(...)
      │  打开已运行的目标进程                      │
      ▼                                            ▼
VirtualAllocEx + WriteProcessMemory          枚举目标进程模块列表
      │  写入 DLL 绝对路径                          │  拿到完整（64 位）模块基址
      ▼                                            ▼
CreateRemoteThread(LoadLibraryW)            CreateRemoteThread(FreeLibrary)
      │  远程加载 DLL，触发 DllMain                  │  远程卸载 DLL
      ▼                                            ▼
核验模块列表                                  卸载完成
      │
      ▼
  注入完成
```

> 说明：64 位进程中模块句柄是 64 位值，而远程线程退出码只有 32 位，直接把退出码当句柄传给 `FreeLibrary` 会导致卸载失败；本工具改为在注入器侧枚举目标进程模块取得完整基址，因此 x64 / x86 卸载均可靠。

### 注入后调用 DLL 导出函数

```
（注入完成，DLL 已加载，目标进程正常运行）
      ▼
PeHelper.GetExportRva(dllPath, funcName)
      │  本地解析 DLL 导出表，得到导出函数 RVA（PE 解析，无需目标进程配合）
      ▼
枚举目标进程模块 → 模块基址
      │  Process.Modules 取得该 DLL 的完整（64 位）基址
      ▼
目标地址 = 模块基址 + 导出 RVA
      │  规避 64 位句柄截断，得到真实函数入口
      ▼
（可选）VirtualAllocEx + WriteProcessMemory
      │  a) 单个参数：把「调用参数」以 UTF-16 写入目标进程，指针作为唯一参数
      │  b) 多参数（含 ||）：写入 NULL 结尾的 UTF-16 字符串指针数组，数组首地址作为参数
      ▼
CreateRemoteThread(导出函数地址, 参数指针)
      │  远程线程执行导出函数
      ▼
WaitForSingleObject(15s) → GetExitCodeThread
      │  同步等待完成，读取函数返回码（记录到日志）
      ▼
  调用完成
```

> 导出函数建议签名：
> - **单参数**：`DWORD __stdcall MyFunc(LPVOID arg)`（x86）或 `unsigned __int64 MyFunc(void* arg)`（x64），`arg` 指向目标进程内一段 UTF-16 字符串（未填参数时为 `NULL`）；
> - **多参数**：`DWORD __stdcall MyFunc(LPVOID* args)`（x86）或 `unsigned __int64 MyFunc(void** args)`（x64），`args` 是指向目标进程内 **NULL 结尾的字符串指针数组**（`args[0]..args[n-1]` 各指向一个 UTF-16 参数，`args[n] == NULL`），例如 `InstallMulti`。
>
> 返回码即线程退出码，`0` 通常表示失败或无返回值。该功能会在注入流程完成后自动执行，每个成功注入的 DLL 都会尝试调用一次。

## 从源码构建

需要 [.NET 8 SDK](https://dotnet.microsoft.com/)。

```bat
build.bat
```

输出：

| 产物 | 架构 |
| --- | --- |
| `out\x64\DllInjector.exe` | 64 位 |
| `out\x86\DllInjector.exe` | 32 位 |

> 也可以直接使用仓库内置的 [GitHub Actions](.github/workflows/build.yml)：打 `v*` 标签即可自动构建并发布 Release。

## 目录结构

```
DllInjectorTest/
├── .github/
│   ├── workflows/build.yml     # CI：自动构建 x64/x86，打标签时自动发 Release
│   ├── ISSUE_TEMPLATE/          # Issue 模板
│   └── PULL_REQUEST_TEMPLATE.md # PR 模板
├── DllInjector/                # 注入器源码（C# WinForms）
│   ├── Program.cs              # 入口 + 注入核心 + 命令行模式
│   └── DllInjector.csproj
├── test/
│   ├── TestHookDll/             # 测试「导出函数调用」功能的示例 DLL（源码 + 已编译 x64/x86，也可在 Releases 下载）
│   │   ├── TestHookDll.c        #   导出 InstallHook / Init / InstallConfig(键值对) / InstallMulti(多参数)，调用后写 hook_call_log.txt
│   │   ├── TestHookDll-x64.dll
│   │   └── TestHookDll-x86.dll
│   ├── TestDll/                 # 自测用注入 DLL 源码（DllMain 写标记文件验证，支持前缀宏区分多 DLL）
│   ├── TestTarget/              # 自测用目标程序源码（支持命令行参数回显）
│   └── build_test.bat           # 编译测试素材的脚本（MSVC）
├── screenshot.png              # 界面截图
├── build.bat                   # 一键构建脚本（x64 + x86）
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── .gitignore
└── README.md
```

## 注意事项

- **位数必须一致**：DLL 必须与目标程序同为 32 位或 64 位，否则会拒绝注入；
- **仅支持原生 DLL**：需为含 `DllMain` 的 C/C++ 编译产物，托管 .NET DLL 无法以此方式执行代码；
- **导出函数调用约定**：被调用的导出函数应接受**一个指针参数**——单参数时指向目标进程内 UTF-16 文本（未填参数时为 `NULL`）；多参数（`||` 分隔）时指向 **NULL 结尾的字符串指针数组**，DLL 侧用 `LPVOID* args` 逐个访问；函数若阻塞超过 15 秒会被判定超时；QueueUserAPC 为异步加载，调用导出函数时 DLL 可能尚未加载完成，建议使用 CRT/NTC 方式；
- **QueueUserAPC 的局限**：仅适用于启动时注入，且目标主线程需处于可告警等待（SleepEx / GetMessage 循环），否则不会执行（核验会提示）；
- **UAC 提权**：图形界面非管理员启动时自动请求管理员权限；若不希望每次弹 UAC，可取消后按普通权限使用（普通进程注入无需提权）；
- **SeDebugPrivilege**：以管理员运行时会自动启用调试权限，从而能打开/注入 SYSTEM 等高权限或其它会话的进程；普通权限令牌下该权限不存在，注入这类进程会提示权限不足；
- **杀毒软件可能告警**：`CreateRemoteThread` 注入是常见注入手法，部分杀软会报毒；
- **请合法使用**：仅对你有权操作的软件使用（如插件、MOD、调试、内部工具等场景），详见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE) © 2026 [isTurn](https://github.com/isTurn)
