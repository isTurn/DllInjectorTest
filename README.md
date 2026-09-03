# DLL 注入器 (DLL Injector)

[![Release](https://img.shields.io/github/v/release/isTurn/DllInjectorTest?style=flat-square&logo=github)](https://github.com/isTurn/DllInjectorTest/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/isTurn/DllInjectorTest/build.yml?style=flat-square&logo=githubactions&logoColor=white&label=build)](https://github.com/isTurn/DllInjectorTest/actions)
[![License](https://img.shields.io/github/license/isTurn/DllInjectorTest?style=flat-square)](LICENSE)
[![Language](https://img.shields.io/github/languages/top/isTurn/DllInjectorTest?style=flat-square)](https://github.com/isTurn/DllInjectorTest)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20x86-0078D6?style=flat-square&logo=windows)]()

一个带图形界面的 Windows 工具：选择目标 exe 和要注入的 dll，点击「注入并启动」，工具会以**挂起方式启动目标程序 → 批量注入 DLL → 恢复运行**；也可以**向运行中的进程直接注入**，或**卸载已注入的 DLL**。支持 **x64 / x86** 双架构、**多 DLL 批量注入**、**启动参数透传**、**三种注入方式**与**注入结果自动核验**。

## 界面预览

![DLL Injector 界面](screenshot.png)

## 功能特性

- **图形界面**：直观的 WinForms 界面，支持直接把文件拖进输入框（多文件可一次拖入）
- **启动时注入**：以挂起方式启动目标程序 → 批量注入 DLL → 恢复运行
- **多 DLL 批量注入**：DLL 输入框内用 `;` 分隔多个 DLL，一次性全部注入（GUI / CLI 均支持）
- **启动参数透传**：启动目标程序时可附加命令行参数（GUI「启动参数」输入框 / CLI `-args`）
- **注入方式可选**：`CreateRemoteThread`（兼容性最好）、`NtCreateThreadEx`（底层、隐蔽性较好）、`QueueUserAPC`（仅启动时注入，隐蔽性最好）
- **注入到运行中进程**：点击「刷新」枚举当前进程（名称 + PID），选中后一键注入（OpenProcess + 远程 LoadLibraryW）
- **卸载已注入 DLL**：从目标进程远程调用 FreeLibrary，实现注入 / 卸载闭环
- **注入结果核验**：注入后自动在目标进程模块列表中核对 DLL 是否真正加载成功
- **自动请求管理员权限（UAC）**：以非管理员身份打开图形界面时自动弹出 UAC 提权，取消则按普通权限继续
- **记忆上次选择**：自动记住最近一次注入的 exe/dll（多 DLL 完整记忆），下次启动直接带出（配置文件 `DllInjector.config`）
- **命令行模式**：`-inject` / `-injectpid` / `-eject`，支持多 DLL、启动参数与注入方式选择，便于脚本自动化，退出码明确区分成败
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
3. 「DLL 文件」→「浏览...」选择要注入的 dll，**多个 DLL 用 `;` 分隔**（或一次多选）；
4. （可选）在「启动参数」输入框填写附加给目标程序的命令行参数；
5. 在「注入方式」下拉框选择注入方式（默认 `CreateRemoteThread`）；
6. 点击「注入并启动」，下方日志实时显示每一步结果，注入完成后自动核验。

**方式二：注入到运行中进程 / 卸载**

1. 在「运行中进程」右侧点击「刷新」，下拉框列出当前所有进程（名称 + PID）；
2. 下拉选择目标进程；
3. 点击「注入到进程」向它注入当前 DLL 输入框中的文件（可多个）；
4. 或点击「卸载 DLL」把该进程中已加载的 DLL（以输入框文件名为准）卸载掉。

> 注：注入其它进程（尤其以管理员/其它用户运行的进程）可能提示权限不足。图形界面非管理员启动时会自动弹出 UAC 提权；CLI 模式如遇权限不足请用管理员命令行运行。

### 命令行模式（自动化 / 脚本）

```
DllInjector-x64.exe -inject <exe路径> <dll1> [dll2 ...] [-args <参数>] [-method crt|ntc|apc]
DllInjector-x64.exe -injectpid <pid> <dll1> [dll2 ...] [-method crt|ntc]
DllInjector-x64.exe -eject <pid> <dll文件名>
```

- `-args`：附加给目标程序的命令行参数（可含空格）
- `-method`：注入方式，`crt`（默认，CreateRemoteThread）/ `ntc`（NtCreateThreadEx）/ `apc`（QueueUserAPC，仅启动时）
- 退出码：`0` = 成功，`1` = 失败
- 详细日志写入同目录下 `inject_log.txt`

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
│   ├── TestDll/                # 自测用注入 DLL 源码（DllMain 写标记文件验证，支持前缀宏区分多 DLL）
│   ├── TestTarget/             # 自测用目标程序源码（支持命令行参数回显）
│   └── build_test.bat          # 编译测试素材的脚本（MSVC）
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
- **QueueUserAPC 的局限**：仅适用于启动时注入，且目标主线程需处于可告警等待（SleepEx / GetMessage 循环），否则不会执行（核验会提示）；
- **UAC 提权**：图形界面非管理员启动时自动请求管理员权限；若不希望每次弹 UAC，可取消后按普通权限使用（普通进程注入无需提权）；
- **杀毒软件可能告警**：`CreateRemoteThread` 注入是常见注入手法，部分杀软会报毒；
- **请合法使用**：仅对你有权操作的软件使用（如插件、MOD、调试、内部工具等场景），详见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE) © 2026 [isTurn](https://github.com/isTurn)
