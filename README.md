# DLL 注入器 (DLL Injector)

[![Release](https://img.shields.io/github/v/release/isTurn/DllInjectorTest?style=flat-square&logo=github)](https://github.com/isTurn/DllInjectorTest/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/isTurn/DllInjectorTest/build.yml?style=flat-square&logo=githubactions&logoColor=white&label=build)](https://github.com/isTurn/DllInjectorTest/actions)
[![License](https://img.shields.io/github/license/isTurn/DllInjectorTest?style=flat-square)](LICENSE)
[![Language](https://img.shields.io/github/languages/top/isTurn/DllInjectorTest?style=flat-square)](https://github.com/isTurn/DllInjectorTest)
[![.NET](https://img.shields.io/badge/.NET-8.0-512BD4?style=flat-square&logo=dotnet)](https://dotnet.microsoft.com/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20x64%20%7C%20x86-0078D6?style=flat-square&logo=windows)]()

一个带图形界面的 Windows 工具：选择目标 exe 和要注入的 dll，点击「注入并启动」，工具会以**挂起方式启动目标程序 → 批量注入 DLL → 恢复运行**；也可以**向运行中的进程直接注入**，或**卸载已注入的 DLL**。支持 **x64 / x86** 双架构、**多 DLL 批量注入**、**启动参数透传**、**五种注入方式**、**注入后调用 DLL 导出函数**与**注入结果自动核验**。

## 界面预览

![DLL Injector 界面](screenshot.png?v=3)

## 功能特性

- **图形界面**：直观的 WinForms 界面，支持直接把文件拖进输入框（多文件可一次拖入）
- **启动时注入**：以挂起方式启动目标程序 → 批量注入 DLL → 恢复运行
- **多 DLL 批量注入**：DLL 输入框内用 `;` 分隔多个 DLL，一次性全部注入（GUI / CLI 均支持）；GUI 提供「⇅ 排序」对话框（支持拖拽重排 / 上移 / 下移 / 删除），可自由调整多 DLL 的注入顺序
- **启动参数透传**：启动目标程序时可附加命令行参数（GUI「启动参数」输入框 / CLI `-args`）
- **注入后调用 DLL 导出函数**：注入成功后自动远程调用指定导出函数（如 `InstallHook` / `Init`），可传入一个字符串参数，**也支持多参数**（调用参数内用 `||` 分隔，DLL 侧以字符串指针数组接收）；「启动时注入」与「注入到运行中进程」均支持（GUI「导出函数」「调用参数」输入框 / CLI `-export` / `-exportarg`）
- **注入方式可选**：`CreateRemoteThread`（兼容性最好）、`NtCreateThreadEx`（底层、隐蔽性较好）、`QueueUserAPC`（仅启动时注入，隐蔽性最好）、**反射式注入**（Reflective：针对自带 `ReflectiveLoader` 导出的反射 DLL，由 DLL 自行在目标进程内完成 PE 映射，不落盘更隐蔽）、**手动映射注入**（Manual Map：注入器内置 shellcode 在目标进程内完成全部 PE 映射，不调用 LoadLibrary，普通 DLL 即可用，能绕开基于 LoadLibrary 挂钩的检测）
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
- **命令行模式**：`-inject` / `-injectpid` / `-injectname` / `-eject` / `-checkdll` / `-status` / `-help` / `-version`，支持多 DLL、启动参数、注入方式与批量注入选择，便于脚本自动化，退出码明确区分成败
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

Release 里还会附带测试样例 DLL（`TestHookDll-*` / `TestReflectiveDll-*`）、文本 Hook 的
`TextHookDll-*` / `TextHookClient.exe` 与引擎适配表模板 `TextHookDll.profiles.ini`。
它们只用于试用对应功能，普通注入不需要。

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
DllInjector-x64.exe -inject <exe路径> <dll1> [dll2 ...] [-args <参数>] [-method crt|ntc|apc|rfi|mm] [-export <函数>] [-exportarg <参数>]
DllInjector-x64.exe -injectpid <pid1[,pid2...]> <dll1> [dll2 ...] [-method crt|ntc|rfi|mm] [-export <函数>] [-exportarg <参数>]
DllInjector-x64.exe -injectname <进程名> <dll1> [dll2 ...] [-method crt|ntc|rfi|mm] [-export <函数>] [-exportarg <参数>]
DllInjector-x64.exe -eject <pid> <dll文件名>
DllInjector-x64.exe -checkdll <dll1> [dll2 ...]
DllInjector-x64.exe -status <pid> [dll...] [-pipe <管道名>]
DllInjector-x64.exe -help | -version
```

- `-args`：附加给目标程序的命令行参数（可含空格）
- `-method`：注入方式，`crt`（默认，CreateRemoteThread）/ `ntc`（NtCreateThreadEx）/ `apc`（QueueUserAPC，仅启动时）/ `rfi`（反射式注入，DLL 需自带 `ReflectiveLoader` 导出）/ `mm`（手动映射注入，不调用 LoadLibrary，普通 DLL 即可用）
- `-export`：注入成功后要调用的 DLL 导出函数名（可空）
- `-exportarg`：传给该导出函数的参数；多个参数用 `||` 分隔（UTF-16，可空）
- `-injectpid`：支持**多个 PID 用逗号分隔**，逐个批量注入并汇总结果
- `-injectname`：按**进程名**批量注入，支持 `*` / `?` 通配（如 `cmd*`），位数不符自动跳过
- `-checkdll`：**只做注入前 PE 体检**，不执行注入（返回 0 = 全部合格）
- `-status`：**只读查询**，不动目标进程——打印进程位数与是否与本注入器匹配、指定 DLL 是否已在模块列表（给出基址）、
  手动映射记录是否有效（`DllInjector.mmmap` 里的基址，PID 复用过的会被判失效）、文本 Hook 的命名管道是否在线
  （`-pipe` 指定管道名，默认 `GalToolText`；能区分「没有这个管道」与「有管道但实例全被占满」）
- `-help` / `-version`：打印完整用法 / 版本号后以 `0` 退出，不注入、不写日志
- 退出码：`0` = 成功，`1` = 失败
- 详细日志写入同目录下 `inject_log.txt`

> **`|` 有两种含义，别混用**：作为**多个 DLL 之间的分隔符**时（DLL 输入框 / `-inject` 的 DLL 参数），`;`、`|`、换行都可以；而 `-exportarg` 里的 `|` 只是**普通字符**，原样传给导出函数（`InstallConfig` 正是用它分隔多个键值对）。
> 所以 `-exportarg "engine=generic-gdi|cp=932"` 里的 `|` 不会被当成 DLL 分隔符——它整个是一份参数值。多个 DLL 请写在 `-exportarg` **之前**，或用 `;` 分隔以免看错。
> 想让 `-exportarg` 传**多个独立参数**（打包成字符串指针数组）时用 `||`，例如 `-exportarg "张三||2024-01-01||admin"`。

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
| `反射式注入 (Reflective)` | ✅ | ✅ | 不把 DLL 落盘、不调用 LoadLibrary，由 DLL 自带 `ReflectiveLoader` 在目标进程内完成 PE 映射/重定位/填 IAT，磁盘无痕迹，隐蔽性最强；要求 DLL 本身是**反射 DLL** |
| `手动映射注入 (Manual Map)` | ✅ | ✅ | 不调用 LoadLibrary：注入器把 shellcode 写进目标进程，由它在进程内完成 PE 映射/重定位/填 IAT/调 DllMain；**普通 DLL 即可用**，能绕开基于 LoadLibrary 挂钩的检测 |

> 说明：`QueueUserAPC` 仅适用于「启动时注入」——注入器在挂起状态下把 `LoadLibraryW` 排入目标主线程的 APC 队列，目标程序恢复运行并进入可告警等待时执行。若目标程序主线程从不进入可告警等待，该方式不会生效，此时请改用另两种方式。
> 说明：反射式注入的 DLL 必须自带 `ReflectiveLoader` 导出函数（普通 `LoadLibrary` 型 DLL 请改用 CRT/NTC/APC 方式）。x86 反射 DLL 对全局量采用绝对寻址，要求目标进程的映像基址（通常 `0x10000000`）空闲可分配。

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

> **手动映射（`mm`）注入的 DLL 卸载**：MM DLL 不在目标进程模块列表，枚举与 `FreeLibrary` 均无效。
> 「卸载 DLL」会先查手动映射基址记录（注入时写入同目录 `DllInjector.mmmap`，支持跨进程 / 重启注入器后卸载），
> 命中后在目标进程内执行卸载 shellcode：调用 `DllMain(DLL_PROCESS_DETACH)` → 按镜像整体 `VirtualFree` 释放，
> 全程不调 `FreeLibrary`。x64 520 字节 / x86 451 字节，源码见 `test/ManualMap/UnmapDll_*.asm`。

### 反射式注入（Reflective）

```
PeHelper.GetExportRva(dllPath, "ReflectiveLoader")
      │  本地解析反射 DLL 导出表，定位 ReflectiveLoader 的 RVA
      ▼
VirtualAllocEx(目标进程, SizeOfImage, RWX)
      │  x86 反射 DLL 用绝对寻址 → 优先分配在映像基址（如 0x10000000）；
      │  x64 走 RIP 相对寻址，映像基址占用时回退任意地址
      ▼
WriteProcessMemory（内存布局展开）
      │  头部复制到 +0，每个节复制到各自的 VirtualAddress（而非文件偏移）
      ▼
CreateRemoteThread(基址 + loaderRva, NULL)
      │  远程线程执行 DLL 自带的 ReflectiveLoader
      ▼
ReflectiveLoader 在目标进程内自行完成：
      │  定位 kernel32（PEB 模块链）→ 解析导出表 → VirtualAlloc 新镜像
      │  → 复制节 → 应用重定位（基址增量）→ 填充 IAT → 调用 DllMain
      ▼
WaitForSingleObject(15s) → 线程退出码非 0 即成功（返回映射模块句柄）
      │
      ▼
  反射注入完成（磁盘无 DLL 落盘，LoadLibrary 链路被完全绕开）
```

> 反射 DLL 的 `ReflectiveLoader` 全部工作在**目标进程内**：先通过 PEB 的模块链手工找到 kernel32（x86 从 `FS:[0x30]` 取 PEB，x64 从 `GS:[0x60]` 取），再解析其导出表拿到 `VirtualAlloc / LoadLibraryA / GetProcAddress` 等函数；随后为镜像分配新内存、逐节复制、按基址增量重定位、填充导入表，最后调用 `DllMain(DLL_PROCESS_ATTACH)`。整个过程不产生任何磁盘文件。
> 仓库 `test/TestReflectiveDll/` 提供**自包含反射加载器**示例（`ReflectiveLoader_x64.asm` / `ReflectiveLoader_x86.asm` + C 源码），已编译 x64/x86 两个反射 DLL，可直接配合反射式注入使用。同目录的 `TestLoader-x64.exe` / `TestLoader-x86.exe` 用于**进程内自验证**：把 DLL 按内存布局展开后直接调用其 `ReflectiveLoader`，不依赖注入器即可确认加载器本身可用（成功则输出 `C:\Windows\Temp\rfi_call_log.txt`）。

### 手动映射注入（Manual Map）

```
PeHelper 校验 PE（MZ/PE 签名/位数）
      │  注入器本地解析 DLL 文件头
      ▼
VirtualAllocEx：rawBuf(DLL 字节) + argsBuf(MmArgs + 结果区) + scBuf(shellcode, RWX)
      │  shellcode = 注入器内置的手动映射器（x64 1202B / x86 956B）
      ▼
CreateRemoteThread(scBuf, argsBuf)
      │  远程线程在目标进程内执行 shellcode
      ▼
shellcode 在目标进程内完成：
      │  校验 MZ/PE32(32/64) → PEB 定位 kernel32（x86 FS:[0x30] / x64 GS:[0x60]）
      │  → 解析导出表拿 VirtualAlloc / LoadLibraryA / GetProcAddress
      │  → VirtualAlloc(SizeOfImage, RWX) → 拷头 + 逐节按 PointerToRawData 拷贝 + BSS 补零
      │  → 按基址增量应用重定位 → 填 IAT（名字/序数双路径）→ 调用 DllMain(PROCESS_ATTACH)
      │  → 把完整模块基址写回结果区（64 位下线程退出码会截断，基址经结果区完整回传）
      ▼
WaitForSingleObject(15s) → 注入器读回结果区模块基址
      │
      ▼
  手动映射注入完成（不调用 LoadLibrary，LoadLibrary 链路被完全绕开）
```

> 与反射式注入的区别：反射式要求 DLL 自带 `ReflectiveLoader`，由 DLL 自己完成映射；手动映射由**注入器提供的 shellcode** 在目标进程内完成全部 PE 映射工作，因此**普通 LoadLibrary 型 DLL 也能注入**，同时同样绕开基于 LoadLibrary 挂钩的检测（EDR / 杀软常监控 LoadLibrary）。shellcode 源码在 `test/ManualMap/`（`ManualMap_x64.asm` / `ManualMap_x86.asm`），经 ml64 / ml 编译后由脚本提取字节内嵌进注入器。

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

## 文本 Hook（GalGame 引擎适配）

注入器本身是**通用投送器**；面向 GalGame 的文本提取能力由配套的文本 Hook DLL 提供。

> 完整设计（分层架构、引擎 profile 抽象、Hook 策略演进、编码处理、路线图）见
> **[docs/text-hook-design.md](docs/text-hook-design.md)**。

`test/TextHookDll/` 提供一阶段原型：

| 文件 | 作用 |
| --- | --- |
| `TextHookDll.c` | profile 驱动的文本 Hook DLL：IAT 挂钩 `TextOutA/W`、`ExtTextOutA/W`、`DrawTextA/W`，SJIS/GBK → UTF-8 转换，命名管道推送 |
| `TextHookDll.def` | 导出表：统一 x86/x64 的无修饰导出名（x86 下 `__stdcall` 会修饰成 `_InstallConfig@4`） |
| `TextHookDll.profiles.ini` | **引擎适配表模板**（随 DLL 一起分发）。改引擎适配只需改这个文件，不用重编译 DLL |
| `TextHookClient.c` | 管道消费者，实时打印捕获到的文本；管道断开后自动重连（游戏重开、重新注入都不会让客户端自己退出） |
| `TestTextHook.c` | **进程内端到端验证器**：自己加载 DLL、装钩子、用 GDI 输出文本、核对日志，全自动（自动跑 8 个场景，x64 + x86 都跑） |
| `build.bat` | 编译上述内容 + 验证用目标程序，**并自动跑两个架构的验证**（输出到 `test_output\`） |
| `../TestTextTarget/TestTextTarget.c` | 验证目标：用 GDI 输出硬编码的日文/中文文本，便于确定性核对 |

**零改动复用现有注入器**——引擎配置通过既有的 `-export` / `-exportarg` 机制下发：

```bat
:: 1) 编译 + 自动验证（x64 与 x86 都会跑一遍，失败即非零退出）
test\TextHookDll\build.bat

:: 2) 起客户端监听管道（独立控制台，可选）
test_output\TextHookClient.exe

:: 3) 注入并启动目标程序
DllInjector-x64.exe -inject test_output\TextTarget_x64.exe test_output\TextHookDll-x64.dll ^
    -export InstallConfig -exportarg "engine=generic-gdi|cp=932|log=1"
```

> **编码必须配对**：`cp=` 是**进程级**设置，一个进程只能有一种 `*A` 编码。验证目标默认输出 Shift-JIS（配 `cp=932`）；
> 要验证 GBK 请以 `test_output\TextTarget_x64.exe gbk` 启动并传 `cp=936`。两者不匹配时 `*A` 文本必然乱码，这是设计使然。
> `*W` 系列走宽字符，不受 `cp=` 影响。

### 适配新引擎：改 ini，不用重编译

DLL 会从**自身所在目录**读取 `TextHookDll.profiles.ini`，也可以写一份自己的：

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

```bat
DllInjector-x64.exe -inject game.exe test_output\TextHookDll-x64.dll ^
    -export InstallConfig -exportarg "profilefile=D:\my\game.ini|engine=my-game-jp|log=1"
```

文件里的 profile 可以**同名覆盖**内置的 4 个（写一个 `[generic-gdi]` 就能改掉兜底行为）；
任何一行写错则整份文件不生效、退回内置，并在启动横幅里说明原因。

**框架不认识的函数也能挂**——只要补上参数位置（序号 1 起）：

```ini
[my-engine]
desc=引擎自己的文本函数
codepage=932
minlen=2
dedup=200
text=4        ; 第 4 个参数是文本指针
len=5         ; 第 5 个参数是长度（不写 = 以 \0 结尾）
argc=5        ; 参数总数，1..8。必填，转发调用要按它弹栈
wide=0        ; 0 = char*（按 codepage 转）；1 = wchar_t*
conv=stdcall  ; stdcall（默认）或 cdecl。写错会弹歪栈、进程直接崩
hook=myengine.dll,RenderText
```

这 5 个键写在段内任意位置都行（整段读完才生效），会应用到该段的所有 `hook=`。
校验是「全有或全无」：`argc` 越界、`text`/`len` 超出 `argc`、值不是数字，
都会让整份文件不生效并退回内置。

> ⚠ **能力边界**：`text=` / `len=` 让 profile 不再局限于那 6 个函数，
> 但**「第几个参数是文本」仍需自己数准**（看反汇编或头文件）。
> 数错的后果不只是抓不到——把整数当指针读会让游戏崩掉，所以务必先在调试器里确认。
> 仍然做不到的：自动猜参数位置、把逐字片段拼成整句、DirectX 自绘（S5）、
> 引擎连 `GetProcAddress` 都自己现取的情况（S2 Inline Hook）。

**动态取址（`GetProcAddress`）已被覆盖**：引擎若用
`p = GetProcAddress(GetModuleHandleA("gdi32.dll"), "TextOutA")` 自己取地址再调用，
导入表里看不到这个函数、IAT Hook 抓不到。DLL 会把各模块 IAT 里的 `GetProcAddress`
换成自己的替身：先问真实地址，若是我们挂钩的目标就返回替换函数。
启动横幅会单独报告一行「已登记 N 个目标，GetProcAddress 替换了 M 个槽」——
「钩子挂上了却没文本」时，看这一行就能判断是不是动态取址没覆盖到。

**确认 ini 有没有被读到**：看 `texthook_log.txt` 开头的第二行横幅，它会直接报出
读了哪个文件、加载了几个 profile、分别叫什么。

配置项（`k=v` 用 `|` 分隔）：

| 键 | 说明 |
| --- | --- |
| `engine` | 内置 `generic-gdi`（默认）/ `generic-gdi-sjis` / `generic-gdi-gbk` / `generic-unicode`，或 ini 文件里自定义的名字 |
| `profilefile` | 指定 profile 文件路径（默认取 DLL 同目录的 `TextHookDll.profiles.ini`） |
| `nofile` | `1` 时完全不读 profile 文件，只用内置的 4 个（排查「是不是 ini 在作怪」时用） |
| `cp` | 强制 `*A` 系列文本的代码页（932 = Shift-JIS，936 = GBK），覆盖 profile 默认值 |
| `pipe` | 管道名，默认 `GalToolText`（实际路径 `\\.\pipe\<名称>`）。服务端默认开 **4 个实例**，可同时挂多个消费者，同一行文本广播给所有已连接的客户端 |
| `log` | `1` 时同时落盘 `texthook_log.txt`（默认开，便于无客户端时验证） |
| `minlen` / `dedup` | 最短文本长度（默认 2）/ 去重窗口毫秒（默认 200，游戏每帧重绘必须去重） |

> **当前状态：一阶段 IAT Hook + 引擎适配表外部化 + 动态取址补漏。**
> 挂钩发生在游戏开跑之后（注入器的 `ResumeThread` 早于导出函数调用，会漏掉启动后约百毫秒的文本）。
> profile 可以写成文件、不用重编译，也能挂框架不认识的函数；但**具体引擎 profile 仍需对着实机样本逆向填写**，
> 无法凭空推测。演进计划见设计文档第 8 节路线图。

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
| `dist\DllInjector-x64.exe` | 64 位（与 Release 同名副本） |
| `dist\DllInjector-x86.exe` | 32 位（与 Release 同名副本） |

> 发布参数与 [GitHub Actions](.github/workflows/build.yml) 保持一致（Release + 自包含单文件 + 压缩），本地构建与 CI 产物相同。
> 也可以直接用仓库内置的 CI：打 `v*` 标签即可自动构建并发布 Release。

<details>
<summary>遇到 <code>NuGet.targets(745,5): error : Value cannot be null. (Parameter 'path1')</code>？</summary>

这是**环境变量缺失**，与项目无关。NuGet 6.x 的 `NuGetEnvironment` 用环境变量（而非 Win32 API）推导配置目录：

| NuGet 需要的目录 | 依赖的环境变量 |
| --- | --- |
| `MachineWideSettingsBaseDirectory` | `ProgramFiles` |
| `UserSettingsDirectory` | `APPDATA` |

在精简 / 加固 / 沙箱化的 shell 里这些变量可能整体缺失，于是 `XPlatMachineWideSetting` 的**静态**构造函数在项目被读取之前就 `Path.Combine(null, ...)` 抛异常——因此**改项目文件、改 `NuGet.Config`、加 MSBuild 属性都绕不过去**（空工程同样失败）。

`build.bat` 已在启动时防御性补回缺失的变量，所以正常用 `build.bat` 不会碰到。若是直接调用 `dotnet`，手动补上即可：

```bat
set "APPDATA=%USERPROFILE%\AppData\Roaming"
set "ProgramFiles=%SystemDrive%\Program Files"
```
</details>

### 构建测试素材（可选）

`test/` 下的 C / ASM 素材需要 MSVC，脚本会通过 `vswhere.exe` 自动定位 Visual Studio（任意版本、任意安装路径均可）：

```bat
test\build_test.bat                  :: 编译测试 DLL 与目标程序 -> test_output\
test\ManualMap\build_shellcode.bat   :: 汇编手动映射 shellcode 并回填 Program.cs 的字节数组
test\ManualMap\build_shellcode.bat --check  :: 只校验 Program.cs 与 .asm 是否同步（CI 用）
test\TestReflectiveDll\build.bat     :: 编译反射 DLL 示例 + TestLoader 进程内验证器（产物在 test_output\）
test\TestHookDll\build.bat           :: 编译示例 DLL（x64 + x86，产物在 test_output\，并就地跑一遍导出函数验证）
test\TextHookDll\build.bat           :: 编译文本 Hook DLL + 客户端 + 验证目标，并自动跑双架构验证 -> test_output\
test\DllInjectorTests\build.bat      :: C# 纯逻辑回归测试（不需要 MSVC，只要 .NET 8 SDK）
test\DllInjectorE2E\build.bat        :: 注入器端到端测试（真的建进程/注入/调导出/卸载，五种方式全覆盖）
test\DllInjectorE2E\build.bat --x86  :: 同上，按 32 位跑（测试主机位数必须与目标进程一致）
```

> `DllInjectorE2E` 会真的启动 `test_output\Target_*.exe`、真的注入、真的调用导出函数、
> 真的卸载，所以它需要先跑过 `test\build_test.bat`、`test\TestHookDll\build.bat`、
> `test\TestReflectiveDll\build.bat`（缺文件时脚本会直接打印 `MISSING_PREREQ` 并退出 1）。
> 它是这个仓库里唯一能发现「反射注入报告成功、目标进程其实已经死了」这类问题的测试——
> 只测纯函数永远看不见。

> `test\ManualMap\build_shellcode.bat` 会**自动回填** `DllInjector\Program.cs` 里的四个 `byte[]`
> （由 `gen_shellcode.py --apply` 完成，不再是手工复制）。
> `--check` 只比对不写入：仓库里的数组与 `.asm` 汇编结果不一致时以非零码退出，
> CI 用它挡住「改了 `.asm` 却忘了重新生成」的情况。

> **这些脚本都不会写仓库里已提交的文件。** 四个随仓库分发的样例 DLL
> （`test\TestHookDll\TestHookDll-{x64,x86}.dll`、`test\TestReflectiveDll\TestReflectiveDll-{x64,x86}.dll`）
> 默认由脚本重新编译到 `test_output\`，源码目录里那份保持不动，所以跑完回归
> `git status` 是干净的。确实要刷新已提交的那份（只有维护者发布新样例时才需要）：
>
> ```bat
> test\TestHookDll\build.bat --update-shipped
> test\TestReflectiveDll\build.bat --update-shipped
> ```
>
> 两个脚本都带 `/Brepro`，同一条工具链下重复构建产出的字节完全一致——
> 否则每跑一次都会因为 PE 头里的时间戳而变化，`git status` 永远脏，
> 「这份二进制到底改没改」也无从判断。

### 在受限网络下同步仓库（GitHub API）

某些环境里 `github.com:443` 不通（`git fetch` / `git push` 报
`Connection was reset` 或 `Failed to connect to github.com:443`），但
`api.github.com` 可达。`tools/git-api-sync.py` 走 Git Data API 搬运对象，
**不需要** smart-HTTP 通道：

```bash
python tools/git-api-sync.py status                # 本地 vs 远端
python tools/git-api-sync.py push                  # 把本地新提交推上去
python tools/git-api-sync.py fetch                 # 把远端新提交拉下来
```

两个方向都是**逐字节重放**：推上去的提交 SHA 与本地完全一致，拉下来的
历史也是完整提交链而不是压平的快照，脚本会断言这一点。`push` 拒绝改写
历史（父提交必须是远端 tip）；`fetch` 只会快进，不会强推本地分支。

> 远端返回的日期被归一化成 UTC、提交消息末尾的换行会被吃掉，脚本对这两项
> 都做了候选搜索，命中后校验 SHA —— 细节见脚本开头的说明。

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
│   ├── TestReflectiveDll/       # 测试「反射式注入」的自包含反射加载器（源码 + 已编译 x64/x86，也可在 Releases 下载）
│   │   ├── TestReflectiveDll.c  #   自包含反射加载器核心：PEB 定位 kernel32 / 映射 / 重定位 / 填 IAT / 调 DllMain
│   │   ├── ReflectiveLoader_x64.asm   #   x64 反射加载器入口（栈对齐已处理）
│   │   ├── ReflectiveLoader_x86.asm   #   x86 反射加载器入口
│   │   ├── Reflective.def / build.bat
│   │   ├── TestReflectiveDll-x64.dll  #   加载成功后写 C:\Windows\Temp\rfi_call_log.txt 两行日志
│   │   ├── TestReflectiveDll-x86.dll
│   │   ├── TestLoader.c         #   进程内验证反射加载器（按内存布局展开后直接调用 ReflectiveLoader）
│   │   └── build.bat            #   产物落 test_output\；TestLoader-{x64,x86}.exe 也编在那里，默认加载同目录同架构的反射 DLL
│   ├── ManualMap/               # 手动映射注入 shellcode（源码 + 编译中间物，字节已内嵌注入器）
│   │   ├── ManualMap_x64.asm    #   x64 手动映射器（1202 字节，已实机验证 Init=42 / InstallHook=1）
│   │   ├── ManualMap_x86.asm    #   x86 手动映射器（956 字节，已实机验证 Init=42 / InstallHook=1）
│   │   ├── UnmapDll_x64.asm     #   x64 手动映射卸载器（520 字节）
│   │   ├── UnmapDll_x86.asm     #   x86 手动映射卸载器（451 字节）
│   │   ├── gen_shellcode.py     #   从 .obj 提取 .text 机器码并生成 C# byte[] 字面量
│   │   └── build_shellcode.bat  #   一键汇编 + 提取（ml64 / ml + python）
│   ├── TextHookDll/             # GalGame 文本 Hook（一阶段原型，详见 docs/text-hook-design.md）
│   │   ├── TextHookDll.c        #   profile 驱动的 IAT 文本 Hook：挂钩 GDI 文本 API + 管道推送
│   │   ├── TextHookDll.def      #   导出表：统一 x86/x64 的无修饰导出名（避免 __stdcall 修饰差异）
│   │   ├── TextHookDll.profiles.ini  # 引擎适配表模板（随 DLL 分发，改它不用重编译）
│   │   ├── TextHookClient.c     #   管道消费者（控制台实时打印捕获到的文本）
│   │   ├── TestTextHook.c       #   进程内端到端验证器（自动跑 8 个场景，x64 + x86 都跑）
│   │   └── build.bat            #   编译 Hook DLL + 客户端 + 验证目标 + 验证器，并自动验证
│   ├── DllInjectorTests/        # C# 纯逻辑回归测试（PE 解析 / DLL 分隔 / -method / 通配 / 配置）
│   │   ├── Program.cs           #   自带断言的控制台程序，不依赖任何 NuGet 测试框架
│   │   ├── DllInjectorTests.csproj   # 把 DllInjector/Program.cs 原样链接进来编译
│   │   └── build.bat            #   构建 + 运行，只需 .NET 8 SDK（不需要 MSVC）
│   ├── DllInjectorE2E/          # 注入器端到端测试（真的建进程 / 注入 / 调导出 / 卸载）
│   │   ├── Program.cs           #   覆盖 CRT / NTC / APC / RFI / MM + 卸载 + -status
│   │   ├── DllInjectorE2E.csproj     # 同样链接 Program.cs，按 -p:PlatformTarget 出双架构
│   │   └── build.bat            #   build.bat 跑 x64，build.bat --x86 跑 x86
│   ├── TestTextTarget/          # 文本 Hook 的验证目标（GDI 输出硬编码日文/中文，便于确定性核对）
│   │   └── TestTextTarget.c     #   可传 sjis（默认）/ gbk 选择 *A 系列编码，需与 cp= 配对
│   ├── TestDll/                 # 自测用注入 DLL 源码（DllMain 写标记文件验证，支持前缀宏区分多 DLL）
│   ├── TestTarget/              # 自测用目标程序源码（支持命令行参数回显）
│   └── build_test.bat           # 编译测试素材的脚本（MSVC，自动定位 Visual Studio）
├── docs/
│   ├── index.html               # GitHub Pages 展示页
│   └── text-hook-design.md      # 多引擎文本 Hook 适配架构设计
├── tools/
│   └── git-api-sync.py          # 受限网络下用 GitHub Git Data API 推/拉（逐字节保 SHA）
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
- **反射式注入的要求**：DLL 必须自带 `ReflectiveLoader` 导出；x86 反射 DLL 用绝对寻址，要求目标进程映像基址（通常 `0x10000000`）空闲，若被占用注入会失败（x64 无此限制）；反射映射成功后注入器保留映射内存直至目标进程退出；
- **手动映射注入的说明**：不调用 LoadLibrary，模块**不会出现在目标进程模块列表**（属正常）；调用导出函数时用 shellcode 返回的模块基址 + 导出 RVA 直接计算地址；要求目标进程位数与注入器一致；x86 的 stdcall 导出函数在查找时自动兼容 `_函数名@N` 装饰名；
- **QueueUserAPC 的局限**：仅适用于启动时注入，且目标主线程需处于可告警等待（SleepEx / GetMessage 循环），否则不会执行（核验会提示）；
- **UAC 提权**：图形界面非管理员启动时自动请求管理员权限；若不希望每次弹 UAC，可取消后按普通权限使用（普通进程注入无需提权）；
- **SeDebugPrivilege**：以管理员运行时会自动启用调试权限，从而能打开/注入 SYSTEM 等高权限或其它会话的进程；普通权限令牌下该权限不存在，注入这类进程会提示权限不足；
- **杀毒软件可能告警**：`CreateRemoteThread` 注入是常见注入手法，部分杀软会报毒；
- **请合法使用**：仅对你有权操作的软件使用（如插件、MOD、调试、内部工具等场景），详见 [SECURITY.md](SECURITY.md)。

## License

[MIT](LICENSE) © 2026 [isTurn](https://github.com/isTurn)
