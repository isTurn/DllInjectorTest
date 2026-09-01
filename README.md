# DLL 注入器（DLL Injector）

一个带图形界面的 Windows 工具：选择目标 exe 和要注入的 dll，点击「注入并启动」，工具会以挂起方式启动目标程序 → 把 DLL 注入进去 → 恢复运行。

## 文件说明

| 文件 | 说明 |
|---|---|
| `DllInjector-x64.exe` | 64 位版本（用于 64 位目标程序），通过 Releases 附件分发 |
| `DllInjector-x86.exe` | 32 位版本（用于 32 位目标程序），通过 Releases 附件分发 |
| `DllInjector/` | 源码工程（C# WinForms，可自行修改重新编译） |
| `test/` | 自测用的示例 DLL 与目标程序源码 |
| `build.bat` | 一键编译出 x64 / x86 两个版本的 EXE |

> 编译出的 EXE 为自包含单文件（约 130MB），无需安装 .NET 环境即可直接运行。

## 构建

需要 [.NET 8 SDK](https://dotnet.microsoft.com/)。

```
build.bat
```

输出：`out\x64\DllInjector.exe`（64 位）和 `out\x86\DllInjector.exe`（32 位）。

## 使用方法（图形界面）

1. 根据目标程序的位数选择对应版本：32 位程序用 32 位版本，64 位程序用 64 位版本。
2. 打开后：
   - 点击「目标程序」旁的「浏览...」选择要启动的 exe（也支持直接把文件拖进输入框）；
   - 点击「DLL 文件」旁的「浏览...」选择要注入的 dll；
   - 点击「注入并启动」。
3. 下方日志会显示每一步的结果（进程 PID、DLL 是否加载成功等）。

> 提示：文件选择对话框默认定位在**注入器 EXE 所在文件夹**，建议把目标 exe 和要注入的 dll 放到与注入器同一目录，选择起来更方便。

## 命令行模式（自动化/脚本）

```
DllInjector-x64.exe -inject <exe路径> <dll路径>
```

执行完毕后退出码：`0` = 注入成功，`1` = 失败（详情见同目录下 `inject_log.txt`）。

## 重要约束

- **位数必须一致**：DLL 必须与目标程序同为 32 位或 64 位，否则会拒绝注入。
- **DLL 必须是原生 DLL**（含 `DllMain` 的 C/C++ 编译产物）。托管 .NET DLL 无法通过这种方式执行代码。
- 注入原理为标准 `CreateProcess(CREATE_SUSPENDED)` + 远程内存写入 DLL 路径 + `CreateRemoteThread(LoadLibraryW)` + `ResumeThread`。部分杀毒软件可能对 `CreateRemoteThread` 注入行为报警。
- 请仅对你有权操作的软件使用本工具（如插件、MOD、调试、内部工具等场景）。
