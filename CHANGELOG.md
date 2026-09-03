# Changelog

本项目所有重要变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 新增
- 注入到运行中进程：枚举当前进程列表（名称 + PID），选中后一键向正在运行的进程注入
- 卸载已注入 DLL：从运行中进程远程调用 FreeLibrary，形成「注入 / 卸载」闭环
- 命令行模式新增 `-injectpid <pid> <dll>` 与 `-eject <pid> <dll名>`
- 图形界面新增「刷新」按钮实时加载进程列表

### 修复
- 64 位进程卸载失败：远程线程退出码仅 32 位导致模块句柄截断，改为注入器侧枚举目标进程模块取得完整 64 位基址
- 「刷新」按钮点击时的空引用异常（对象未设置为对象实例）

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
