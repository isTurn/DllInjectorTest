# Changelog

本项目所有重要变更都会记录在此文件中。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [1.0.0] - 2026-09-01

### 新增
- 图形界面（WinForms）：选择目标 exe 与 dll，一键「注入并启动」
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
