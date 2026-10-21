# 贡献指南（Contributing）

感谢你愿意为 **DLL 注入器** 出力。本文件说明如何搭建环境、修改代码、以及提交改动。

在动手前，请先阅读 [SECURITY.md](SECURITY.md) —— 本项目涉及进程注入，**只接受合法用途的贡献**（调试、插件 / MOD 开发、教学研究）。任何用于绕过授权、规避检测、攻击他人系统的改动都会被拒绝。

---

## 环境要求

| 用途 | 需要什么 |
| --- | --- |
| 编译注入器本体 | [.NET 8 SDK](https://dotnet.microsoft.com/download) |
| 编译 `test/` 下的 C/ASM 测试素材 | Visual Studio 2022（或 Build Tools），需勾选「使用 C++ 的桌面开发」工作负载 |
| 重新生成手动映射 shellcode | 上面的 VS + Python 3（`test/ManualMap/gen_shellcode.py`） |

> 构建脚本通过 `vswhere.exe` 自动定位 Visual Studio，**任意版本**（Community / Professional / Enterprise）与任意安装路径都可用，无需手工改路径。

## 构建

```bat
:: 构建注入器（x64 + x86 自包含单文件）
build.bat

:: 构建测试素材（测试 DLL + 目标程序）
test\build_test.bat

:: 重新生成手动映射 shellcode 字节数组
test\ManualMap\build_shellcode.bat
```

> 各 `build.bat` 开头都有一道**增量门**（共用 `test/_uptodate.bat`）：把自身输入清单算成
> 内容指纹（逐文件 SHA1 顺序拼接），和上次成功构建一致且产物都在，就打印
> `[SKIP] ... nothing to do.` 直接退出。改过输入、删过产物、或带 `--force` 才会真的重建。
> 因此重复跑全量回归不会反复重新编译没动过的东西。

`build.bat` 产物：

| 路径 | 说明 |
| --- | --- |
| `out\x64\DllInjector.exe` | 64 位注入器 |
| `out\x86\DllInjector.exe` | 32 位注入器 |
| `dist\DllInjector-x64.exe` | 与 Release 同名的 64 位副本 |
| `dist\DllInjector-x86.exe` | 与 Release 同名的 32 位副本 |

发布参数与 [`.github/workflows/build.yml`](.github/workflows/build.yml) **保持一致**。改动其中一处时，请同步另一处，否则本地构建与 CI 产物会出现差异。

## 目录职责

```
DllInjector/Program.cs       注入器全部源码（单文件，约 4200 行）
  ├─ NativeMethods           Win32 / ntdll P/Invoke 声明与常量
  ├─ PeHelper                PE 头解析：位数、导出表 RVA、注入前体检
  ├─ MainForm                WinForms 界面（手写 DPI 缩放布局）
  │   ├─ DllSortDialog       多 DLL 注入顺序拖拽排序
  │   └─ BatchInjectDialog   多进程批量注入勾选
  ├─ InjectorCore            注入核心（GUI 与 CLI 共用）
  ├─ AtomicFile              原子写文件（tmp + File.Replace，防写到一半被杀留下空文件）
  ├─ ConfigStore             配置持久化（记忆 exe/dll/注入方式/窗口位置）
  ├─ Theme                   暗色主题色板
  └─ Program                 入口：UAC 自提权 + CLI 模式分发

test/                        测试素材（源码 + 部分已编译产物）
  ├─ TestDll/                自测注入 DLL（写标记文件，宏区分多 DLL 变体）
  ├─ TestTarget/             自测目标程序（回显命令行参数）
  ├─ TestHookDll/            导出函数调用示例（InstallHook / Init / InstallConfig / InstallMulti）
  ├─ TestReflectiveDll/      自包含反射加载器示例
  ├─ ManualMap/              手动映射 / 卸载 shellcode（.asm 源码 + 生成脚本）
  ├─ TextHookDll/            GalGame 文本 Hook（IAT Hook + 管道推送 + 进程内端到端验证）
  ├─ DllInjectorTests/       C# 纯逻辑回归测试（链接 Program.cs 编译，自带断言）
  └─ DllInjectorE2E/         注入器端到端测试（真的建进程 / 注入 / 调导出 / 卸载，双架构）

tools/git-api-sync.py        受限网络下用 GitHub Git Data API 推拉（github.com 不通时用）

docs/index.html              GitHub Pages 展示页
```

## 代码约定

本项目**刻意保持单文件、零第三方依赖**——请不要引入 NuGet 包或拆分文件，除非在 Issue 中先达成共识。

1. **目标框架**：`net8.0-windows`，WinForms。`Nullable` 与 `ImplicitUsings` 按现有 `csproj` 设置，不要改动。
2. **注释用中文**，与现有风格一致；关键分支要写清「为什么这么做」，而不只是「做了什么」。
3. **布局必须走 `LayoutAll()`**：界面全部手写坐标，基准是 96 DPI 逻辑值，统一经 `Scale()` 换算。**不要**使用 `AutoScaleMode`，也不要在控件上写死像素。
4. **日志统一走 `Action<string> log` 回调**，不要在 `InjectorCore` 里直接碰控件或 `Console`——CLI 与 GUI 共用同一套核心逻辑。
5. **错误信息要可诊断**：涉及 Win32 调用失败时附上 `NativeMethods.LastErrorText()`。
6. **退出码语义固定**：CLI `0` = 成功，`1` = 失败。不要引入其他退出码。
7. **`.bat` 脚本只用 ASCII 输出**：cmd.exe 按控制台代码页读取批处理文件，写入非 ASCII 文本会乱码。

## 新增一种注入方式

五种注入方式的实现都在 `InjectorCore.LoadLibraryIntoProcess` 中按 `method` 分派。新增一种需要同步改动以下位置：

1. `NativeMethods`：新增 `INJECT_XXX` 常量（**追加在末尾**，不要插队，否则会破坏 `ConfigStore` 里已记忆的方式编号）。
2. `InjectorCore.LoadLibraryIntoProcess`：新增分派分支，并明确 `remoteBuf` / `hRemoteThread` 的所有权与释放责任。
3. `InjectorCore.Run` 与 `InjectToProcess`：确认新方式是否支持「启动时注入」与「运行中进程」；若只支持其一，需像 `QueueUserAPC` 那样给出提示或自动降级。
4. `InjectorCore` 的注入核验段：说明该方式注入后模块是否会出现在目标进程模块列表，并给出对应的核验方式。
5. `MainForm.BuildUi`：`_cboMethod` 的 `Items` 追加同名项（**顺序必须与常量编号一致**）。
6. `Program.ParseMethod`：新增 CLI 别名。
7. 文档：`README.md`（功能特性 / 对比表 / 原理图 / CLI 用法）、`docs/index.html`、`CHANGELOG.md`。
8. `ConfigStore.Method` 的取值上限校验（当前是 `m <= 4`）。

## 提交前自检

- [ ] `build.bat` 能成功产出 x64 + x86 两个版本
- [ ] 若改动涉及注入逻辑，用 `test\build_test.bat` 的素材实测过，且 x64 / x86 **双架构都验证**
- [ ] `test\DllInjectorTests\build.bat` 通过（纯逻辑回归，改过 `Program.cs` 就该跑）
- [ ] 若改动涉及注入链路（`LoadLibraryIntoProcess` / `InjectToProcess` / 反射 / 手动映射 / 卸载），
      `test\DllInjectorE2E\build.bat` 与 `test\DllInjectorE2E\build.bat --x86` 都要通过 ——
      它真的建进程、真的注入、真的调导出、真的卸载，纯函数测试看不见这条链路
- [ ] 若改过 `test\ManualMap\*.asm`，跑过 `test\ManualMap\build_shellcode.bat`（会自动回填字节数组）
- [ ] 若改了 `test/` 下的构建脚本或 C 源码，留意增量门的输入清单（`_uptodate.bat check` 后面那串）——
      新增一个源文件却不加进清单，脚本会在源码变动后错误地跳过重建
- [ ] `README.md` / `docs/index.html` / `CHANGELOG.md` 中受影响的内容已同步更新
- [ ] 没有提交构建产物与运行时文件（`out/`、`dist/`、`bin/`、`obj/`、`test_output/`、`*.obj`、`inject_log.txt`、`DllInjector.config` 等，见 `.gitignore`）
- [ ] 没有为了「顺手」而重构无关代码（请让 PR 保持聚焦）

## 提交信息

参考 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/)：

```
feat: 新增 xxx 注入方式
fix: 修正 64 位进程卸载时模块句柄被截断
docs: 补充手动映射卸载的说明
build: 让 test/build_test.bat 自动定位 Visual Studio
refactor: 抽取 PreflightDlls 供 CLI 复用
```

## 提交 PR

1. 从 `main` 切出分支，命名如 `feat/manual-map-unload`、`fix/x64-eject`；
2. 按 [PR 模板](.github/PULL_REQUEST_TEMPLATE.md) 填写说明，**务必写清测试方式**；
3. 确认自检清单全部勾选。

## 版本与变更记录

- 版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)；
- 所有用户可见的改动都要写进 [`CHANGELOG.md`](CHANGELOG.md) 的 `[Unreleased]` 段，合并发布时再归入具体版本号；
- 打 `v*` 标签会触发 CI 自动构建并发布 Release。

## 遇到问题

- 使用问题、编译报错 → 提 [Issue](.github/ISSUE_TEMPLATE/bug_report.md)
- 安全相关问题 → **不要**开公开 Issue，走 [SECURITY.md](SECURITY.md) 里的私密通道
