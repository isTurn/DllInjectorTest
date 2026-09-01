# 参与贡献

欢迎为本项目贡献力量！无论是提交 Bug、提出新特性，还是提交代码，都非常感谢。

## 环境准备

- [.NET 8 SDK](https://dotnet.microsoft.com/)（构建注入器）
- Visual Studio 2022 + MSVC 工具集（可选，仅编译 `test/` 下的 C 测试程序时需要）

## 本地构建

```bat
build.bat
```

## 提交流程

1. Fork 本仓库并创建特性分支：`git checkout -b feature/my-feature`
2. 修改代码后本地构建验证：`build.bat`
3. 提交并推送，然后创建 Pull Request（参考 `.github/PULL_REQUEST_TEMPLATE.md`）
4. 等待 Review

## 代码风格

- 遵循 `.editorconfig`（UTF-8、4 空格缩进）
- C# 代码保持与现有 `Program.cs` 风格一致（区域注释、命名清晰）
- 提交信息使用简洁的祈使句，如 `Add xxx` / `Fix yyy`

## 测试建议

`test/` 目录提供了示例 DLL 与目标程序源码（C 语言，MSVC 编译），可用来端到端验证注入功能。测试 DLL 会在目标进程内写入标记文件以证明 `DllMain` 被调用。
