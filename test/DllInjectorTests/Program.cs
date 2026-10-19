/// <summary>
/// DllInjector 的纯逻辑回归测试。
///
/// 为什么用控制台程序而不是 xUnit / NUnit：本项目的硬约定是**零第三方依赖**
/// （全部源码在 DllInjector/Program.cs，不引入 NuGet）。引入测试框架会破坏这条
/// 约定，而这里要测的都是「输入 → 输出」的纯函数，一个几十行的断言工具足够了。
///
/// 覆盖对象是那些**错了不会崩、但会静默给出错误结果**的逻辑：
///   - PE 位数 / 导出表解析（错了就会注入到位数不符的进程，或调不到导出函数）
///   - DLL 路径分隔（错了就少注入一个 DLL）
///   - -method 解析（错了就静默退回 CRT，用户以为用的是 MM）
///   - 进程名通配（错了就批量注入到不该注入的进程）
/// 这些都是「看起来正常、实际不对」的典型位置，也正是单元测试最划算的地方。
/// </summary>
using System;
using System.IO;

namespace DllInjectorTests
{
    internal static class TestMain
    {
        private static int _pass;
        private static int _fail;

        private static void Check(bool cond, string what)
        {
            if (cond) { _pass++; Console.WriteLine("    [PASS] " + what); }
            else { _fail++; Console.WriteLine("    [FAIL] " + what); }
        }

        private static void CheckEq<T>(T actual, T expected, string what)
        {
            bool ok = Equals(actual, expected);
            Check(ok, what);
            if (!ok) Console.WriteLine($"           期望 {expected}，实际 {actual}");
        }

        /// <summary>从测试程序所在目录向上找到仓库根（含 DllInjector/DllInjector.csproj）</summary>
        private static string FindRepoRoot()
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir != null)
            {
                if (File.Exists(Path.Combine(dir.FullName, "DllInjector", "DllInjector.csproj")))
                    return dir.FullName;
                dir = dir.Parent;
            }
            return null;
        }

        private static int Main()
        {
            // 与 test\ 下那些 C 程序保持一致：直接输出 UTF-8 字节。
            // 不设的话 Console 会按控制台 OEM 代码页（中文 Windows 是 936）编码，
            // 于是在 UTF-8 终端里看是一堆乱码，和 C 测试的输出风格也对不上。
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

            Console.WriteLine("DllInjectorTests — DllInjector 纯逻辑回归测试");
            Console.WriteLine("================================================");

            string root = FindRepoRoot();
            if (root == null)
            {
                Console.WriteLine("[ERROR] 找不到仓库根（应包含 DllInjector/DllInjector.csproj）");
                return 1;
            }
            Console.WriteLine("仓库根: " + root);

            // ---- 1. DLL 路径分隔 ------------------------------------------------
            Console.WriteLine("\n  --- SplitDlls（DLL 输入框的分隔规则）---");
            CheckEq(DllInjector.InjectorCore.SplitDlls("a.dll;b.dll").Length, 2, "分号分隔");
            CheckEq(DllInjector.InjectorCore.SplitDlls("a.dll|b.dll").Length, 2, "竖线分隔");
            CheckEq(DllInjector.InjectorCore.SplitDlls("a.dll\nb.dll\r\nc.dll").Length, 3, "换行分隔");
            CheckEq(DllInjector.InjectorCore.SplitDlls("  a.dll  ;  b.dll  ").Length, 2, "去掉首尾空白");
            CheckEq(DllInjector.InjectorCore.SplitDlls("\"C:\\x y\\a.dll\";b.dll")[0], @"C:\x y\a.dll",
                    "去掉包裹的引号（路径含空格）");
            CheckEq(DllInjector.InjectorCore.SplitDlls("").Length, 0, "空串得到空数组");
            CheckEq(DllInjector.InjectorCore.SplitDlls("   ").Length, 0, "全空白得到空数组");
            CheckEq(DllInjector.InjectorCore.SplitDlls("a.dll;;b.dll").Length, 2, "连续分隔符不产生空项");

            // ---- 2. -method 解析 -------------------------------------------------
            Console.WriteLine("\n  --- ParseMethod（CLI -method）---");
            CheckEq(DllInjector.Program.ParseMethod("crt"), DllInjector.NativeMethods.INJECT_CRT, "crt");
            CheckEq(DllInjector.Program.ParseMethod("ntc"), DllInjector.NativeMethods.INJECT_NTC, "ntc");
            CheckEq(DllInjector.Program.ParseMethod("apc"), DllInjector.NativeMethods.INJECT_APC, "apc");
            CheckEq(DllInjector.Program.ParseMethod("rfi"), DllInjector.NativeMethods.INJECT_RFI, "rfi");
            CheckEq(DllInjector.Program.ParseMethod("reflect"), DllInjector.NativeMethods.INJECT_RFI, "reflect 别名");
            CheckEq(DllInjector.Program.ParseMethod("reflective"), DllInjector.NativeMethods.INJECT_RFI, "reflective 别名");
            CheckEq(DllInjector.Program.ParseMethod("mm"), DllInjector.NativeMethods.INJECT_MM, "mm");
            CheckEq(DllInjector.Program.ParseMethod("manualmap"), DllInjector.NativeMethods.INJECT_MM, "manualmap 别名");
            CheckEq(DllInjector.Program.ParseMethod("manual-map"), DllInjector.NativeMethods.INJECT_MM, "manual-map 别名");
            CheckEq(DllInjector.Program.ParseMethod("MM"), DllInjector.NativeMethods.INJECT_MM, "大小写不敏感");
            CheckEq(DllInjector.Program.ParseMethod("不认识的东西"), DllInjector.NativeMethods.INJECT_CRT, "未知值退回 crt");
            CheckEq(DllInjector.Program.ParseMethod(""), DllInjector.NativeMethods.INJECT_CRT, "空串退回 crt");

            // ---- 3. 进程名通配 ---------------------------------------------------
            Console.WriteLine("\n  --- WildcardMatch（-injectname）---");
            Check(DllInjector.Program.WildcardMatch("notepad", "notepad"), "完全匹配");
            Check(DllInjector.Program.WildcardMatch("NOTEpad", "notepad"), "大小写不敏感");
            Check(DllInjector.Program.WildcardMatch("note*", "notepad"), "* 前缀匹配");
            Check(DllInjector.Program.WildcardMatch("*pad", "notepad"), "* 后缀匹配");
            Check(DllInjector.Program.WildcardMatch("note?ad", "notepad"), "? 匹配单个字符");
            Check(!DllInjector.Program.WildcardMatch("note?ad", "notead"), "? 不能匹配零个字符");
            Check(!DllInjector.Program.WildcardMatch("notepad", "notepad2"), "完全匹配不能吃掉多余字符");
            // 正则元字符必须被转义：否则 "a.b" 会把 "axb" 也匹配上
            Check(!DllInjector.Program.WildcardMatch("a.b", "axb"), "点号按字面匹配（正则元字符已转义）");
            Check(DllInjector.Program.WildcardMatch("a.b", "a.b"), "点号匹配自身");
            Check(!DllInjector.Program.WildcardMatch("a+b", "aab"), "加号按字面匹配");

            // ---- 4. PE 位数 ------------------------------------------------------
            Console.WriteLine("\n  --- PeHelper.GetExeBitness ---");
            string dll64 = Path.Combine(root, "test", "TestHookDll", "TestHookDll-x64.dll");
            string dll32 = Path.Combine(root, "test", "TestHookDll", "TestHookDll-x86.dll");
            Check(File.Exists(dll64), "测试素材存在: TestHookDll-x64.dll");
            Check(File.Exists(dll32), "测试素材存在: TestHookDll-x86.dll");
            CheckEq(DllInjector.PeHelper.GetExeBitness(dll64), 64, "x64 DLL 识别为 64");
            CheckEq(DllInjector.PeHelper.GetExeBitness(dll32), 32, "x86 DLL 识别为 32");
            CheckEq(DllInjector.PeHelper.GetExeBitness(Path.Combine(root, "README.md")), 0,
                    "非 PE 文件返回 0（不抛异常）");
            CheckEq(DllInjector.PeHelper.GetExeBitness(Path.Combine(root, "不存在.dll")), 0,
                    "不存在的文件返回 0（不抛异常）");

            // ---- 5. 导出表解析 ---------------------------------------------------
            Console.WriteLine("\n  --- PeHelper.GetExportRva ---");
            foreach (var fn in new[] { "Init", "InstallHook", "InstallConfig", "InstallMulti" })
            {
                long rva = DllInjector.PeHelper.GetExportRva(dll64, fn);
                Check(rva > 0, $"x64 能解析导出 {fn} 的 RVA（{rva}）");
            }
            CheckEq(DllInjector.PeHelper.GetExportRva(dll64, "NoSuchExport"), -1L,
                    "不存在的导出返回 -1");
            Check(DllInjector.PeHelper.GetExportRva(dll32, "InstallConfig") > 0,
                    "x86 也能解析 InstallConfig（.def 保证无修饰名）");

            // ---- 6. PE 体检 ------------------------------------------------------
            Console.WriteLine("\n  --- PeHelper.InspectDll ---");
            var insp64 = DllInjector.PeHelper.InspectDll(dll64);
            Check(insp64.IsValidPe, "x64 DLL 是有效 PE");
            CheckEq(insp64.Bitness, 64, "x64 DLL 体检位数 = 64");
            Check(insp64.IsDll, "x64 DLL 有 DLL 标志");
            Check(insp64.HasExportTable, "x64 DLL 有导出表");
            CheckEq(insp64.ExportCount, 4, "x64 DLL 导出函数个数 = 4");
            Check(insp64.HasExecSection, "x64 DLL 有可执行段");
            Check(insp64.FileSize > 0, "x64 DLL 文件大小可读");

            var inspBad = DllInjector.PeHelper.InspectDll(Path.Combine(root, "README.md"));
            Check(!inspBad.IsValidPe, "非 PE 文件体检判定为无效");
            Check(!string.IsNullOrEmpty(inspBad.Detail), "无效文件给出原因说明");

            // ---- 7. 配置读写（ConfigStore）---------------------------------------
            // 这几条覆盖的是「存了但读不回来」「写坏配置文件」这类静默故障：
            // 用户不会看到任何报错，只会觉得「上次选的东西又没了」。
            Console.WriteLine("\n  --- ConfigStore（记忆上次选择）---");
            string cfgPath = DllInjector.ConfigStore.ConfigPath;
            Check(!string.IsNullOrEmpty(cfgPath), "能确定配置文件路径");
            if (!string.IsNullOrEmpty(cfgPath))
            {
                // 保存 → 读回。注意 ConfigStore 会把 exe/dll 之外的值也一起保留，
                // 所以这里顺带验证「不会把其它键冲掉」。
                DllInjector.ConfigStore.Save(@"C:\games\target.exe", @"C:\dll\hook.dll");
                DllInjector.ConfigStore.Load(out string exe1, out string dll1);
                CheckEq(exe1, @"C:\games\target.exe", "保存后能读回 exe");
                CheckEq(dll1, @"C:\dll\hook.dll", "保存后能读回 dll");

                DllInjector.ConfigStore.Method = DllInjector.NativeMethods.INJECT_MM;
                CheckEq(DllInjector.ConfigStore.Method, DllInjector.NativeMethods.INJECT_MM,
                        "注入方式能存能读（MM）");
                DllInjector.ConfigStore.WindowPos = "10,20,720,700";
                CheckEq(DllInjector.ConfigStore.WindowPos, "10,20,720,700", "窗口位置能存能读");

                // 再存一次 exe/dll，前一步写的 method / winpos 必须还在
                DllInjector.ConfigStore.Save(@"C:\games\other.exe", @"C:\dll\hook.dll");
                CheckEq(DllInjector.ConfigStore.Method, DllInjector.NativeMethods.INJECT_MM,
                        "保存 exe/dll 不会冲掉注入方式");
                CheckEq(DllInjector.ConfigStore.WindowPos, "10,20,720,700",
                        "保存 exe/dll 不会冲掉窗口位置");

                // 原子写：临时文件必须被清理干净，不能留在磁盘上
                Check(!File.Exists(cfgPath + ".tmp"), "原子写之后没有残留的 .tmp 文件");

                // 缓存不能把外部修改当成不存在：模拟用户手工编辑配置文件
                CheckEq(DllInjector.ConfigStore.Method, DllInjector.NativeMethods.INJECT_MM,
                        "读取时命中缓存（值仍然正确）");
                try
                {
                    File.WriteAllText(cfgPath, "method=2\nwinpos=5,6,700,600\n");
                    CheckEq(DllInjector.ConfigStore.Method, DllInjector.NativeMethods.INJECT_APC,
                            "外部编辑配置文件后能读到新值（缓存会失效）");
                    CheckEq(DllInjector.ConfigStore.WindowPos, "5,6,700,600",
                            "外部编辑后窗口位置同样读到新值");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("           （跳过外部编辑检查: " + ex.Message + "）");
                }

                // 非法 method 值不能把注入方式搞成越界值（会索引到下拉框之外）
                try
                {
                    File.WriteAllText(cfgPath, "method=99\n");
                    CheckEq(DllInjector.ConfigStore.Method, DllInjector.NativeMethods.INJECT_CRT,
                            "配置文件里的非法 method 退回 CRT（不会越界）");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("           （跳过非法值检查: " + ex.Message + "）");
                }

                try { File.Delete(cfgPath); } catch { }
            }

            // ---- 收尾 ------------------------------------------------------------
            Console.WriteLine("\n================================================");
            Console.WriteLine($"通过 {_pass} 项，失败 {_fail} 项");
            if (_fail == 0)
            {
                Console.WriteLine("RESULT: PASS");
                return 0;
            }
            Console.WriteLine("RESULT: FAIL");
            return 1;
        }
    }
}
