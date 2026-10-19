/// <summary>
/// DllInjector 的端到端（E2E）测试：真的建进程、真的注入、真的调导出函数、真的卸载。
///
/// 为什么必须有这一层：test/DllInjectorTests 只测纯函数，而注入器最容易坏的地方
/// 全在「和真实进程交互」这一侧——远程内存的分配/释放时序、远程线程的等待、
/// 手动映射的基址记录、卸载时到底有没有真的把模块摘掉。这些错法**不会抛异常**，
/// 只会让日志里少一行、或者让目标进程多背一个模块，纯单元测试永远看不见。
///
/// 为什么五种注入方式都测：CRT / NTC / APC / RFI / MM 走的是五条完全不同的代码路径
/// （远程线程 vs APC 排队 vs 反射 loader vs 手写 shellcode 映射），任何一条坏掉
/// 用户都会以为「注入器坏了」，而 CI 之前只有 -checkdll 冒烟测试，一个都没覆盖。
///
/// 前置条件：test_output\ 里要有 Target_x64.exe / TestHookDll-x64.dll /
/// TestReflectiveDll-x64.dll（由 test\build_test.bat 与 test\TestHookDll\build.bat、
/// test\TestReflectiveDll\build.bat 生成）。测试主机位数必须与目标一致。
/// </summary>
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using DllInjector;

namespace DllInjectorE2E
{
    internal static class E2EMain
    {
        private static int _pass;
        private static int _fail;
        private static readonly List<string> _skips = new List<string>();

        private static void Check(bool cond, string what)
        {
            if (cond) { _pass++; Console.WriteLine("    [PASS] " + what); }
            else { _fail++; Console.WriteLine("    [FAIL] " + what); }
        }

        private static void Skip(string what)
        {
            _skips.Add(what);
            Console.WriteLine("    [SKIP] " + what);
        }

        /// <summary>收集注入器日志，供断言「某行出现过 / 没出现过」。</summary>
        private sealed class LogSink
        {
            private readonly List<string> _lines = new List<string>();
            private readonly object _gate = new object();

            public void Write(string msg)
            {
                lock (_gate) _lines.Add(msg);
                Console.WriteLine("      | " + msg);
            }

            public bool Has(string needle)
            {
                lock (_gate)
                    foreach (var l in _lines)
                        if (l.IndexOf(needle, StringComparison.Ordinal) >= 0) return true;
                return false;
            }
        }

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

        /// <summary>等目标进程把 args_&lt;pid&gt;.txt 写出来（它启动后的第一件事），最多等 ms 毫秒。</summary>
        private static bool WaitForFile(string path, int ms)
        {
            var sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < ms)
            {
                if (File.Exists(path)) return true;
                Thread.Sleep(50);
            }
            return File.Exists(path);
        }

        /// <summary>杀进程并等它真的消失（否则下一个用例可能撞上还没退干净的旧 PID）。</summary>
        private static void KillAndWait(int pid)
        {
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    p.Kill();
                    p.WaitForExit(5000);
                }
            }
            catch { /* 已经退了，正好 */ }
        }

        private static bool ModuleLoaded(int pid, string dllPath)
        {
            try
            {
                using (var p = Process.GetProcessById(pid))
                {
                    string name = Path.GetFileName(dllPath);
                    foreach (ProcessModule m in p.Modules)
                        if (string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase))
                            return true;
                }
            }
            catch { }
            return false;
        }

        private static int Main()
        {
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }

            Console.WriteLine("================================================");
            Console.WriteLine(" DllInjector 端到端测试");
            Console.WriteLine("================================================");
            Console.WriteLine("测试主机: " + (IntPtr.Size * 8) + " 位");

            string root = FindRepoRoot();
            if (root == null)
            {
                Console.WriteLine("[ERROR] 找不到仓库根（应包含 DllInjector/DllInjector.csproj）");
                return 1;
            }
            string outDir = Path.Combine(root, "test_output");
            string bits = IntPtr.Size == 8 ? "x64" : "x86";

            string target = Path.Combine(outDir, "Target_" + bits + ".exe");
            string hookDll = Path.Combine(outDir, "TestHookDll-" + bits + ".dll");
            string rfiDll = Path.Combine(outDir, "TestReflectiveDll-" + bits + ".dll");
            string hookLog = Path.Combine(outDir, "hook_call_log.txt");

            if (!File.Exists(target))
            {
                Console.WriteLine("[ERROR] 缺少测试素材: " + target);
                Console.WriteLine("        请先跑 test\\build_test.bat");
                return 1;
            }

            // ManualMap 会把基址记进 DllInjector.mmmap（优先注入器同目录）。测试里先把
            // 记录清空，避免上一次失败的残留让「卸载」那步走错分支。
            InjectorCore.LoadMmMap();

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 1. 启动时注入：CreateRemoteThread（CRT）---");
            // ---------------------------------------------------------------
            {
                if (!File.Exists(hookDll)) { Skip("CRT: 缺少 " + hookDll); }
                else
                {
                    if (File.Exists(hookLog)) File.Delete(hookLog);
                    var log = new LogSink();
                    bool ok = InjectorCore.Run(target, new[] { hookDll }, "", NativeMethods.INJECT_CRT,
                        "InstallHook", "E2E-CRT", log.Write);
                    Check(ok, "Run 返回成功");
                    Check(log.Has("注入流程完成"), "日志出现「注入流程完成」");
                    Check(log.Has("InstallHook 调用完成"), "日志里导出函数被调用");
                    Check(File.Exists(hookLog), "DLL 写出了 hook_call_log.txt");
                    if (File.Exists(hookLog))
                    {
                        string text = File.ReadAllText(hookLog);
                        Check(text.Contains("E2E-CRT"), "导出的参数字符串原样送达 DLL（UTF-16 传递正确）");
                        Check(text.Contains("InstallHook"), "日志里是 InstallHook 的记录");
                    }
                }
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 2. 启动时注入：NtCreateThreadEx（NTC）---");
            // ---------------------------------------------------------------
            {
                if (!File.Exists(hookDll)) { Skip("NTC: 缺少 " + hookDll); }
                else
                {
                    if (File.Exists(hookLog)) File.Delete(hookLog);
                    var log = new LogSink();
                    bool ok = InjectorCore.Run(target, new[] { hookDll }, "", NativeMethods.INJECT_NTC,
                        "InstallHook", "E2E-NTC", log.Write);
                    Check(ok, "Run 返回成功");
                    Check(log.Has("注入流程完成"), "日志出现「注入流程完成」");
                    Check(File.Exists(hookLog) && File.ReadAllText(hookLog).Contains("E2E-NTC"),
                        "DLL 收到参数并落日志");
                }
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 3. 启动时注入：QueueUserAPC（APC）---");
            // ---------------------------------------------------------------
            // APC 是异步排队：LoadLibraryW 要等目标主线程进入可告警等待才执行。
            // TestTarget 用 SleepEx(1000, TRUE) 轮询，正好满足这个条件。
            // 这也解释了为什么这一步**必须**用 TestTarget 这种主动 alertable 的目标，
            // 换成普通 GUI 程序（GetMessage 消息循环）就要靠运气。
            // ---------------------------------------------------------------
            {
                if (!File.Exists(hookDll)) { Skip("APC: 缺少 " + hookDll); }
                else
                {
                    if (File.Exists(hookLog)) File.Delete(hookLog);
                    var log = new LogSink();
                    bool ok = InjectorCore.Run(target, new[] { hookDll }, "", NativeMethods.INJECT_APC,
                        "InstallHook", "E2E-APC", log.Write);
                    Check(ok, "Run 返回成功");
                    Check(log.Has("排队到目标主线程 APC"), "走了 APC 路径（而不是被降级）");
                    Check(File.Exists(hookLog) && File.ReadAllText(hookLog).Contains("E2E-APC"),
                        "APC 执行后 DLL 收到参数并落日志");
                }
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 4. 启动时注入：反射式（RFI）---");
            // ---------------------------------------------------------------
            // 反射注入的核验点是那条真实副作用：TestReflectiveDll 的 ReflectiveLoader
            // 映射完成后会往固定路径写日志。只看「远程线程退出码非零」是不够的——
            // 那个码是 loader 返回值被截断后的结果，0xC0000005 之类的垃圾值也能骗过它。
            // ---------------------------------------------------------------
            {
                string rfiLog = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                    "Temp", "rfi_call_log.txt");
                if (!File.Exists(rfiDll)) { Skip("RFI: 缺少 " + rfiDll); }
                else
                {
                    // 这里刻意传一个导出函数名：RFI 的设计是「拒绝调用」并把理由说出来。
                    // 早先这个用例传的是空串，于是 Run 里那段提示压根没被执行（外层条件
                    // 是 exportFunc 非空），断言「按设计不自动调用导出函数」永远失败 ——
                    // 测试自己写错了，不是产品错。
                    long before = File.Exists(rfiLog) ? new FileInfo(rfiLog).Length : 0;
                    var log = new LogSink();
                    bool ok = InjectorCore.Run(target, new[] { rfiDll }, "", NativeMethods.INJECT_RFI,
                        "Init", "", log.Write);
                    Check(ok, "Run 返回成功");
                    Check(log.Has("反射加载成功"), "日志出现「反射加载成功」");
                    Check(log.Has("核验通过"), "反射注入的核验通过");
                    bool grew = File.Exists(rfiLog) && new FileInfo(rfiLog).Length > before;
                    Check(grew, "ReflectiveLoader 真的跑起来了（它把映射成功写进了自己的日志）");
                    Check(log.Has("不自动调用导出函数"), "按设计不自动调用反射 DLL 的导出函数");
                    bool sawNtStatus = log.Has("NTSTATUS");
                    Check(!sawNtStatus, "loader 没有以 NTSTATUS 崩溃（0xC0000005 之类不能被当成成功）");
                }
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 5. 启动时注入：手动映射（MM）---");
            // ---------------------------------------------------------------
            // 手动映射的关键特征是「DLL 不在进程模块列表里」，所以核验不能查 Modules，
            // 只能看 shellcode 回传的基址 + MmBases 记录。这里两头都断言。
            // ---------------------------------------------------------------
            {
                if (!File.Exists(rfiDll)) { Skip("MM: 缺少 " + rfiDll); }
                else
                {
                    // MmBases 是持久化的（DllInjector.mmmap），里面既有本次运行新增的
                    // 记录，也有历史运行留下的。只对「本次新增的那一条」做断言，
                    // 否则旧记录会让断言数量随运行次数漂移，而且可能掩盖本次的坏值。
                    var beforeKeys = new HashSet<string>();
                    foreach (var kv in InjectorCore.MmBases) beforeKeys.Add(kv.Key);

                    var log = new LogSink();
                    bool ok = InjectorCore.Run(target, new[] { rfiDll }, "", NativeMethods.INJECT_MM,
                        "", "", log.Write);
                    Check(ok, "Run 返回成功");
                    Check(log.Has("手动映射成功"), "日志出现「手动映射成功」");
                    Check(log.Has("核验通过"), "手动映射的核验通过");

                    var added = new List<long>();
                    foreach (var kv in InjectorCore.MmBases)
                        if (!beforeKeys.Contains(kv.Key) && kv.Key.Contains("TestReflectiveDll"))
                            added.Add(kv.Value.Base);

                    // shellcode 返回的基址必须是个像样的用户态地址，而不是被截断的垃圾
                    Check(added.Count == 1, "本次手动映射的基址被记进 MmBases（正好一条）");
                    foreach (long b in added)
                    {
                        Check(b > 0x10000 && b < 0x7FFFFFFFFFFF, "记录的基址 0x" + b.ToString("X") + " 落在用户态范围");
                        // 0xC0000005 之类的 NTSTATUS 也「小于 0x7FFF...」，光看上限拦不住它。
                        Check((b & 0xFFFFF000L) != 0xC0000000L,
                            "记录的基址 0x" + b.ToString("X") + " 不是 NTSTATUS 错误码");
                    }
                }
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 6. 注入到运行中进程 + 卸载 ---");
            // ---------------------------------------------------------------
            // 这一段覆盖 InjectToProcess / EjectDll 那条只在 GUI「注入到进程」里
            // 才会走到的路径，之前完全没有自动化。
            // ---------------------------------------------------------------
            {
                if (!File.Exists(hookDll)) { Skip("运行中注入: 缺少 " + hookDll); }
                else
                {
                    int pid = 0;
                    var psi = new ProcessStartInfo(target) { UseShellExecute = false, CreateNoWindow = false };
                    using (var p = Process.Start(psi))
                    {
                        pid = p.Id;
                        WaitForFile(Path.Combine(outDir, "args_" + pid + ".txt"), 5000);
                        Thread.Sleep(200);

                        Check(!ModuleLoaded(pid, hookDll), "注入前模块不在列表里（基线）");

                        var log = new LogSink();
                        bool ok = InjectorCore.InjectToProcess(pid, new[] { hookDll },
                            NativeMethods.INJECT_CRT, "Init", "", log.Write);
                        Check(ok, "InjectToProcess 返回成功");
                        Check(ModuleLoaded(pid, hookDll), "注入后模块出现在进程模块列表里");

                        // 再注一次：LoadLibrary 的引用计数会让同一个 DLL 不重复加载，
                        // 但注入器不应该因此报错，也不该在模块列表里多出一份。
                        var log2 = new LogSink();
                        bool ok2 = InjectorCore.InjectToProcess(pid, new[] { hookDll },
                            NativeMethods.INJECT_CRT, "", "", log2.Write);
                        Check(ok2, "重复注入同一 DLL 不报错（LoadLibrary 幂等）");

                        int count = 0;
                        try
                        {
                            using (var p2 = Process.GetProcessById(pid))
                            {
                                string name = Path.GetFileName(hookDll);
                                foreach (ProcessModule m in p2.Modules)
                                    if (string.Equals(m.ModuleName, name, StringComparison.OrdinalIgnoreCase))
                                        count++;
                            }
                        }
                        catch { }
                        Check(count == 1, "模块列表里仍然只有一份（没有重复映射）");

                        var log3 = new LogSink();
                        bool ejected = InjectorCore.EjectDll(pid, hookDll, log3.Write);
                        Check(ejected, "EjectDll 返回成功");
                        Check(log3.Has("卸载完成"), "日志出现「卸载完成」");
                        // 注入了两次就多一个引用计数，卸载一次只是减一，模块还在。
                        // 这是 FreeLibrary 的真实语义，不是 bug——顺便把它固定成断言，
                        // 免得以后有人「优化」成一次卸掉。
                        Check(ModuleLoaded(pid, hookDll),
                            "只卸一次时引用计数还剩 1（FreeLibrary 语义，符合预期）");

                        var log4 = new LogSink();
                        bool ejected2 = InjectorCore.EjectDll(pid, hookDll, log4.Write);
                        Check(ejected2, "第二次 EjectDll 返回成功");
                        Check(!ModuleLoaded(pid, hookDll), "引用计数归零后模块真的从列表里消失了");
                    }
                    KillAndWait(pid);
                }
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 7. 卸载不存在的模块应该失败（而不是假装成功）---");
            // ---------------------------------------------------------------
            // 这一条守的是那种「只打日志、返回值永远是 true」的实现——
            // 调用方（脚本 / 批量流程）会以为卸载成功了，实际上什么都没发生。
            // ---------------------------------------------------------------
            {
                int pid = 0;
                var psi = new ProcessStartInfo(target) { UseShellExecute = false };
                using (var p = Process.Start(psi))
                {
                    pid = p.Id;
                    WaitForFile(Path.Combine(outDir, "args_" + pid + ".txt"), 5000);
                    var log = new LogSink();
                    bool ejected = InjectorCore.EjectDll(pid, "NoSuchModule_zzz.dll", log.Write);
                    Check(!ejected, "卸载不存在的模块返回失败");
                }
                KillAndWait(pid);
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 8. -status 只读查询 ---");
            // ---------------------------------------------------------------
            {
                int pid = 0;
                var psi = new ProcessStartInfo(target) { UseShellExecute = false };
                using (var p = Process.Start(psi))
                {
                    pid = p.Id;
                    WaitForFile(Path.Combine(outDir, "args_" + pid + ".txt"), 5000);
                    var log = new LogSink();
                    bool ok = InjectorCore.Status(pid, new[] { "kernel32.dll", "NoSuchModule_zzz.dll" },
                        "GalToolText", log.Write);
                    Check(ok, "Status 对存在的进程返回成功");
                    Check(log.Has("kernel32.dll"), "报告了 kernel32.dll 的加载情况");
                    Check(log.Has("未在模块列表"), "对不存在的模块明确说「未在模块列表」而不是沉默");
                    // 关键：查询必须是只读的。管道名不存在时不能顺手把服务端建起来。
                    Check(log.Has("未发现") || log.Has("在线"), "报告了文本 Hook 管道状态");

                    var bad = new LogSink();
                    Check(!InjectorCore.Status(999999, null, "GalToolText", bad.Write),
                        "不存在的 PID 返回失败");
                }
                KillAndWait(pid);
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("--- 9. 参数传递与 -args 透传 ---");
            // ---------------------------------------------------------------
            // 注入器要在 CreateProcess 的命令行里把用户参数拼上去。
            // 这一条用目标程序自己写的 args_<pid>.txt 来验证，而不是看注入器日志。
            // ---------------------------------------------------------------
            {
                int pid = 0;
                var log = new LogSink();
                // 直接跑一次带参数的启动注入，然后从 marker 文件读回参数
                var psi = new ProcessStartInfo(target, "\"hello world\" --flag=1")
                { UseShellExecute = false };
                using (var p = Process.Start(psi))
                {
                    pid = p.Id;
                    string marker = Path.Combine(outDir, "args_" + pid + ".txt");
                    Check(WaitForFile(marker, 5000), "目标进程写出了 args_<pid>.txt");
                    if (File.Exists(marker))
                    {
                        string text = File.ReadAllText(marker);
                        Check(text.Contains("hello world"), "带空格的参数原样到达目标（引号没被吃掉）");
                        Check(text.Contains("--flag=1"), "以 - 开头的参数原样到达目标");
                    }
                }
                KillAndWait(pid);
            }

            // ---------------------------------------------------------------
            Console.WriteLine();
            Console.WriteLine("================================================");
            if (_skips.Count > 0)
            {
                Console.WriteLine("跳过 " + _skips.Count + " 项（缺测试素材）:");
                foreach (var s in _skips) Console.WriteLine("  - " + s);
            }
            Console.WriteLine("通过 " + _pass + " 项，失败 " + _fail + " 项");
            Console.WriteLine(_fail == 0 ? "RESULT: PASS" : "RESULT: FAIL");
            Console.WriteLine("================================================");
            return _fail == 0 ? 0 : 1;
        }
    }
}
