using System;
using System.ComponentModel;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DllInjector
{
    /// <summary>Win32 API 声明</summary>
    internal static class NativeMethods
    {
        public const uint CREATE_SUSPENDED  = 0x00000004;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;
        public const uint MEM_COMMIT        = 0x1000;
        public const uint MEM_RESERVE       = 0x2000;
        public const uint MEM_RELEASE       = 0x8000;
        public const uint PAGE_READWRITE    = 0x04;
        public const uint PAGE_EXECUTE_READ = 0x20;
        public const uint PAGE_EXECUTE_READWRITE = 0x40;
        public const uint INFINITE          = 0xFFFFFFFF;
        public const uint WAIT_TIMEOUT      = 0x00000102;
        public const uint WAIT_FAILED       = 0xFFFFFFFF;

        // 进程访问权限
        public const uint PROCESS_CREATE_THREAD     = 0x0002;
        public const uint PROCESS_VM_OPERATION      = 0x0008;
        public const uint PROCESS_VM_READ           = 0x0010;
        public const uint PROCESS_VM_WRITE          = 0x0020;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        // 令牌权限
        public const uint TOKEN_QUERY               = 0x0008;
        public const uint TOKEN_ADJUST_PRIVILEGES   = 0x0020;
        public const uint SE_PRIVILEGE_ENABLED      = 0x00000002;
        public const uint ERROR_NOT_ALL_ASSIGNED    = 1300;   // AdjustTokenPrivileges 返回 true 但权限未生效

        /// <summary>注入 / 卸载所需的最小权限组合</summary>
        public const uint PROCESS_ACCESS_FOR_INJECT =
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

        // 注入方式
        public const int INJECT_CRT = 0;   // CreateRemoteThread（默认，兼容性最好）
        public const int INJECT_NTC = 1;   // NtCreateThreadEx（底层，隐蔽性较好）
        public const int INJECT_APC = 2;   // QueueUserAPC（仅启动时注入，需挂起主线程）
        public const int INJECT_RFI = 3;   // 反射式注入（Reflective）：按内存布局展开 DLL 映像并启动 ReflectiveLoader，由 DLL 自行完成 PE 映射
        public const int INJECT_MM = 4;    // 手动映射注入（Manual Map）：不调 LoadLibrary，由自包含 shellcode 在目标进程内自行解析 PE、映射节、重定位、填 IAT 并调 DllMain

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            public LUID Luid;
            public uint Attributes;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, UIntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);

        [DllImport("ntdll.dll")]
        public static extern int NtCreateThreadEx(
            out IntPtr threadHandle,
            uint desiredAccess,
            IntPtr objectAttributes,
            IntPtr processHandle,
            IntPtr startAddress,
            IntPtr parameter,
            bool createSuspended,
            uint stackZeroBits,
            uint sizeOfStackCommit,
            uint sizeOfStackReserve,
            IntPtr bytesBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UIntPtr dwData);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool WaitNamedPipe(string lpNamedPipeName, uint nTimeOut);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, uint bufferLength, IntPtr previousState, IntPtr returnLength);

        public static string LastErrorText()
        {
            int code = Marshal.GetLastWin32Error();
            return $"0x{code:X8} ({new Win32Exception(code).Message})";
        }
    }

    /// <summary>读取 PE 文件头判断可执行文件位数</summary>
    internal static class PeHelper
    {
        /// <summary>返回 32 / 64；无法识别返回 0。</summary>
        public static int GetExeBitness(string path)
        {
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var br = new BinaryReader(fs);
                if (br.ReadUInt16() != 0x5A4D) return 0;          // "MZ"
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = br.ReadInt32();
                fs.Seek(peOffset, SeekOrigin.Begin);
                if (br.ReadUInt32() != 0x00004550) return 0;       // "PE\0\0"
                ushort machine = br.ReadUInt16();
                if (machine == 0x014C) return 32;                  // IMAGE_FILE_MACHINE_I386
                if (machine == 0x8664) return 64;                  // IMAGE_FILE_MACHINE_AMD64
                return 0;
            }
            catch { return 0; }
        }

        /// <summary>读取 PE 导出表，返回指定导出函数的 RVA（相对模块基址）；未找到或解析失败返回 -1。</summary>
        public static long GetExportRva(string dllPath, string funcName)
        {
            try
            {
                using var fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var br = new BinaryReader(fs);
                if (br.ReadUInt16() != 0x5A4D) return -1;           // "MZ"
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = br.ReadInt32();
                fs.Seek(peOffset, SeekOrigin.Begin);
                if (br.ReadUInt32() != 0x00004550) return -1;       // "PE\0\0"
                br.ReadUInt16();                                    // Machine
                ushort numberOfSections = br.ReadUInt16();
                br.ReadUInt32();                                    // TimeDateStamp
                br.ReadUInt32();                                    // PointerToSymbolTable
                br.ReadUInt32();                                    // NumberOfSymbols
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                br.ReadUInt16();                                    // Characteristics

                long optStart = fs.Position;
                ushort magic = br.ReadUInt16();                     // 0x10B PE32 / 0x20B PE32+
                // DataDirectory 在 PE32 的 OptionalHeader 偏移 96 处，PE32+ 偏移 112 处
                int dataDirOffset = magic == 0x20B ? 112 : 96;
                fs.Seek(optStart + dataDirOffset, SeekOrigin.Begin);
                uint exportRva = br.ReadUInt32();                   // 导出表 RVA
                br.ReadUInt32();                                    // 导出表 Size
                if (exportRva == 0) return -1;

                // 读取节表，构建 RVA -> 文件偏移 映射
                long sectionStart = optStart + sizeOfOptionalHeader;
                var sections = new System.Collections.Generic.List<(uint va, uint rawPtr, uint rawSize)>();
                fs.Seek(sectionStart, SeekOrigin.Begin);
                for (int i = 0; i < numberOfSections; i++)
                {
                    br.ReadBytes(8);                                // Name
                    br.ReadUInt32();                                // VirtualSize
                    uint va = br.ReadUInt32();                      // VirtualAddress
                    uint rawSize = br.ReadUInt32();                 // SizeOfRawData
                    uint rawPtr = br.ReadUInt32();                  // PointerToRawData
                    br.ReadBytes(16);                               // 其余字段
                    sections.Add((va, rawPtr, rawSize));
                }

                long RvaToOffset(uint rva)
                {
                    foreach (var s in sections)
                        if (rva >= s.va && rva < s.va + s.rawSize)
                            return s.rawPtr + (rva - s.va);
                    return -1;
                }

                long exportOff = RvaToOffset(exportRva);
                if (exportOff < 0) return -1;
                fs.Seek(exportOff, SeekOrigin.Begin);
                br.ReadUInt32();                                    // Characteristics
                br.ReadUInt32();                                    // TimeDateStamp
                br.ReadUInt16(); br.ReadUInt16();                   // Major/MinorVersion
                br.ReadUInt32();                                    // Name
                br.ReadUInt32();                                    // Base
                br.ReadUInt32();                                    // NumberOfFunctions
                uint numberOfNames = br.ReadUInt32();
                uint addressOfFunctions = br.ReadUInt32();          // EAT
                uint addressOfNames = br.ReadUInt32();              // ENT
                uint addressOfNameOrdinals = br.ReadUInt32();       // EOT

                long namesOff = RvaToOffset(addressOfNames);
                long ordsOff = RvaToOffset(addressOfNameOrdinals);
                long funcsOff = RvaToOffset(addressOfFunctions);
                if (namesOff < 0 || ordsOff < 0 || funcsOff < 0) return -1;

                for (uint i = 0; i < numberOfNames; i++)
                {
                    fs.Seek(namesOff + i * 4, SeekOrigin.Begin);
                    long nameOff = RvaToOffset(br.ReadUInt32());
                    if (nameOff < 0) continue;
                    fs.Seek(nameOff, SeekOrigin.Begin);
                    string candidate = ReadAsciiZ(br);
                    if (candidate == funcName ||
                        candidate.StartsWith("_" + funcName + "@", StringComparison.Ordinal))
                    {
                        fs.Seek(ordsOff + i * 2, SeekOrigin.Begin);
                        ushort ordinal = br.ReadUInt16();
                        fs.Seek(funcsOff + ordinal * 4, SeekOrigin.Begin);
                        return br.ReadUInt32();                     // 导出函数 RVA
                    }
                }
                return -1;
            }
            catch { return -1; }
        }

        /// <summary>读取以 \0 结尾的 ASCII 字符串</summary>
        private static string ReadAsciiZ(BinaryReader br)
        {
            var sb = new StringBuilder();
            while (true)
            {
                byte b = br.ReadByte();
                if (b == 0) break;
                sb.Append((char)b);
            }
            return sb.ToString();
        }

        /// <summary>PE 体检结果：注入前预检 DLL，提前判断"能否注入"</summary>
        public sealed class PeInspect
        {
            public bool IsValidPe;      // 有效 MZ + PE 签名
            public int Bitness;         // 32 / 64 / 0（0 = 未知机器类型）
            public bool IsDll;          // Characteristics 含 IMAGE_FILE_DLL (0x2000)
            public bool HasExportTable; // 导出表存在（RVA != 0）
            public int ExportCount;     // 导出函数个数（按 EAT NumberOfFunctions，解析失败为 -1）
            public bool HasRelocSection;// 有 .reloc 重定位段（x64 必须；x86 可内联）
            public bool HasExecSection; // 有可执行段（IMAGE_SCN_MEM_EXECUTE 0x20000000）
            public long FileSize;
            public string Detail;       // 失败/异常说明
        }

        /// <summary>对 DLL 做注入前体检：结构完整性、位数、是否为 DLL、导出表、重定位、可执行段</summary>
        public static PeInspect InspectDll(string path)
        {
            var r = new PeInspect { FileSize = -1, ExportCount = -1 };
            try { r.FileSize = new FileInfo(path).Length; }
            catch { }
            try
            {
                using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var br = new BinaryReader(fs);
                if (br.ReadUInt16() != 0x5A4D) { r.Detail = "不是有效的 PE 文件（缺少 MZ 头）"; return r; }
                fs.Seek(0x3C, SeekOrigin.Begin);
                int peOffset = br.ReadInt32();
                fs.Seek(peOffset, SeekOrigin.Begin);
                if (br.ReadUInt32() != 0x00004550) { r.Detail = "缺少 PE 签名"; return r; }
                ushort machine = br.ReadUInt16();
                r.Bitness = machine == 0x014C ? 32 : machine == 0x8664 ? 64 : 0;
                ushort numberOfSections = br.ReadUInt16();
                br.ReadUInt32(); br.ReadUInt32(); br.ReadUInt32();
                ushort sizeOfOptionalHeader = br.ReadUInt16();
                ushort characteristics = br.ReadUInt16();
                r.IsDll = (characteristics & 0x2000) != 0;   // IMAGE_FILE_DLL
                if (r.Bitness == 0) { r.Detail = "未知的机器类型"; return r; }

                long optStart = fs.Position;
                ushort magic = br.ReadUInt16();              // 0x10B PE32 / 0x20B PE32+
                int dataDirOffset = magic == 0x20B ? 112 : 96;
                fs.Seek(optStart + dataDirOffset, SeekOrigin.Begin);
                uint exportRva = br.ReadUInt32();
                br.ReadUInt32();                             // 导出表 Size
                r.HasExportTable = exportRva != 0;

                // 节表：重定位段 + 可执行段 + RVA->文件偏移 映射（用于读导出数量）
                long sectionStart = optStart + sizeOfOptionalHeader;
                var sections = new System.Collections.Generic.List<(uint va, uint rawPtr, uint rawSize)>();
                fs.Seek(sectionStart, SeekOrigin.Begin);
                for (int i = 0; i < numberOfSections; i++)
                {
                    byte[] nameBytes = br.ReadBytes(8);
                    string secName = System.Text.Encoding.ASCII.GetString(nameBytes).TrimEnd('\0');
                    br.ReadUInt32();                         // VirtualSize
                    uint va = br.ReadUInt32();
                    uint rawSize = br.ReadUInt32();
                    uint rawPtr = br.ReadUInt32();
                    br.ReadBytes(12);
                    uint secChars = br.ReadUInt32();
                    sections.Add((va, rawPtr, rawSize));
                    if (secName == ".reloc") r.HasRelocSection = true;
                    if ((secChars & 0x20000000) != 0) r.HasExecSection = true;   // IMAGE_SCN_MEM_EXECUTE
                }

                long RvaToOffset(uint rva)
                {
                    foreach (var s in sections)
                        if (rva >= s.va && rva < s.va + s.rawSize)
                            return s.rawPtr + (rva - s.va);
                    return -1;
                }

                // 读取导出函数个数（EAT NumberOfFunctions）
                if (r.HasExportTable)
                {
                    long expOff = RvaToOffset(exportRva);
                    if (expOff >= 0)
                    {
                        fs.Seek(expOff + 20, SeekOrigin.Begin);   // Characteristics(4)+TimeDateStamp(4)+Major(2)+Minor(2)+Name(4)+Base(4)=20
                        r.ExportCount = br.ReadInt32();           // NumberOfFunctions
                    }
                }

                r.IsValidPe = true;
                if (string.IsNullOrEmpty(r.Detail)) r.Detail = "结构完整";
                return r;
            }
            catch (Exception ex)
            {
                r.Detail = "解析失败: " + ex.Message;
                return r;
            }
        }
    }

    public class MainForm : Form
    {
        private Label _lblExe, _lblDll, _tip, _lblLog;
        private TextBox _txtExe;
        private TextBox _txtDll;
        private Button _btnExe;
        private Button _btnDll;
        private Button _btnSort;   // DLL 排序按钮（多 DLL 时调整注入顺序）
        private Button _btnInject;
        private Label _lblProc;
        private ComboBox _cboProc;
        private Label _lblArgs;
        private TextBox _txtArgs;
        private Label _lblExport;
        private TextBox _txtExport;
        private Label _lblExportArg;
        private TextBox _txtExportArg;
        private Label _lblMethod;
        private ComboBox _cboMethod;
        private Button _btnRefresh;
        private Button _btnInjectProc;
        private Button _btnEject;
        private Button _btnBatch;   // 批量注入按钮（多进程勾选注入）
        private TextBox _log;

        // 96 DPI 逻辑布局基准值
        private const int PadLeft = 12;      // 左侧留白
        private const int LabelWidth = 112;  // 标签区宽度（足够容纳"目标程序:"/"DLL 文件:"）
        private const int BrowseWidth = 120; // 浏览按钮宽度
        private const int RowHeight = 34;

        // 窗口最小尺寸（96 DPI 逻辑值）。构造函数与 LayoutAll 必须用同一组常量：
        // 原先两处分别写死 (620,660) 和 (620,600)，实际生效的是后者的 600，
        // 构造函数里的 660 从来没起过作用，只会误导后来改布局的人。
        private const int MinWinW = 620;
        private const int MinWinH = 600;

        private float _scale = 1f;  // 当前 DPI 缩放系数（144 DPI 时为 1.5）
        private bool _layouting;    // 防重入

        public MainForm()
        {
            Text = "DLL 注入器";
            Font = new Font("Microsoft YaHei UI", 9F);
            // 关闭框架自动缩放（.NET 8 下对代码构建的窗体不会按 DPI 缩放），改为手动精确缩放
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(720, 700);
            MinimumSize = new Size(MinWinW, MinWinH);
            StartPosition = FormStartPosition.CenterScreen;

            BuildUi();
            ApplyTheme();
            LoadLastSelection();
            _cboMethod.SelectedIndex = ConfigStore.Method;   // 记忆上次注入方式
            Resize += (s, e) => LayoutAll();
            Log($"{"注入器已启动"}（{IntPtr.Size * 8} 位）。");
            Log("使用方式①：选择目标 exe 和 dll（多个用 ; 分隔），可填启动参数，点击\"注入并启动\"。");
            Log("使用方式②：在下方选择运行中的进程，点击\"注入到进程\"或\"卸载 DLL\"。");
            Log("注入方式：CreateRemoteThread / NtCreateThreadEx / QueueUserAPC（仅启动时）/ 反射式注入（需 DLL 自带 ReflectiveLoader）/ 手动映射注入（Manual Map，不调 LoadLibrary）。");
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            ApplyDpiScale();
            RestoreWindowPos();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // 记忆窗口位置（含边框的窗口矩形）
            try { ConfigStore.WindowPos = $"{Bounds.X},{Bounds.Y},{Bounds.Width},{Bounds.Height}"; } catch { }
            base.OnFormClosing(e);
        }

        /// <summary>恢复上次记忆的窗口位置（仅当位置仍落在某个屏幕内）</summary>
        private void RestoreWindowPos()
        {
            string wp = ConfigStore.WindowPos;
            if (string.IsNullOrEmpty(wp)) return;
            var parts = wp.Split(',');
            // 不再用 MinimumSize 做「太小就整份丢弃」的门槛。
            // 记忆值是**上一次运行那个 DPI 下**的像素尺寸，换到更高 DPI 的显示器上
            // 必然小于当前 MinimumSize（它已经被 ApplyDpiScale 放大过），
            // 按旧逻辑会把用户辛苦调好的位置和大小一起丢掉，直接回到屏幕居中。
            // 正确做法：只丢弃明显无效的值，尺寸交给下面的钳制步骤处理。
            if (parts.Length == 4 &&
                int.TryParse(parts[0], out int x) && int.TryParse(parts[1], out int y) &&
                int.TryParse(parts[2], out int w) && int.TryParse(parts[3], out int h) &&
                w > 0 && h > 0)
            {
                var rect = new Rectangle(x, y, w, h);
                bool visible = false;
                foreach (var s in Screen.AllScreens)
                    if (s.WorkingArea.IntersectsWith(rect)) { visible = true; break; }
                if (visible)
                {
                    // 限制窗口完整落在屏幕工作区内：防止异常记忆值（过大/越界）
                    // 导致窗口部分超出屏幕、内容不可见或无法访问。
                    var wa = Screen.FromRectangle(rect).WorkingArea;
                    int w2 = Math.Min(rect.Width, wa.Width);
                    int h2 = Math.Min(rect.Height, wa.Height);
                    // 下限钳到当前 DPI 下的最小尺寸，而不是丢弃整条记忆
                    w2 = Math.Max(w2, MinimumSize.Width);
                    h2 = Math.Max(h2, MinimumSize.Height);
                    w2 = Math.Min(w2, wa.Width);
                    h2 = Math.Min(h2, wa.Height);
                    int x2 = Math.Max(wa.X, Math.Min(rect.X, wa.Right - w2));
                    int y2 = Math.Max(wa.Y, Math.Min(rect.Y, wa.Bottom - h2));
                    StartPosition = FormStartPosition.Manual;
                    Bounds = new Rectangle(x2, y2, w2, h2);
                }
            }
        }

        protected override void OnDpiChanged(DpiChangedEventArgs e)
        {
            base.OnDpiChanged(e);
            ApplyDpiScale();
        }

        /// <summary>应用 DPI 缩放：更新缩放系数、字号与窗体尺寸，然后重新布局</summary>
        private void ApplyDpiScale()
        {
            _scale = DeviceDpi / 96f;
            Font = new Font("Microsoft YaHei UI", 9f * _scale, GraphicsUnit.Point);
            if (_log != null) _log.Font = new Font("Consolas", 9f * _scale, GraphicsUnit.Point);
            if (Math.Abs(_scale - 1f) > 0.01f)
            {
                SuspendLayout();
                ClientSize = new Size(Scale(720), Scale(700));
                ResumeLayout(true);
            }
            LayoutAll();
        }

        private int Scale(int v) => (int)Math.Round(v * _scale);

        private void BuildUi()
        {
            _lblExe = MakeLabel("目标程序:");
            _txtExe = MakeBox();
            _btnExe = MakeBrowseButton("浏览",
                () => _txtExe.Text = PickFile("可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"));

            _lblDll = MakeLabel("DLL 文件:");
            _txtDll = MakeBox();
            _btnDll = MakeBrowseButton("浏览",
                () => { string f = PickFiles("DLL 文件 (*.dll)|*.dll|所有文件 (*.*)|*.*"); if (f != null) _txtDll.Text = f; });
            _btnSort = MakeBrowseButton("⇅ 排序",
                () => { if (OpenDllSortDialog()) Log("已按新顺序更新 DLL 列表。"); });

            _btnInject = new Button
            {
                Text = "注入并启动",
                FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Accent,
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            _btnInject.Click += BtnInject_Click;

            _tip = new Label
            {
                Text = "多 DLL 用 ; 分隔；挂起启动 -> 注入 -> 恢复",
                AutoSize = true,
                ForeColor = Theme.TipFore
            };

            _lblArgs = MakeLabel("启动参数:");
            _txtArgs = MakeBox();

            _lblExport = MakeLabel("导出函数:");
            _txtExport = MakeBox();
            _lblExportArg = MakeLabel("调用参数:");
            _txtExportArg = MakeBox();

            _lblMethod = MakeLabel("注入方式:");
            _cboMethod = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                FlatStyle = FlatStyle.Flat
            };
            _cboMethod.Items.AddRange(new object[]
            {
                "CreateRemoteThread（兼容）",
                "NtCreateThreadEx（隐蔽）",
                "QueueUserAPC（仅启动时）",
                "反射式注入（Reflective）",
                "手动映射注入（Manual Map）"
            });
            _cboMethod.SelectedIndex = 0;

            _lblProc = new Label { Text = "运行中进程:", AutoSize = true };
            _cboProc = new ComboBox
            {
                DropDownStyle = ComboBoxStyle.DropDownList,
                FlatStyle = FlatStyle.Flat
            };
            _cboProc.Items.Add("（点击\"刷新\"加载进程列表）");
            _btnRefresh = MakeBrowseButton("刷新", () => BtnRefreshProc_Click(null, EventArgs.Empty));

            _btnInjectProc = new Button
            {
                Text = "注入到进程",
                FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Accent,
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            _btnInjectProc.Click += BtnInjectProc_Click;

            _btnBatch = new Button
            {
                Text = "批量注入",
                FlatStyle = FlatStyle.Flat,
                BackColor = Theme.Accent,
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            _btnBatch.Click += async (s, e) => await BtnBatchInject_Click(s, e);

            _btnEject = new Button
            {
                Text = "卸载 DLL",
                FlatStyle = FlatStyle.Flat,
                BackColor = Theme.ButtonBack,
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };
            _btnEject.Click += BtnEject_Click;

            _lblLog = new Label { Text = "运行日志:", AutoSize = true };

            _log = new TextBox
            {
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                Font = new Font("Consolas", 9F),
                BackColor = Color.FromArgb(28, 28, 30),
                ForeColor = Color.FromArgb(230, 230, 230),
                BorderStyle = BorderStyle.FixedSingle
            };

            Controls.AddRange(new Control[] { _lblExe, _txtExe, _btnExe, _lblDll, _txtDll, _btnDll, _btnSort,
                _lblArgs, _txtArgs, _lblExport, _txtExport, _lblExportArg, _txtExportArg, _btnInject, _tip,
                _lblProc, _cboProc, _btnRefresh, _btnInjectProc, _btnEject, _btnBatch, _lblMethod, _cboMethod,
                _lblLog, _log });
        }

        /// <summary>统一布局：以 96 DPI 逻辑坐标为准，按当前缩放系数与窗口尺寸摆放所有控件</summary>
        private void LayoutAll()
        {
            if (_layouting || _txtExe == null) return;
            _layouting = true;
            try
            {
                SuspendLayout();
                int padL = Scale(12), labelW = Scale(LabelWidth), browseW = Scale(BrowseWidth);
                int gap = Scale(8), rowH = Scale(RowHeight), boxH = Scale(26), btnH = Scale(34);
                int y = Scale(18);

                // 第 1 行：目标程序
                _lblExe.Location = new Point(padL, y + Scale(6));
                _txtExe.Location = new Point(labelW, y);
                _btnExe.Location = new Point(ClientSize.Width - padL - browseW, y);
                _txtExe.Size = new Size(ClientSize.Width - padL - labelW - gap - browseW - padL, boxH);
                _btnExe.Size = new Size(browseW, boxH);
                y += rowH;

                // 第 2 行：DLL 文件（输入框 + 排序 + 浏览）
                _lblDll.Location = new Point(padL, y + Scale(6));
                _txtDll.Location = new Point(labelW, y);
                int sortW = Scale(78);
                _btnSort.Location = new Point(ClientSize.Width - padL - browseW - gap - sortW, y);
                _btnSort.Size = new Size(sortW, boxH);
                _btnDll.Location = new Point(ClientSize.Width - padL - browseW, y);
                _txtDll.Size = new Size(ClientSize.Width - padL - labelW - gap - sortW - gap - browseW - padL, boxH);
                _btnDll.Size = new Size(browseW, boxH);
                y += rowH + Scale(4);

                // 第 3 行：启动参数（全宽输入框）
                _lblArgs.Location = new Point(padL, y + Scale(6));
                _txtArgs.Location = new Point(labelW, y);
                _txtArgs.Size = new Size(ClientSize.Width - padL - labelW - padL, boxH);
                y += rowH + Scale(4);

                // 第 4 行：导出函数（可空，注入后调用）
                _lblExport.Location = new Point(padL, y + Scale(6));
                _txtExport.Location = new Point(labelW, y);
                _txtExport.Size = new Size(ClientSize.Width - padL - labelW - padL, boxH);
                y += rowH + Scale(4);

                // 第 5 行：调用参数（可空，传给导出函数）
                _lblExportArg.Location = new Point(padL, y + Scale(6));
                _txtExportArg.Location = new Point(labelW, y);
                _txtExportArg.Size = new Size(ClientSize.Width - padL - labelW - padL, boxH);
                y += rowH + Scale(4);

                // 第 6 行：注入并启动 + 提示
                _btnInject.Location = new Point(labelW, y);
                _btnInject.Size = new Size(Scale(150), btnH);
                _tip.Location = new Point(labelW + Scale(160), y + Scale(7));
                y += rowH + Scale(8);

                // 第 7 行：运行中进程（下拉框 + 刷新）
                _lblProc.Location = new Point(padL, y + Scale(6));
                int refreshW = Scale(70);
                _cboProc.Location = new Point(labelW, y);
                _cboProc.Size = new Size(ClientSize.Width - padL - labelW - gap - refreshW - padL, boxH);
                _btnRefresh.Location = new Point(ClientSize.Width - padL - refreshW, y);
                _btnRefresh.Size = new Size(refreshW, boxH);
                y += rowH;

                // 第 8 行：注入到进程 / 批量注入 / 卸载 DLL（三个等宽按钮）
                int b3w = Scale(145), b3gap = Scale(8);
                _btnInjectProc.Location = new Point(labelW, y);
                _btnInjectProc.Size = new Size(b3w, btnH);
                _btnBatch.Location = new Point(labelW + b3w + b3gap, y);
                _btnBatch.Size = new Size(b3w, btnH);
                _btnEject.Location = new Point(labelW + 2 * (b3w + b3gap), y);
                _btnEject.Size = new Size(b3w, btnH);
                y += rowH + Scale(6);

                // 第 9 行：注入方式（下拉框）
                _lblMethod.Location = new Point(padL, y + Scale(6));
                _cboMethod.Location = new Point(labelW, y);
                _cboMethod.Size = new Size(ClientSize.Width - padL - labelW - padL, boxH);
                y += rowH + Scale(6);

                // 日志区
                _lblLog.Location = new Point(padL, y);
                y += Scale(22);
                _log.Location = new Point(padL, y);
                _log.Size = new Size(ClientSize.Width - 2 * padL, ClientSize.Height - y - padL);

                // 最小尺寸随缩放
                MinimumSize = new Size(Scale(MinWinW), Scale(MinWinH));

                ResumeLayout(true);
                PerformLayout();
            }
            finally
            {
                _layouting = false;
            }
        }

        /// <summary>应用当前主题（固定暗色）到窗体与全部控件</summary>
        private void ApplyTheme()
        {
            BackColor = Theme.Back;
            ForeColor = Theme.Fore;
            ApplyThemeTo(this);
            // 日志区固定深色终端风格
            _log.BackColor = Color.FromArgb(28, 28, 30);
            _log.ForeColor = Color.FromArgb(230, 230, 230);
            _tip.ForeColor = Theme.TipFore;
            // 主操作按钮固定为强调蓝
            _btnInject.BackColor = Theme.Accent; _btnInject.ForeColor = Color.White;
            _btnInjectProc.BackColor = Theme.Accent; _btnInjectProc.ForeColor = Color.White;
            // 卸载按钮使用次要按钮色
            _btnEject.BackColor = Theme.ButtonBack; _btnEject.ForeColor = Color.White;
            Invalidate(true);
        }

        private void ApplyThemeTo(Control parent)
        {
            foreach (Control c in parent.Controls)
            {
                if (c is Label lbl) lbl.ForeColor = Theme.Fore;
                else if (c is TextBox tb) { if (tb != _log) { tb.BackColor = Theme.BoxBack; tb.ForeColor = Theme.BoxFore; } }
                else if (c is ComboBox cb) { cb.BackColor = Theme.BoxBack; cb.ForeColor = Theme.BoxFore; }
                else if (c is Button b) { if (b != _btnInject && b != _btnInjectProc && b != _btnEject) { b.BackColor = Theme.ButtonBack; b.ForeColor = Theme.Fore; } }
                if (c.HasChildren) ApplyThemeTo(c);
            }
        }

        /// <summary>标签：自动宽度，文字永不被截断</summary>
        private static Label MakeLabel(string text)
            => new Label { Text = text, AutoSize = true };

        private TextBox MakeBox()
        {
            var tb = new TextBox { AllowDrop = true };
            tb.DragEnter += (s, e) => { if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy; };
            tb.DragDrop += (s, e) =>
            {
                if (e.Data.GetData(DataFormats.FileDrop) is string[] files && files.Length > 0)
                    tb.Text = string.Join(";", files);
            };
            return tb;
        }

        private Button MakeBrowseButton(string text, Action onClick)
        {
            var b = new Button { Text = text, FlatStyle = FlatStyle.Flat, Cursor = Cursors.Hand };
            b.Click += (s, e) => onClick();
            return b;
        }

        /// <summary>文件选择：初始目录固定为注入器 EXE 所在文件夹（与 DllInjector 同目录）</summary>
        private string PickFile(string filter)
        {
            using var dlg = new OpenFileDialog { Filter = filter, CheckFileExists = true };

            // 始终从注入器所在目录打开，方便把目标 exe / dll 放在同一文件夹
            string exeDir = AppContext.BaseDirectory;
            if (Directory.Exists(exeDir)) dlg.InitialDirectory = exeDir;

            return dlg.ShowDialog(this) == DialogResult.OK ? dlg.FileName : null;
        }

        /// <summary>多文件选择（DLL 用）：可多选，路径以分号连接；初始目录为注入器所在文件夹</summary>
        private string PickFiles(string filter)
        {
            using var dlg = new OpenFileDialog { Filter = filter, CheckFileExists = true, Multiselect = true };
            string exeDir = AppContext.BaseDirectory;
            if (Directory.Exists(exeDir)) dlg.InitialDirectory = exeDir;
            return dlg.ShowDialog(this) == DialogResult.OK ? string.Join(";", dlg.FileNames) : null;
        }

        /// <summary>载入上次记忆的 exe / dll（仅当文件仍存在时填充输入框）</summary>
        private void LoadLastSelection()
        {
            ConfigStore.Load(out string exe, out string dll);
            if (!string.IsNullOrEmpty(exe) && File.Exists(exe)) _txtExe.Text = exe;
            if (!string.IsNullOrEmpty(dll))
            {
                // 多 DLL 以分号连接：逐段校验，全部仍存在才带出
                string[] parts = InjectorCore.SplitDlls(dll);
                bool allExist = parts.Length > 0;
                foreach (var p in parts)
                    if (!File.Exists(p)) { allExist = false; break; }
                if (allExist) _txtDll.Text = dll;
            }
            if (_txtExe.Text.Length > 0 || _txtDll.Text.Length > 0)
                Log("已载入上次选择（配置: " + ConfigStore.ConfigPath + "）。");
        }

        // 日志行数上限。达到上限后不是每条都重排一次（那样是 O(n²)，
        // 长批次注入时会明显卡顿），而是攒到 SLACK 行才整体裁剪一次，
        // 把重排成本摊薄到 SLACK 条消息上。
        private const int LogMaxLines = 1000;
        private const int LogTrimSlack = 200;
        private int _logLines;

        private void Log(string msg)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string>(Log), msg); return; }
            _log.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}{Environment.NewLine}");
            _logLines++;

            if (_logLines > LogMaxLines + LogTrimSlack)
            {
                // 先把 \r\n 归一到 \n，截断后行尾不再残留 \r
                string[] lines = _log.Text.Replace("\r\n", "\n").Split('\n');
                if (lines.Length > LogMaxLines)
                {
                    _log.Text = string.Join("\n", lines, lines.Length - LogMaxLines, LogMaxLines);
                    _logLines = LogMaxLines;
                }
                else
                {
                    _logLines = lines.Length;
                }
            }

            _log.SelectionStart = _log.TextLength;
            _log.ScrollToCaret();
        }

        private async void BtnInject_Click(object sender, EventArgs e)
        {
            string exe = _txtExe.Text.Trim().Trim('"');
            string[] dlls = InjectorCore.SplitDlls(_txtDll.Text);
            string args = _txtArgs.Text.Trim();
            string exportFunc = _txtExport.Text.Trim();
            string exportArg = _txtExportArg.Text.Trim();
            int method = _cboMethod.SelectedIndex;
            ConfigStore.Method = method;   // 记忆注入方式
            if (string.IsNullOrEmpty(exe) || dlls.Length == 0)
            {
                MessageBox.Show("请先选择目标 exe 和 dll 文件。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            ConfigStore.Save(exe, _txtDll.Text.Trim());   // 记忆本次选择，下次启动自动带出

            var btn = sender as Button;
            btn.Enabled = false;
            try
            {
                await Task.Run(() => InjectorCore.Run(exe, dlls, args, method, exportFunc, exportArg, Log));
            }
            catch (Exception ex)
            {
                Log("发生异常: " + ex.Message);
            }
            finally
            {
                btn.Enabled = true;
            }
        }

        /// <summary>刷新运行中进程列表（异步，避免卡 UI）</summary>
        private async void BtnRefreshProc_Click(object sender, EventArgs e)
        {
            _btnRefresh.Enabled = false;
            _cboProc.Items.Clear();
            _cboProc.Items.Add("正在加载进程列表...");
            try
            {
                var items = await Task.Run(() =>
                {
                    var list = new System.Collections.Generic.List<ProcItem>();
                    foreach (var p in System.Diagnostics.Process.GetProcesses())
                    {
                        try
                        {
                            if (p.Id > 0 && !string.IsNullOrEmpty(p.ProcessName))
                                list.Add(new ProcItem { Pid = p.Id, Name = $"{p.ProcessName} [PID {p.Id}]" });
                        }
                        catch { }
                    }
                    list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
                    return list;
                });

                _cboProc.Items.Clear();
                foreach (var item in items) _cboProc.Items.Add(item);
                Log($"进程列表已刷新（{items.Count} 个进程）。");
            }
            catch (Exception ex)
            {
                Log("刷新进程列表失败: " + ex.Message);
            }
            finally
            {
                _btnRefresh.Enabled = true;
            }
        }

        /// <summary>向选中的运行中进程注入 DLL</summary>
        private async void BtnInjectProc_Click(object sender, EventArgs e)
        {
            if (!TryGetSelectedPid(out int pid)) return;
            string[] dlls = InjectorCore.SplitDlls(_txtDll.Text);
            if (dlls.Length == 0)
            {
                MessageBox.Show("请先选择要注入的 dll 文件。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string exportFunc = _txtExport.Text.Trim();
            string exportArg = _txtExportArg.Text.Trim();
            int method = _cboMethod.SelectedIndex;
            ConfigStore.Method = method;   // 记忆注入方式
            var btn = sender as Button;
            btn.Enabled = false;
            try
            {
                await Task.Run(() => InjectorCore.InjectToProcess(pid, dlls, method, exportFunc, exportArg, Log));
            }
            catch (Exception ex)
            {
                Log("发生异常: " + ex.Message);
            }
            finally
            {
                btn.Enabled = true;
            }
        }

        /// <summary>批量注入：弹窗勾选多个进程后逐一注入，结果汇总到日志</summary>
        private async Task BtnBatchInject_Click(object sender, EventArgs e)
        {
            string[] dlls = InjectorCore.SplitDlls(_txtDll.Text);
            if (dlls.Length == 0)
            {
                MessageBox.Show("请先选择要注入的 dll 文件。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            string exportFunc = _txtExport.Text.Trim();
            string exportArg = _txtExportArg.Text.Trim();
            int method = _cboMethod.SelectedIndex;
            ConfigStore.Method = method;

            using var dlg = new BatchInjectDialog(_scale);
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            int[] pids = dlg.SelectedPids;
            if (pids.Length == 0)
            {
                MessageBox.Show("未勾选任何进程。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var btn = sender as Button;
            btn.Enabled = false;
            try
            {
                await Task.Run(() => InjectorCore.BatchInjectProcesses(pids, dlls, method, exportFunc, exportArg, Log));
            }
            catch (Exception ex)
            {
                Log("发生异常: " + ex.Message);
            }
            finally
            {
                btn.Enabled = true;
            }
        }

        /// <summary>从选中的运行中进程卸载 DLL（使用 DLL 输入框中的文件名）</summary>
        private async void BtnEject_Click(object sender, EventArgs e)
        {
            if (!TryGetSelectedPid(out int pid)) return;
            string dll = _txtDll.Text.Trim().Trim('"');
            if (string.IsNullOrEmpty(dll))
            {
                MessageBox.Show("请先选择要卸载的 dll 文件（或输入模块名）。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }
            var btn = sender as Button;
            btn.Enabled = false;
            try
            {
                await Task.Run(() => InjectorCore.EjectDll(pid, dll, Log));
            }
            catch (Exception ex)
            {
                Log("发生异常: " + ex.Message);
            }
            finally
            {
                btn.Enabled = true;
            }
        }

        /// <summary>从进程下拉框取出 PID；未选择时提示并返回 false</summary>
        private bool TryGetSelectedPid(out int pid)
        {
            pid = -1;
            if (_cboProc.SelectedItem is ProcItem item && item.Pid > 0)
            {
                pid = item.Pid;
                return true;
            }
            MessageBox.Show("请先点击\"刷新\"并选择一个运行中的进程。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return false;
        }

        /// <summary>进程下拉框条目：显示名称 + 真实 PID</summary>
        private sealed class ProcItem
        {
            public int Pid;
            public string Name;
            public override string ToString() => Name;
        }

        /// <summary>打开 DLL 排序对话框（支持拖拽重排 / 上移 / 下移 / 删除）；确定后回写输入框</summary>
        private bool OpenDllSortDialog()
        {
            var dlls = InjectorCore.SplitDlls(_txtDll.Text);
            if (dlls.Length == 0)
            {
                MessageBox.Show("当前没有可排序的 DLL，请先在「DLL 文件」中填写（多个用 ; 分隔）。",
                    "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return false;
            }
            using var dlg = new DllSortDialog(dlls, _scale);
            if (dlg.ShowDialog(this) == DialogResult.OK)
            {
                _txtDll.Text = string.Join(";", dlg.Result);
                return true;
            }
            return false;
        }

        /// <summary>DLL 排序对话框：列表支持鼠标拖拽重排，附 上移 / 下移 / 删除 与 确定 / 取消</summary>
        private sealed class DllSortDialog : Form
        {
            private readonly ListBox _list;

            public string[] Result => _list.Items.Cast<string>().ToArray();

            public DllSortDialog(string[] items, float scale)
            {
                Text = "DLL 注入顺序（拖拽调整）";
                FormBorderStyle = FormBorderStyle.FixedDialog;
                MaximizeBox = false;
                MinimizeBox = false;
                StartPosition = FormStartPosition.CenterParent;
                ShowInTaskbar = false;
                ClientSize = new Size((int)(450 * scale), (int)(360 * scale));
                BackColor = Color.FromArgb(45, 45, 48);
                ForeColor = Color.White;
                Font = new Font("Microsoft YaHei UI", 9f * scale);

                _list = new ListBox
                {
                    Location = new Point((int)(12 * scale), (int)(12 * scale)),
                    Size = new Size((int)(426 * scale), (int)(250 * scale)),
                    AllowDrop = true,
                    BackColor = Color.FromArgb(28, 28, 30),
                    ForeColor = Color.FromArgb(230, 230, 230),
                    BorderStyle = BorderStyle.FixedSingle,
                    IntegralHeight = false,
                    DrawMode = DrawMode.OwnerDrawFixed,
                    ItemHeight = (int)(22 * scale)
                };
                _list.Items.AddRange(items);
                _list.DrawItem += (s, e) =>
                {
                    e.DrawBackground();
                    using var br = new SolidBrush(
                        (e.State & DrawItemState.Selected) != 0 ? Color.White : Color.FromArgb(230, 230, 230));
                    e.Graphics.DrawString(
                        _list.Items[e.Index].ToString(),
                        e.Font,
                        br,
                        e.Bounds.X + 4,
                        e.Bounds.Y + 2);
                };

                // 拖拽重排（ListBox 用 MouseDown 发起拖拽）
                _list.MouseDown += (s, e) =>
                {
                    if (e.Button != MouseButtons.Left) return;
                    int idx = _list.IndexFromPoint(e.Location);
                    if (idx >= 0) _list.DoDragDrop(_list.Items[idx], DragDropEffects.Move);
                };
                _list.DragOver += (s, e) => e.Effect = DragDropEffects.Move;
                _list.DragDrop += (s, e) =>
                {
                    if (!(e.Data.GetData(typeof(string)) is string item)) return;
                    var pt = _list.PointToClient(new Point(e.X, e.Y));
                    int idx = _list.IndexFromPoint(pt);
                    _list.Items.Remove(item);
                    if (idx < 0 || idx >= _list.Items.Count) _list.Items.Add(item);
                    else _list.Items.Insert(idx, item);
                };

                var btnUp = MakeBtn("上移");
                var btnDown = MakeBtn("下移");
                var btnDel = MakeBtn("删除");
                btnUp.Click += (s, e) => MoveSelected(-1);
                btnDown.Click += (s, e) => MoveSelected(1);
                btnDel.Click += (s, e) => { if (_list.SelectedIndex >= 0) _list.Items.RemoveAt(_list.SelectedIndex); };

                var btnOk = MakeBtn("确定");
                btnOk.BackColor = Theme.Accent;
                btnOk.DialogResult = DialogResult.OK;
                var btnCancel = MakeBtn("取消");
                btnCancel.DialogResult = DialogResult.Cancel;

                int by = (int)(272 * scale);
                int bw = (int)(72 * scale), bh = (int)(32 * scale), gap = (int)(8 * scale);
                btnUp.Location = new Point((int)(12 * scale), by);
                btnDown.Location = new Point((int)(12 * scale) + bw + gap, by);
                btnDel.Location = new Point((int)(12 * scale) + 2 * (bw + gap), by);
                btnOk.Location = new Point(ClientSize.Width - 2 * bw - gap - (int)(12 * scale), by);
                btnCancel.Location = new Point(ClientSize.Width - bw - (int)(12 * scale), by);
                foreach (var b in new Control[] { btnUp, btnDown, btnDel, btnOk, btnCancel })
                    b.Size = new Size(bw, bh);

                Controls.Add(_list);
                Controls.AddRange(new Control[] { btnUp, btnDown, btnDel, btnOk, btnCancel });
                AcceptButton = btnOk;
                CancelButton = btnCancel;
            }

            private static Button MakeBtn(string text) => new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(70, 70, 74),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };

            private void MoveSelected(int delta)
            {
                int i = _list.SelectedIndex;
                if (i < 0) return;
                int ni = i + delta;
                if (ni < 0 || ni >= _list.Items.Count) return;
                object it = _list.Items[i];
                _list.Items.RemoveAt(i);
                _list.Items.Insert(ni, it);
                _list.SelectedIndex = ni;
            }
        }

        /// <summary>批量注入对话框：勾选多个进程（支持按名称筛选），确定后批量注入</summary>
        private sealed class BatchInjectDialog : Form
        {
            private sealed class ProcEntry
            {
                public int Pid;
                public string Name;
                public string Bits;
                public override string ToString() => $"{Name} [PID {Pid}]（{Bits}）";
            }

            private readonly CheckedListBox _list;
            private readonly TextBox _filter;
            private readonly System.Collections.Generic.List<ProcEntry> _all;

            public int[] SelectedPids
            {
                get
                {
                    var r = new System.Collections.Generic.List<int>();
                    foreach (ProcEntry e in _list.CheckedItems) r.Add(e.Pid);
                    return r.ToArray();
                }
            }

            public BatchInjectDialog(float scale)
            {
                Text = "批量注入 - 勾选目标进程";
                FormBorderStyle = FormBorderStyle.FixedDialog;
                MaximizeBox = false;
                MinimizeBox = false;
                StartPosition = FormStartPosition.CenterParent;
                ShowInTaskbar = false;
                ClientSize = new Size((int)(500 * scale), (int)(430 * scale));
                BackColor = Color.FromArgb(45, 45, 48);
                ForeColor = Color.White;
                Font = new Font("Microsoft YaHei UI", 9f * scale);

                var hint = new Label
                {
                    Text = "勾选要注入的进程（可多选）；位数不符自动跳过。",
                    AutoSize = true,
                    ForeColor = Color.FromArgb(170, 170, 170),
                    Location = new Point((int)(12 * scale), (int)(12 * scale))
                };

                _filter = new TextBox
                {
                    Location = new Point((int)(12 * scale), (int)(34 * scale)),
                    Size = new Size((int)(300 * scale), (int)(26 * scale)),
                    BackColor = Color.FromArgb(28, 28, 30),
                    ForeColor = Color.FromArgb(230, 230, 230),
                    BorderStyle = BorderStyle.FixedSingle
                };
                var lblFilter = new Label
                {
                    Text = "筛选:",
                    AutoSize = true,
                    Location = new Point((int)(318 * scale), (int)(38 * scale)),
                    ForeColor = Color.FromArgb(170, 170, 170)
                };

                _list = new CheckedListBox
                {
                    Location = new Point((int)(12 * scale), (int)(68 * scale)),
                    Size = new Size((int)(476 * scale), (int)(290 * scale)),
                    CheckOnClick = true,
                    IntegralHeight = false,
                    BackColor = Color.FromArgb(28, 28, 30),
                    ForeColor = Color.FromArgb(230, 230, 230),
                    BorderStyle = BorderStyle.FixedSingle
                };

                _all = Enumerate();
                _filter.TextChanged += (s, e) => Fill(_filter.Text);

                var btnOk = MakeBtn("确定");
                btnOk.BackColor = Theme.Accent;
                btnOk.DialogResult = DialogResult.OK;
                var btnCancel = MakeBtn("取消");
                btnCancel.DialogResult = DialogResult.Cancel;

                int by = (int)(372 * scale);
                int bw = (int)(80 * scale), bh = (int)(32 * scale), gap = (int)(10 * scale);
                btnOk.Location = new Point(ClientSize.Width - 2 * bw - gap - (int)(12 * scale), by);
                btnCancel.Location = new Point(ClientSize.Width - bw - (int)(12 * scale), by);
                foreach (var b in new Control[] { btnOk, btnCancel }) b.Size = new Size(bw, bh);

                Controls.Add(hint);
                Controls.Add(_filter);
                Controls.Add(lblFilter);
                Controls.Add(_list);
                Controls.AddRange(new Control[] { btnOk, btnCancel });
                AcceptButton = btnOk;
                CancelButton = btnCancel;
                Fill("");
            }

            private static Button MakeBtn(string text) => new Button
            {
                Text = text,
                FlatStyle = FlatStyle.Flat,
                BackColor = Color.FromArgb(70, 70, 74),
                ForeColor = Color.White,
                Cursor = Cursors.Hand
            };

            private System.Collections.Generic.List<ProcEntry> Enumerate()
            {
                var list = new System.Collections.Generic.List<ProcEntry>();
                foreach (var p in System.Diagnostics.Process.GetProcesses())
                {
                    try
                    {
                        if (p.Id <= 0) continue;
                        string bits = "位数未知";
                        IntPtr h = NativeMethods.OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, p.Id);
                        if (h != IntPtr.Zero)
                        {
                            try
                            {
                                bool w64 = false;
                                if (NativeMethods.IsWow64Process(h, out w64)) bits = w64 ? "32 位" : "64 位";
                            }
                            catch { }
                            finally { NativeMethods.CloseHandle(h); }
                        }
                        list.Add(new ProcEntry { Pid = p.Id, Name = p.ProcessName, Bits = bits });
                    }
                    catch { }
                }
                list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
                return list;
            }

            private void Fill(string filter)
            {
                _list.Items.Clear();
                foreach (var e in _all)
                    if (string.IsNullOrEmpty(filter) || e.Name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0)
                        _list.Items.Add(e, false);
            }
        }
    }

    /// <summary>注入核心逻辑（GUI 与命令行模式共用）</summary>
    internal static class InjectorCore
    {
        /// <summary>一条手动映射注入记录。</summary>
        public readonly struct MmRecord
        {
            /// <summary>目标进程内的完整模块基址（手动映射的映像不进模块列表，只能靠这个记住）。</summary>
            public readonly long Base;
            /// <summary>记录时目标进程的启动时间（Ticks）。0 = 未知（旧格式记录），此时无法识别 PID 复用。</summary>
            public readonly long StartTicks;
            public MmRecord(long moduleBase, long startTicks) { Base = moduleBase; StartTicks = startTicks; }
        }

        /// <summary>手动映射注入的 DLL 基址记录（key = "pid|dll路径"），供「卸载 DLL」使用。
        /// 仅本注入器进程内有效：注入器退出后丢失（手动映射 DLL 不在目标进程模块列表，无法重新枚举）。</summary>
        public static readonly System.Collections.Concurrent.ConcurrentDictionary<string, MmRecord> MmBases = new();

        /// <summary>手动映射基址的跨进程持久化文件（key = "pid|dll路径"，
        /// value = "基址十六进制|进程启动时间十六进制"；启动时间用于识别 PID 复用）。
        /// 注入器进程退出后，只要目标进程还活着，重启注入器仍可按此文件卸载手动映射 DLL。</summary>
        private static readonly string MmMapPath = System.IO.Path.Combine(AppContext.BaseDirectory, "DllInjector.mmmap");

        /// <summary>取进程启动时间（Ticks）。进程不存在或无权查询时返回 0。</summary>
        private static long GetProcessStartTicks(int pid)
        {
            try
            {
                using (var p = System.Diagnostics.Process.GetProcessById(pid))
                    return p.StartTime.Ticks;
            }
            catch { return 0; }
        }

        private static bool ProcessExists(int pid)
        {
            try
            {
                using (var p = System.Diagnostics.Process.GetProcessById(pid)) { return true; }
            }
            catch { return false; }
        }

        /// <summary>校验一条手动映射记录是否仍然可信。
        /// 进程已退出 → 记录必然失效（映像随进程一起消失）。
        /// 进程还在但启动时间对不上 → PID 被复用，这是**另一个**进程，按旧基址去卸载会破坏无关进程。
        /// 启动时间未知（旧格式记录）或读不到时保守保留，只做「进程是否存在」这一层判断。</summary>
        private static bool IsMmRecordValid(int pid, long recordedStartTicks, out string reason)
        {
            reason = null;
            if (!ProcessExists(pid)) { reason = $"目标进程 {pid} 已退出"; return false; }
            if (recordedStartTicks != 0)
            {
                long current = GetProcessStartTicks(pid);
                if (current != 0 && current != recordedStartTicks)
                { reason = $"PID {pid} 已被其它进程复用"; return false; }
            }
            return true;
        }

        private static bool TryParseMmKey(string key, out int pid, out string dllPath)
        {
            pid = 0; dllPath = null;
            if (string.IsNullOrEmpty(key)) return false;
            int sep = key.IndexOf('|');
            if (sep <= 0 || sep >= key.Length - 1) return false;
            if (!int.TryParse(key.Substring(0, sep), out pid) || pid <= 0) return false;
            dllPath = key.Substring(sep + 1);
            return true;
        }

        private static string EncodeMmValue(long moduleBase, long startTicks)
            => moduleBase.ToString("X") + "|" + startTicks.ToString("X");

        /// <summary>解析记录值。兼容旧格式（只有基址、没有启动时间）。</summary>
        private static bool TryDecodeMmValue(string value, out long moduleBase, out long startTicks)
        {
            moduleBase = 0; startTicks = 0;
            if (string.IsNullOrEmpty(value)) return false;
            string[] parts = value.Split('|');
            if (!long.TryParse(parts[0], System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out moduleBase) || moduleBase == 0)
                return false;
            if (parts.Length > 1)
                long.TryParse(parts[1], System.Globalization.NumberStyles.HexNumber,
                    System.Globalization.CultureInfo.InvariantCulture, out startTicks);
            return true;
        }

        /// <summary>记录手动映射注入的 DLL 基址（内存 + 落盘）。</summary>
        public static void RecordMmBase(int pid, string dllPath, long baseAddr)
        {
            string key = pid + "|" + dllPath;
            long startTicks = GetProcessStartTicks(pid);
            MmBases[key] = new MmRecord(baseAddr, startTicks);
            try
            {
                var map = LoadMmMapFile();
                map[key] = EncodeMmValue(baseAddr, startTicks);
                SaveMmMapFile(map);
            }
            catch { /* 落盘失败不影响注入本身 */ }
        }

        /// <summary>卸载成功后移除手动映射记录（内存 + 落盘）。</summary>
        public static void UnrecordMmBase(string key)
        {
            if (string.IsNullOrEmpty(key)) return;
            MmBases.TryRemove(key, out _);
            try
            {
                var map = LoadMmMapFile();
                if (map.Remove(key)) SaveMmMapFile(map);
            }
            catch { }
        }

        /// <summary>启动时把上次的持久化记录读入内存，供跨进程卸载使用。
        /// 顺带剔除失效记录——进程已退出的、以及 PID 被复用的（后者尤其危险：
        /// 命中陈旧基址会去卸载无关进程）。清理结果写回文件，避免记录只增不减。</summary>
        public static void LoadMmMap()
        {
            try
            {
                var file = LoadMmMapFile();
                var kept = new System.Collections.Generic.Dictionary<string, string>();
                int dropped = 0;
                foreach (var kv in file)
                {
                    if (!TryParseMmKey(kv.Key, out int pid, out _) ||
                        !TryDecodeMmValue(kv.Value, out long moduleBase, out long startTicks))
                    { dropped++; continue; }

                    if (!IsMmRecordValid(pid, startTicks, out _)) { dropped++; continue; }

                    MmBases[kv.Key] = new MmRecord(moduleBase, startTicks);
                    kept[kv.Key] = kv.Value;
                }
                if (dropped > 0) SaveMmMapFile(kept);
            }
            catch { }
        }

        private static void SaveMmMapFile(System.Collections.Generic.Dictionary<string, string> map)
        {
            try { File.WriteAllText(MmMapPath, System.Text.Json.JsonSerializer.Serialize(map)); }
            catch { }
        }

        private static System.Collections.Generic.Dictionary<string, string> LoadMmMapFile()
        {
            try
            {
                if (File.Exists(MmMapPath))
                {
                    string json = File.ReadAllText(MmMapPath);
                    if (!string.IsNullOrWhiteSpace(json))
                        return System.Text.Json.JsonSerializer.Deserialize<System.Collections.Generic.Dictionary<string, string>>(json)
                               ?? new System.Collections.Generic.Dictionary<string, string>();
                }
            }
            catch { }
            return new System.Collections.Generic.Dictionary<string, string>();
        }
        /// <summary>启用当前进程的 SeDebugPrivilege（调试权限），便于打开/注入 SYSTEM 等高权限或其它会话的进程。
        /// 普通权限令牌下会失败（当前令牌不含该权限），仅提示、不阻断后续尝试。</summary>
        public static bool EnableSeDebugPrivilege(Action<string> log)
        {
            IntPtr token;
            if (!NativeMethods.OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
                NativeMethods.TOKEN_ADJUST_PRIVILEGES | NativeMethods.TOKEN_QUERY, out token))
            {
                log("提示: 打开进程令牌失败，未启用 SeDebugPrivilege - " + NativeMethods.LastErrorText());
                return false;
            }
            try
            {
                NativeMethods.LUID luid;
                if (!NativeMethods.LookupPrivilegeValue(null, "SeDebugPrivilege", out luid))
                {
                    log("提示: 查询 SeDebugPrivilege 失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                var tp = new NativeMethods.TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = NativeMethods.SE_PRIVILEGE_ENABLED
                };
                if (!NativeMethods.AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    log("提示: 调整令牌权限失败，未启用 SeDebugPrivilege - " + NativeMethods.LastErrorText());
                    return false;
                }
                // AdjustTokenPrivileges 成功返回 true 但可能"未全部授予"（当前令牌本就不含该权限，常见于普通权限运行）
                if (Marshal.GetLastWin32Error() == (int)NativeMethods.ERROR_NOT_ALL_ASSIGNED)
                {
                    log("提示: 当前令牌不含 SeDebugPrivilege（需以管理员/特权账户运行），对 SYSTEM 等高权限进程的注入可能失败。");
                    return false;
                }
                log("已启用 SeDebugPrivilege（调试权限），可尝试访问 SYSTEM 等高权限 / 其他会话进程。");
                return true;
            }
            finally
            {
                NativeMethods.CloseHandle(token);
            }
        }

        /// <summary>注入前 PE 体检：剔除不可用的 DLL（非 PE / 非 DLL / 位数不符），记录体检结论，返回可通过的 DLL 列表</summary>
        public static string[] PreflightDlls(string[] dllPaths, int targetBits, Action<string> log)
        {
            var ok = new System.Collections.Generic.List<string>();
            foreach (var dll in dllPaths)
            {
                string name = Path.GetFileName(dll);
                var insp = PeHelper.InspectDll(dll);
                if (!insp.IsValidPe)
                {
                    log("体检失败: " + name + " - " + (string.IsNullOrEmpty(insp.Detail) ? "不是有效的 PE 文件" : insp.Detail));
                    continue;
                }
                if (!insp.IsDll)
                {
                    log("体检失败: " + name + " - 不是 DLL（缺少 IMAGE_FILE_DLL 标志）");
                    continue;
                }
                if (insp.Bitness != targetBits)
                {
                    log($"体检失败: {name} - 位数不匹配（DLL 为 {insp.Bitness} 位，目标为 {targetBits} 位）");
                    continue;
                }
                var warns = new System.Collections.Generic.List<string>();
                if (!insp.HasExportTable) warns.Add("无导出表");
                if (!insp.HasRelocSection) warns.Add("无 .reloc 重定位段");
                if (insp.FileSize >= 0 && insp.FileSize < 1024) warns.Add("文件异常小");
                string warn = warns.Count > 0 ? "（提示: " + string.Join("，", warns) + "）" : "";
                string exp = insp.ExportCount >= 0 ? "导出函数 " + insp.ExportCount + " 个" : "无导出信息";
                log($"体检通过: {name}（{insp.Bitness} 位, {exp}, 文件 {insp.FileSize} 字节）{warn}");
                ok.Add(dll);
            }
            return ok.ToArray();
        }

        /// <summary>核心注入流程：挂起启动 -> 逐个注入 DLL -> 恢复主线程 -> 调用导出函数 -> 注入结果核验</summary>
        public static bool Run(string exePath, string[] dllPaths, string args, int method, string exportFunc, string exportArg, Action<string> log)
        {
            log("================ 开始注入 ================");
            EnableSeDebugPrivilege(log);
            if (!File.Exists(exePath)) { log("错误: 目标程序不存在: " + exePath); return false; }
            if (dllPaths == null || dllPaths.Length == 0) { log("错误: 未指定要注入的 DLL。"); return false; }
            foreach (var dll in dllPaths)
                if (!File.Exists(dll)) { log("错误: DLL 不存在: " + dll); return false; }

            int toolBits = IntPtr.Size * 8;
            int targetBits = PeHelper.GetExeBitness(exePath);
            if (targetBits == 0)
            {
                log("错误: 无法识别目标程序架构，可能不是有效的 PE 可执行文件。");
                return false;
            }
            log($"目标程序: {Path.GetFileName(exePath)}（{targetBits} 位）| 注入器: {toolBits} 位 | DLL 数量: {dllPaths.Length}");
            if (targetBits != toolBits)
            {
                log($"错误: 位数不匹配，无法注入。请使用与目标程序同位数（{targetBits} 位）的注入器版本。");
                return false;
            }

            // 注入前 PE 体检：剔除不可用的 DLL
            dllPaths = PreflightDlls(dllPaths, toolBits, log);
            if (dllPaths.Length == 0)
            {
                log("错误: 所有 DLL 均未通过体检，无法注入。");
                return false;
            }

            string workDir = Path.GetDirectoryName(exePath);
            string cmdLine = "\"" + exePath + "\"";
            if (!string.IsNullOrEmpty(args)) cmdLine += " " + args;
            var si = new NativeMethods.STARTUPINFO { cb = Marshal.SizeOf<NativeMethods.STARTUPINFO>() };
            NativeMethods.PROCESS_INFORMATION pi;

            if (!NativeMethods.CreateProcess(exePath, cmdLine, IntPtr.Zero, IntPtr.Zero,
                    false, NativeMethods.CREATE_SUSPENDED | NativeMethods.CREATE_NEW_CONSOLE,
                    IntPtr.Zero, workDir, ref si, out pi))
            {
                log("错误: 创建进程失败 - " + NativeMethods.LastErrorText());
                return false;
            }
            log($"已创建目标进程（PID={pi.dwProcessId}）并挂起，开始注入...");

            bool allOk = true;
            var injected = new System.Collections.Generic.List<string>();
            
            try
            {
                foreach (var dll in dllPaths)
                {
                    log("----- 注入: " + Path.GetFileName(dll) + " -----");
                    IntPtr remoteBuf, hRemoteThread, mmModule;
                    if (LoadLibraryIntoProcess(pi.hProcess, pi.hThread, dll, method, log, out remoteBuf, out hRemoteThread, out mmModule, out bool bufBusy))
                    {
                        injected.Add(dll);
                        if (mmModule != IntPtr.Zero) InjectorCore.RecordMmBase(pi.dwProcessId, dll, mmModule.ToInt64());
                        // CRT/NTC 为同步等待（LoadLibraryW 已完成），路径内存可立即释放；
                        // APC 为异步排队（LoadLibraryW 要等主线程可告警后才执行），其路径内存保留在目标进程内，随进程退出回收；
                        // RFI 的原始字节缓冲区保留在目标进程（供 ReflectiveLoader 回溯定位，映射已由其完成）；
                        // MM 的临时内存（DLL 字节/shellcode/参数）在 ManualMapInjectIntoProcess 内映射完成后已自行释放。
                        if (method != NativeMethods.INJECT_APC && method != NativeMethods.INJECT_RFI && remoteBuf != IntPtr.Zero)
                            NativeMethods.VirtualFreeEx(pi.hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                    }
                    else
                    {
                        allOk = false;   // 注入失败：标记整体流程未全部成功（修正：原代码漏了该赋值）
                        // bufBusy = 远程线程可能仍在读这块内存（超时/等待失败），此时释放就是 use-after-free
                        if (remoteBuf != IntPtr.Zero && !bufBusy)
                            NativeMethods.VirtualFreeEx(pi.hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                        else if (remoteBuf != IntPtr.Zero && bufBusy)
                            log("提示: 该 DLL 的远程路径缓冲区已交由目标进程回收（避免与仍在运行的远程线程竞争）。");
                    }

                    if (hRemoteThread != IntPtr.Zero)
                        NativeMethods.CloseHandle(hRemoteThread);
                }
            }
            finally
            {
                NativeMethods.ResumeThread(pi.hThread);
                log("主线程已恢复，目标程序开始运行。");
                NativeMethods.CloseHandle(pi.hThread);
            }

            // 注入后调用 DLL 导出函数（目标进程已运行、模块齐全）
            if (!string.IsNullOrEmpty(exportFunc) && injected.Count > 0)
            {
                if (method == NativeMethods.INJECT_APC)
                {
                    // 先等 APC 把 DLL 真正装进去，否则导出函数必定拿不到模块基址
                    WaitApcloaded(pi.dwProcessId, injected.ToArray(), log);
                }
                if (method == NativeMethods.INJECT_RFI)
                    log("提示: 反射式注入不自动调用导出函数（反射 DLL 不进入进程模块列表，且 Loader 返回句柄经线程退出码截断无法可靠定位），初始化请由 DLL 在 ReflectiveLoader / DllMain 内自行完成。");
                else
                    foreach (var dll in injected)
                        CallExport(pi.hProcess, pi.dwProcessId, dll, exportFunc, exportArg, log,
                            InjectorCore.MmBases.TryGetValue(pi.dwProcessId + "|" + dll, out MmRecord mmRec) ? mmRec.Base : 0);
            }

            NativeMethods.CloseHandle(pi.hProcess);

            // 注入结果核验（目标进程已运行，模块列表齐全）
            if (injected.Count > 0)
            {
                log("----- 注入结果核验 -----");
                bool verifyOk = true;
                foreach (var dll in injected)
                {
                    if (method == NativeMethods.INJECT_RFI)
                        log($"核验通过：{Path.GetFileName(dll)} 反射映射成功（ReflectiveLoader 返回句柄非零；反射 DLL 不进入进程模块列表属正常）。");
                    else if (method == NativeMethods.INJECT_MM)
                        log($"核验通过：{Path.GetFileName(dll)} 手动映射成功（shellcode 返回完整基址 0x{(InjectorCore.MmBases.TryGetValue(pi.dwProcessId + "|" + dll, out MmRecord mmb) ? mmb.Base : 0):X}；手动映射 DLL 不进入进程模块列表属正常）。");
                    else if (!VerifyModuleLoaded(pi.dwProcessId, dll, log)) verifyOk = false;
                }
                if (!verifyOk && method == NativeMethods.INJECT_APC)
                    log("提示: QueueUserAPC 需要目标主线程处于可告警(alertable)等待（如 SleepEx / GetMessage 消息循环），否则 APC 不会执行；失败请改用 CreateRemoteThread 或 NtCreateThreadEx。");
            }

            log(allOk ? "===== 注入流程完成 =====" : "===== 注入流程结束（部分 DLL 未成功，见上方日志）=====");
            return allOk;
        }

        /// <summary>向已运行的进程注入 DLL（OpenProcess + 远程 LoadLibraryW，支持多 DLL 与导出函数调用）</summary>
        public static bool InjectToProcess(int pid, string[] dllPaths, int method, string exportFunc, string exportArg, Action<string> log)
        {
            log("================ 注入到运行中进程 ================");
            EnableSeDebugPrivilege(log);
            if (pid <= 0) { log("错误: 无效 PID: " + pid); return false; }
            if (dllPaths == null || dllPaths.Length == 0) { log("错误: 未指定要注入的 DLL。"); return false; }
            foreach (var dll in dllPaths)
                if (!File.Exists(dll)) { log("错误: DLL 不存在: " + dll); return false; }

            int toolBits = IntPtr.Size * 8;
            IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ACCESS_FOR_INJECT, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                log($"错误: 无法打开进程 PID={pid} - {NativeMethods.LastErrorText()}（可能需要管理员权限）");
                return false;
            }
            try
            {
                // 运行中进程用 IsWow64Process 判断位数
                bool isWow64 = false;
                int targetBits = toolBits;
                if (NativeMethods.IsWow64Process(hProcess, out isWow64))
                    targetBits = isWow64 ? 32 : 64;

                log($"目标进程 PID={pid}（{targetBits} 位）| 注入器: {toolBits} 位 | DLL 数量: {dllPaths.Length}");
                if (targetBits != toolBits)
                {
                    log($"错误: 位数不匹配，无法注入。请使用与目标进程同位数（{targetBits} 位）的注入器版本。");
                    return false;
                }

                // QueueUserAPC 仅支持启动时注入（需要挂起线程）；对运行中进程自动降级为 CreateRemoteThread
                int useMethod = method;
                if (method == NativeMethods.INJECT_APC)
                {
                    log("提示: QueueUserAPC 仅适用于启动时注入，此处已自动改用 CreateRemoteThread。");
                    useMethod = NativeMethods.INJECT_CRT;
                }

                // 注入前 PE 体检：剔除不可用的 DLL
                dllPaths = PreflightDlls(dllPaths, targetBits, log);
                if (dllPaths.Length == 0)
                {
                    log("错误: 所有 DLL 均未通过体检，无法注入。");
                    return false;
                }

                bool allOk = true;
                var injected = new System.Collections.Generic.List<string>();
                
                foreach (var dll in dllPaths)
                {
                    log("----- 注入: " + Path.GetFileName(dll) + " -----");
                    IntPtr remoteBuf, hThread, mmModule;
                    bool injectOk = LoadLibraryIntoProcess(hProcess, IntPtr.Zero, dll, useMethod, log, out remoteBuf, out hThread, out mmModule, out bool bufBusy);
                    if (injectOk)
                    {
                        injected.Add(dll);
                        if (mmModule != IntPtr.Zero) InjectorCore.RecordMmBase(pid, dll, mmModule.ToInt64());
                        // RFI 的原始字节缓冲区保留在目标进程（供 ReflectiveLoader 回溯定位），其余方式成功后即可释放路径内存；
                        // MM 的临时内存由 ManualMapInjectIntoProcess 自行释放（remoteBuf 返回 0）。
                        if (useMethod != NativeMethods.INJECT_RFI && remoteBuf != IntPtr.Zero)
                            NativeMethods.VirtualFreeEx(hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                    }
                    else
                    {
                        allOk = false;
                        // bufBusy = 远程线程可能仍在读这块路径内存（等待超时/失败）。
                        // 此时释放就是 use-after-free：线程会从已归还的页里读路径，LoadLibraryW 拿到乱码或直接崩。
                        if (remoteBuf != IntPtr.Zero && !bufBusy)   // RFI 失败也释放已分配缓冲
                            NativeMethods.VirtualFreeEx(hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                        else if (remoteBuf != IntPtr.Zero && bufBusy)
                            log("提示: 该 DLL 的远程路径缓冲区已交由目标进程回收（避免与仍在运行的远程线程竞争）。");
                    }
                    if (hThread != IntPtr.Zero)
                        NativeMethods.CloseHandle(hThread);
                }

                // 注入后调用 DLL 导出函数
                if (!string.IsNullOrEmpty(exportFunc) && injected.Count > 0)
                {
                    if (useMethod == NativeMethods.INJECT_RFI)
                        log("提示: 反射式注入不自动调用导出函数（反射 DLL 不进模块列表且句柄截断无法可靠定位），请由 DLL 自行完成初始化。");
                    else
                        foreach (var dll in injected)
                            CallExport(hProcess, pid, dll, exportFunc, exportArg, log,
                                InjectorCore.MmBases.TryGetValue(pid + "|" + dll, out MmRecord mmRec) ? mmRec.Base : 0);
                }

                if (injected.Count > 0)
                {
                    log("----- 注入结果核验 -----");
                    foreach (var dll in injected)
                    {
                        if (useMethod == NativeMethods.INJECT_RFI)
                            log($"核验通过：{Path.GetFileName(dll)} 反射映射成功（ReflectiveLoader 返回句柄非零）。");
                        else if (useMethod == NativeMethods.INJECT_MM)
                            log($"核验通过：{Path.GetFileName(dll)} 手动映射成功（shellcode 返回完整基址 0x{(InjectorCore.MmBases.TryGetValue(pid + "|" + dll, out MmRecord mmb) ? mmb.Base : 0):X}；手动映射 DLL 不进入进程模块列表属正常）。");
                        else
                            VerifyModuleLoaded(pid, dll, log);
                    }
                }

                log(allOk ? "===== 注入到进程完成 =====" : "===== 注入到进程结束（部分 DLL 未成功）=====");
                return allOk;
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        /// <summary>批量注入：向多个目标进程逐一注入同一组 DLL，最后汇总成功 / 失败结果；至少成功 1 个返回 true</summary>
        public static bool BatchInjectProcesses(int[] pids, string[] dllPaths, int method, string exportFunc, string exportArg, Action<string> log)
        {
            log($"===== 批量注入 {pids.Length} 个进程（DLL {dllPaths.Length} 个）=====");
            int okN = 0, failN = 0;
            var failPids = new System.Collections.Generic.List<int>();
            foreach (var pid in pids)
            {
                log($"----- 目标 PID={pid} -----");
                bool r = InjectToProcess(pid, dllPaths, method, exportFunc, exportArg, log);
                if (r) okN++;
                else { failN++; failPids.Add(pid); }
            }
            log($"===== 批量注入汇总: 成功 {okN} 个，失败 {failN} 个 =====");
            if (failN > 0) log("失败 PID: " + string.Join(", ", failPids));
            return okN > 0;
        }

        /// <summary>从运行中的进程卸载 DLL（注入器侧枚举模块基址 + 远程 FreeLibrary）</summary>
        public static bool EjectDll(int pid, string dllNameOrPath, Action<string> log)
        {
            log("================ 卸载 DLL ================");
            EnableSeDebugPrivilege(log);
            if (pid <= 0) { log("错误: 无效 PID"); return false; }
            string moduleName = Path.GetFileName(dllNameOrPath.Trim().Trim('"'));
            if (string.IsNullOrEmpty(moduleName)) { log("错误: 未指定要卸载的 DLL 文件名"); return false; }

            int toolBits = IntPtr.Size * 8;
            IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ACCESS_FOR_INJECT, false, pid);
            if (hProcess == IntPtr.Zero)
            {
                log($"错误: 无法打开进程 PID={pid} - {NativeMethods.LastErrorText()}（可能需要管理员权限）");
                return false;
            }
            try
            {
                // 位数校验（与注入一致）
                bool isWow64 = false;
                int targetBits = toolBits;
                if (NativeMethods.IsWow64Process(hProcess, out isWow64))
                    targetBits = isWow64 ? 32 : 64;
                if (targetBits != toolBits)
                {
                    log($"错误: 位数不匹配。请使用与目标进程同位数（{targetBits} 位）的注入器版本。");
                    return false;
                }

                // 在注入器侧枚举目标进程模块，取得完整（64 位）模块基址。
                // 原因：远程线程退出码只有 32 位，64 位进程的模块句柄会被截断导致 FreeLibrary 失败。
                IntPtr moduleBase = IntPtr.Zero;
                try
                {
                    using var proc = System.Diagnostics.Process.GetProcessById(pid);
                    foreach (System.Diagnostics.ProcessModule m in proc.Modules)
                    {
                        try
                        {
                            if (string.Equals(Path.GetFileName(m.FileName), moduleName, StringComparison.OrdinalIgnoreCase))
                            { moduleBase = m.BaseAddress; break; }
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    log("错误: 枚举目标进程模块失败 - " + ex.Message);
                    return false;
                }
                if (moduleBase == IntPtr.Zero)
                {
                    // 枚举不到模块：可能是手动映射注入的 DLL（不在目标进程模块列表）。
                    // 查本注入器进程内记录的手动映射基址，命中则走卸载 shellcode（DllMain(DETACH) + VirtualFree）。
                    // 用之前必须再校验一次记录是否仍然可信：进程可能已退出，或 PID 已被别的进程复用。
                    // 拿陈旧基址去执行卸载，会在一个无关进程里调 DllMain(DETACH) 并 VirtualFree，破坏它。
                    long mmBase = 0;
                    string mmKey = null;
                    foreach (var kv in InjectorCore.MmBases)
                    {
                        if (!TryParseMmKey(kv.Key, out int recPid, out string recPath)) continue;
                        if (recPid != pid) continue;
                        if (!string.Equals(Path.GetFileName(recPath), moduleName, StringComparison.OrdinalIgnoreCase)) continue;

                        if (!IsMmRecordValid(pid, kv.Value.StartTicks, out string staleReason))
                        {
                            log($"忽略并清理失效的手动映射记录：{staleReason}。");
                            InjectorCore.UnrecordMmBase(kv.Key);
                            continue;
                        }
                        mmBase = kv.Value.Base; mmKey = kv.Key; break;
                    }
                    if (mmBase != 0)
                    {
                        log($"模块列表未找到 {moduleName}，命中手动映射记录（基址 0x{mmBase:X}），执行手动映射卸载...");
                        bool ok = UnmapManualMapIntoProcess(hProcess, mmBase, log);
                        if (ok) InjectorCore.UnrecordMmBase(mmKey);
                        return ok;
                    }
                    log($"未在目标进程（PID={pid}）中找到模块 {moduleName}，可能尚未注入或已卸载。");
                    return false;
                }
                log($"目标进程中模块 {moduleName} 基址: 0x{moduleBase.ToInt64():X}");

                IntPtr kernel32 = NativeMethods.GetModuleHandle("kernel32.dll");
                IntPtr freeLibrary = NativeMethods.GetProcAddress(kernel32, "FreeLibrary");
                if (freeLibrary == IntPtr.Zero)
                {
                    log("错误: 获取 FreeLibrary 地址失败。");
                    return false;
                }

                // 远程 FreeLibrary(完整基址) 卸载
                IntPtr hThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero,
                    freeLibrary, moduleBase, 0, out _);
                if (hThread == IntPtr.Zero)
                {
                    log("错误: 创建远程线程失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                try
                {
                    if (NativeMethods.WaitForSingleObject(hThread, 15000) != 0 ||
                        !NativeMethods.GetExitCodeThread(hThread, out uint freeResult))
                    {
                        log("警告: 等待 FreeLibrary 完成超时或失败。");
                        return false;
                    }
                    // FreeLibrary 返回 0 是**失败**：目标 DLL 的引用计数没减到 0（还有人持有句柄），
                    // 或者传入的基址根本不是已加载模块。原先只打日志仍 return true，
                    // 会让 GUI/CLI 报告「卸载成功」，而 DLL 其实还在目标进程里跑着 —— 这是语义错误。
                    if (freeResult == 0)
                    {
                        log($"错误: FreeLibrary 返回 0，卸载失败（DLL 仍被引用或基址无效）。");
                        return false;
                    }
                    log($"FreeLibrary 调用完成（返回 {freeResult}）。");
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }

                // 双重确认：模块列表里应该已经看不到它了。残留说明 FreeLibrary 只是减了引用计数。
                bool stillLoaded = false;
                try
                {
                    foreach (System.Diagnostics.ProcessModule pm in System.Diagnostics.Process.GetProcessById(pid).Modules)
                    {
                        if (string.Equals(pm.FileName, moduleName, StringComparison.OrdinalIgnoreCase)) { stillLoaded = true; break; }
                    }
                }
                catch { }
                if (stillLoaded)
                {
                    log("警告: FreeLibrary 已返回成功，但模块仍在目标进程模块列表中（引用计数未归零）。");
                    return false;
                }

                log("===== 卸载完成 =====");
                return true;
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        /// <summary>探测一个命名管道是否存在、是否还有空闲实例。</summary>
        /// <param name="pipeName">不带 <c>\\.\pipe\</c> 前缀的管道名。</param>
        /// <returns>0 = 不存在；1 = 存在且有空闲实例（可以立刻连上）；2 = 存在但实例全被占用；-1 = 其它错误。</returns>
        /// <remarks>
        /// 为什么用 WaitNamedPipe 而不是枚举 <c>\\.\pipe\</c>：枚举只能拿到一堆设备名，
        /// 还得自己按名字过滤；WaitNamedPipe 直接回答了「这个具体名字现在能不能连」，
        /// 而且它**不会真的建立连接**——用 CreateFile 探测会短暂占用一个实例，
        /// 服务端会看到一次「连上就断」并把该实例重建，平白制造噪音。
        /// 实测错误码（timeout 传 0）：
        ///   管道不存在 → ERROR_FILE_NOT_FOUND(2)；
        ///   存在但实例全忙 → ERROR_SEM_TIMEOUT(121)，注意这里**不是** ERROR_PIPE_BUSY(231)，
        ///   后者是 CreateFile 才会返回的码；两个都认下来最稳妥。
        /// </remarks>
        private static int ProbePipe(string pipeName)
        {
            if (string.IsNullOrEmpty(pipeName)) return 0;
            string full = @"\\.\pipe\" + pipeName;
            if (NativeMethods.WaitNamedPipe(full, 0)) return 1;
            return Marshal.GetLastWin32Error() switch
            {
                121 => 2,   // ERROR_SEM_TIMEOUT：WaitNamedPipe 等待超时 = 实例都忙着
                231 => 2,   // ERROR_PIPE_BUSY：同一语义的另一个码
                2 => 0,     // ERROR_FILE_NOT_FOUND：根本没有这个管道
                3 => 0,     // ERROR_PATH_NOT_FOUND：同上（路径形式异常时的兜底）
                _ => -1,
            };
        }

        /// <summary>只读状态查询：报告目标进程的位数、已加载模块、手动映射记录、文本 Hook 管道是否在线。</summary>
        /// <remarks>
        /// 用途是把「注入之后到底成没成」从「看日志猜」变成「一条命令问清楚」。
        /// 尤其是手动映射注入的 DLL 不进目标进程模块列表，光看任务管理器永远找不到它，
        /// 只能靠 <c>DllInjector.mmmap</c> 里的记录回答，这里就把它一并报出来。
        /// 全程只读：不挂起目标、不写内存、不改任何记录。
        /// </remarks>
        public static bool Status(int pid, string[] dllNames, string pipeName, Action<string> log)
        {
            log("================ 状态查询 ================");
            if (pid <= 0) { log("错误: 无效 PID"); return false; }

            System.Diagnostics.Process proc;
            try { proc = System.Diagnostics.Process.GetProcessById(pid); }
            catch { log($"进程 {pid} 不存在。"); return false; }

            try
            {
                log($"进程: {pid}  {proc.ProcessName}");
                try { log($"启动时间: {proc.StartTime:yyyy-MM-dd HH:mm:ss}"); }
                catch { log("启动时间: 无权限读取（权限不足）"); }

                // ---- 位数 ----
                int toolBits = IntPtr.Size * 8;
                int targetBits = 0;
                IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.PROCESS_ACCESS_FOR_INJECT, false, pid);
                if (hProcess == IntPtr.Zero)
                {
                    log($"警告: 无法打开进程 - {NativeMethods.LastErrorText()}（可能需要管理员权限）");
                }
                else
                {
                    try
                    {
                        bool wow64 = false;
                        if (NativeMethods.IsWow64Process(hProcess, out wow64)) targetBits = wow64 ? 32 : 64;
                    }
                    finally { NativeMethods.CloseHandle(hProcess); }
                }
                if (targetBits != 0)
                    log($"位数: {targetBits} 位（当前注入器 {toolBits} 位，{(targetBits == toolBits ? "匹配" : "不匹配——注入会被拦截")}）");

                // ---- 已加载模块 ----
                // 只在给了 DLL 名时逐个查；不给就只报模块总数，避免刷屏。
                var loaded = new System.Collections.Generic.Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
                int moduleCount = 0;
                try
                {
                    foreach (System.Diagnostics.ProcessModule m in proc.Modules)
                    {
                        moduleCount++;
                        try
                        {
                            string fn = Path.GetFileName(m.FileName);
                            if (!string.IsNullOrEmpty(fn) && !loaded.ContainsKey(fn)) loaded[fn] = m.BaseAddress.ToInt64();
                        }
                        catch { /* 个别模块取不到路径，跳过 */ }
                    }
                    log($"模块总数: {moduleCount}");
                }
                catch (Exception ex)
                {
                    log("警告: 无法枚举模块列表 - " + ex.Message);
                }

                if (moduleCount > 0)
                {
                    if (dllNames != null && dllNames.Length > 0)
                    {
                        foreach (var dll in dllNames)
                        {
                            string name = Path.GetFileName(dll.Trim().Trim('"'));
                            if (string.IsNullOrEmpty(name)) continue;
                            if (loaded.TryGetValue(name, out long b))
                                log($"  已加载: {name}  基址 0x{b:X}（常规注入）");
                            else
                                log($"  未在模块列表: {name}（可能没注入、已卸载，或者是手动映射——见下）");
                        }
                    }
                }

                // ---- 手动映射记录 ----
                // 这些 DLL 不在模块列表里，只有本工具的记录知道它们在哪。
                // 报之前必须校验记录是否仍然可信（进程可能已退出、PID 可能被复用）。
                bool anyMm = false;
                foreach (var kv in MmBases)
                {
                    if (!TryParseMmKey(kv.Key, out int recPid, out string recPath)) continue;
                    if (recPid != pid) continue;
                    if (dllNames != null && dllNames.Length > 0)
                    {
                        bool wanted = false;
                        foreach (var dll in dllNames)
                        {
                            if (string.Equals(Path.GetFileName(dll.Trim().Trim('"')), Path.GetFileName(recPath),
                                    StringComparison.OrdinalIgnoreCase)) { wanted = true; break; }
                        }
                        if (!wanted) continue;
                    }
                    anyMm = true;
                    string verdict = IsMmRecordValid(pid, kv.Value.StartTicks, out string why)
                        ? "记录有效" : "记录已失效: " + why;
                    log($"  手动映射记录: {Path.GetFileName(recPath)}  基址 0x{kv.Value.Base:X}（{verdict}）");
                }
                if (anyMm) log("  说明: 手动映射的 DLL 不会出现在模块列表里，只能靠上面的记录定位。");

                // ---- 文本 Hook 管道 ----
                if (!string.IsNullOrEmpty(pipeName))
                {
                    int st = ProbePipe(pipeName);
                    string text = st switch
                    {
                        0 => @"未发现（该进程可能没装文本 Hook，或 pipe= 用的不是这个名字）",
                        1 => "在线，且有空闲实例（TextHookClient 可以连上）",
                        2 => "在线，但所有实例都被占用（4 个消费者都已连上）",
                        _ => "探测失败（其它错误）",
                    };
                    log($@"文本 Hook 管道: \\.\pipe\{pipeName} — {text}");
                }

                log("===== 状态查询完成 =====");
                return true;
            }
            finally
            {
                proc.Dispose();
            }
        }

        /// <summary>在目标进程内远程调用 LoadLibraryW 加载 DLL。失败时通过 out 返回已分配资源，由调用方负责清理。
        /// <paramref name="rfiModule"/>：反射式注入成功后返回的映射模块句柄（非 RFI 时为 IntPtr.Zero）。</summary>
        private static bool LoadLibraryIntoProcess(IntPtr hProcess, IntPtr hTargetThread, string dllPath, int method, Action<string> log,
            out IntPtr remoteBuf, out IntPtr hRemoteThread, out IntPtr rfiModule, out bool remoteBufBusy)
        {
            remoteBuf = IntPtr.Zero;
            hRemoteThread = IntPtr.Zero;
            rfiModule = IntPtr.Zero;
            // remoteBufBusy = 目标进程里的那个缓冲区「可能仍被远程线程使用」。
            // 超时是唯一会产生它的路径：此时远程线程还在跑 LoadLibraryW，
            // 它的参数就是 remoteBuf。调用方若照旧 VirtualFreeEx，就会把
            // 正在被使用的字符串抹掉 → 目标进程随机崩溃或 LoadLibrary 拿到乱码路径。
            remoteBufBusy = false;

            // 反射式注入：不写路径、不调 LoadLibraryW，直接搬运原始字节 + 调用 DLL 自带 ReflectiveLoader
            if (method == NativeMethods.INJECT_RFI)
            {
                rfiModule = ReflectiveInjectIntoProcess(hProcess, dllPath, log, out remoteBuf, out hRemoteThread);
                return rfiModule != IntPtr.Zero;
            }

            // 手动映射注入：不调 LoadLibraryW，由自包含 shellcode 在目标进程内完成完整 PE 映射（普通 DLL 即可，无需自带 Loader）
            if (method == NativeMethods.INJECT_MM)
            {
                rfiModule = ManualMapInjectIntoProcess(hProcess, dllPath, log, out remoteBuf, out hRemoteThread);
                return rfiModule != IntPtr.Zero;
            }

            // 使用 LoadLibraryW，支持中文等非 ASCII 路径
            byte[] dllPathBytes = Encoding.Unicode.GetBytes(dllPath);
            remoteBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero,
                (UIntPtr)(dllPathBytes.Length + 2),
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (remoteBuf == IntPtr.Zero)
            {
                log("错误: 在目标进程分配内存失败 - " + NativeMethods.LastErrorText());
                return false;
            }

            if (!NativeMethods.WriteProcessMemory(hProcess, remoteBuf, dllPathBytes,
                    (UIntPtr)dllPathBytes.Length, out _))
            {
                log("错误: 写入 DLL 路径失败 - " + NativeMethods.LastErrorText());
                return false;
            }
            log("DLL 路径已写入目标进程内存。");

            IntPtr kernel32 = NativeMethods.GetModuleHandle("kernel32.dll");
            IntPtr loadLibraryW = NativeMethods.GetProcAddress(kernel32, "LoadLibraryW");
            if (loadLibraryW == IntPtr.Zero)
            {
                log("错误: 获取 LoadLibraryW 地址失败 - " + NativeMethods.LastErrorText());
                return false;
            }

            // 注入方式一：QueueUserAPC —— 仅启动时注入（目标主线程处于挂起态），
            // 把 LoadLibraryW 排队到 APC 队列，恢复线程后由内核在用户态执行。
            if (method == NativeMethods.INJECT_APC)
            {
                if (hTargetThread == IntPtr.Zero)
                {
                    log("错误: QueueUserAPC 方式需要目标线程句柄（仅支持启动时注入）。");
                    return false;
                }
                if (NativeMethods.QueueUserAPC(loadLibraryW, hTargetThread, (UIntPtr)remoteBuf.ToInt64()) == 0)
                {
                    log("错误: QueueUserAPC 失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                log("已将 LoadLibraryW 排队到目标主线程 APC，待线程恢复后执行（结果由注入核验确认）。");
                return true;   // hRemoteThread = 0，由调用方跳过线程等待
            }

            // 注入方式二：NtCreateThreadEx —— 直接调用 ntdll 的底层线程创建，不经过 CreateRemoteThread 的检测点。
            if (method == NativeMethods.INJECT_NTC)
            {
                int status = NativeMethods.NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero,
                    hProcess, loadLibraryW, remoteBuf, false, 0, 0, 0, IntPtr.Zero);
                if (status != 0 || hRemoteThread == IntPtr.Zero)
                {
                    log($"错误: NtCreateThreadEx 失败（NTSTATUS=0x{(uint)status:X8}）。");
                    hRemoteThread = IntPtr.Zero;   // 失败时防止无效句柄被调用方 CloseHandle
                    return false;
                }
                log("已通过 NtCreateThreadEx 创建远程线程，等待 DLL 的 DllMain 初始化完成...");
            }
            // 注入方式三（默认）：CreateRemoteThread —— 兼容性最好。
            else
            {
                hRemoteThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero,
                    loadLibraryW, remoteBuf, 0, out _);
                if (hRemoteThread == IntPtr.Zero)
                {
                    log("错误: 创建远程线程失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                log("已创建远程线程，等待 DLL 的 DllMain 初始化完成...");
            }

            uint wait = NativeMethods.WaitForSingleObject(hRemoteThread, 15000);   // 注入等待超时固定 15 秒
            if (wait == NativeMethods.WAIT_TIMEOUT)
            {
                // 远程线程还活着，而它的参数就是 remoteBuf。
                // 这里**必须**把缓冲区标记为「占用中」，让调用方放弃释放：
                // 提前 VirtualFreeEx 会把 LoadLibraryW 正在读的路径抹掉。
                remoteBufBusy = true;
                log("警告: 等待超时（15 秒），DLL 可能在 DllMain 中阻塞；路径缓冲区保留在目标进程内（远程线程仍可能在使用它），不再释放。");
                return false;
            }
            if (wait == NativeMethods.WAIT_FAILED)
            {
                // 等待本身失败 → 线程状态未知，同样不能断定它已经不再读 remoteBuf
                remoteBufBusy = true;
                log("错误: WaitForSingleObject 失败 - " + NativeMethods.LastErrorText());
                return false;
            }
            if (!NativeMethods.GetExitCodeThread(hRemoteThread, out uint code))
            {
                log("错误: GetExitCodeThread 失败 - " + NativeMethods.LastErrorText());
                return false;
            }
            if (code == 0)
            {
                log("警告: LoadLibrary 返回 0，DLL 加载失败（检查依赖 / 位数是否匹配）。");
                return false;
            }
            log($"注入成功！DLL 已加载（模块句柄 0x{code:X}）。");
            return true;
        }


        public static readonly byte[] ManualMapX64 =
        {
        0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x83, 0xEC, 0x60, 0xFC, 0x48, 0x8B, 0x01, 0x48, 0x89, 0x44, 0x24, 0x50,
        0x48, 0x8B, 0x41, 0x08, 0x48, 0x89, 0x44, 0x24, 0x48, 0xE8, 0x00, 0x00,
        0x00, 0x00, 0x5B, 0x48, 0x89, 0x5C, 0x24, 0x58, 0x48, 0x8B, 0x44, 0x24,
        0x50, 0x66, 0x81, 0x38, 0x4D, 0x5A, 0x0F, 0x85, 0xA4, 0x03, 0x00, 0x00,
        0x8B, 0x48, 0x3C, 0x48, 0x8D, 0x34, 0x08, 0x81, 0x3E, 0x50, 0x45, 0x00,
        0x00, 0x0F, 0x85, 0x91, 0x03, 0x00, 0x00, 0x0F, 0xB7, 0x46, 0x18, 0x66,
        0x3D, 0x0B, 0x02, 0x0F, 0x85, 0x83, 0x03, 0x00, 0x00, 0x48, 0x89, 0x34,
        0x24, 0x8B, 0x46, 0x50, 0x48, 0x89, 0x44, 0x24, 0x18, 0x48, 0x8B, 0x46,
        0x30, 0x48, 0x89, 0x44, 0x24, 0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,
        0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8D, 0x78, 0x20, 0x48,
        0x8B, 0x07, 0x48, 0x3B, 0xC7, 0x0F, 0x84, 0x51, 0x03, 0x00, 0x00, 0x4C,
        0x8B, 0xE8, 0x4C, 0x8B, 0x60, 0x20, 0x4D, 0x85, 0xE4, 0x74, 0x54, 0x0F,
        0xB7, 0x48, 0x48, 0x66, 0x83, 0xF9, 0x18, 0x72, 0x4A, 0x4C, 0x8B, 0x40,
        0x50, 0x48, 0x8B, 0x54, 0x24, 0x58, 0x4C, 0x8D, 0x8A, 0x57, 0x04, 0x00,
        0x00, 0x45, 0x33, 0xD2, 0x43, 0x0F, 0xB7, 0x04, 0x50, 0x43, 0x0F, 0xB6,
        0x14, 0x11, 0x83, 0xF8, 0x41, 0x72, 0x08, 0x83, 0xF8, 0x5A, 0x77, 0x03,
        0x83, 0xC8, 0x20, 0x83, 0xFA, 0x41, 0x72, 0x08, 0x83, 0xFA, 0x5A, 0x77,
        0x03, 0x83, 0xCA, 0x20, 0x3B, 0xC2, 0x75, 0x0F, 0x85, 0xC0, 0x74, 0x11,
        0x41, 0xFF, 0xC2, 0x41, 0x83, 0xFA, 0x0D, 0x72, 0xCB, 0xEB, 0x00, 0x49,
        0x8B, 0x45, 0x00, 0xEB, 0x91, 0x4C, 0x89, 0x64, 0x24, 0x28, 0x48, 0x8B,
        0x54, 0x24, 0x58, 0x4C, 0x8D, 0x82, 0x64, 0x04, 0x00, 0x00, 0xE8, 0xD9,
        0x02, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x0F, 0x84, 0xCC, 0x02, 0x00, 0x00,
        0x48, 0x89, 0x5C, 0x24, 0x30, 0x48, 0x8B, 0x54, 0x24, 0x58, 0x4C, 0x8D,
        0x82, 0x71, 0x04, 0x00, 0x00, 0xE8, 0xBA, 0x02, 0x00, 0x00, 0x48, 0x85,
        0xDB, 0x0F, 0x84, 0xAD, 0x02, 0x00, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x38,
        0x48, 0x8B, 0x54, 0x24, 0x58, 0x4C, 0x8D, 0x82, 0x7E, 0x04, 0x00, 0x00,
        0xE8, 0x9B, 0x02, 0x00, 0x00, 0x48, 0x85, 0xDB, 0x0F, 0x84, 0x8E, 0x02,
        0x00, 0x00, 0x48, 0x89, 0x5C, 0x24, 0x40, 0x48, 0x33, 0xC9, 0x48, 0x8B,
        0x54, 0x24, 0x18, 0x49, 0xC7, 0xC0, 0x00, 0x30, 0x00, 0x00, 0x49, 0xC7,
        0xC1, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x83,
        0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x85, 0xC0, 0x0F,
        0x84, 0x5B, 0x02, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0x8B,
        0x7C, 0x24, 0x08, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x48, 0x8B, 0x0C, 0x24,
        0x8B, 0x49, 0x54, 0xF3, 0xA4, 0x48, 0x8B, 0x34, 0x24, 0x0F, 0xB7, 0x4E,
        0x06, 0x48, 0x89, 0x4C, 0x24, 0x58, 0x0F, 0xB7, 0x46, 0x14, 0x48, 0x8D,
        0x76, 0x18, 0x48, 0x03, 0xF0, 0x48, 0x8B, 0x44, 0x24, 0x58, 0x48, 0x85,
        0xC0, 0x74, 0x4B, 0x48, 0xFF, 0xC8, 0x48, 0x89, 0x44, 0x24, 0x58, 0x4C,
        0x8B, 0xF6, 0x48, 0x8B, 0x7C, 0x24, 0x08, 0x41, 0x8B, 0x46, 0x0C, 0x48,
        0x03, 0xF8, 0x41, 0x8B, 0x4E, 0x10, 0x44, 0x8B, 0xE9, 0x85, 0xC9, 0x74,
        0x0E, 0x41, 0x8B, 0x46, 0x14, 0x48, 0x8B, 0x74, 0x24, 0x50, 0x48, 0x03,
        0xF0, 0xF3, 0xA4, 0x41, 0x8B, 0x46, 0x08, 0x41, 0x3B, 0xC5, 0x76, 0x09,
        0x41, 0x2B, 0xC5, 0x8B, 0xC8, 0x33, 0xC0, 0xF3, 0xAA, 0x49, 0x83, 0xC6,
        0x28, 0x49, 0x8B, 0xF6, 0xEB, 0xAB, 0x48, 0x8B, 0x44, 0x24, 0x08, 0x48,
        0x2B, 0x44, 0x24, 0x20, 0x48, 0x89, 0x44, 0x24, 0x10, 0x0F, 0x84, 0x95,
        0x00, 0x00, 0x00, 0x48, 0x8B, 0x34, 0x24, 0x8B, 0x86, 0xB0, 0x00, 0x00,
        0x00, 0x85, 0xC0, 0x0F, 0x84, 0x83, 0x00, 0x00, 0x00, 0x8B, 0x8E, 0xB4,
        0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x79, 0x48, 0x8B, 0x74, 0x24, 0x08,
        0x48, 0x03, 0xF0, 0x4C, 0x8D, 0x24, 0x0E, 0x49, 0x3B, 0xF4, 0x73, 0x68,
        0x8B, 0x46, 0x04, 0x85, 0xC0, 0x74, 0x61, 0x8B, 0x0E, 0x48, 0x8D, 0x7E,
        0x08, 0x4C, 0x8D, 0x04, 0x06, 0x49, 0x3B, 0xF8, 0x73, 0x4D, 0x0F, 0xB7,
        0x07, 0x8B, 0xD0, 0x81, 0xE2, 0xFF, 0x0F, 0x00, 0x00, 0xC1, 0xE8, 0x0C,
        0x83, 0xF8, 0x0A, 0x74, 0x07, 0x83, 0xF8, 0x03, 0x74, 0x1A, 0xEB, 0x2D,
        0x4C, 0x8B, 0x4C, 0x24, 0x08, 0x4C, 0x03, 0xC9, 0x4C, 0x03, 0xCA, 0x49,
        0x8B, 0x01, 0x48, 0x03, 0x44, 0x24, 0x10, 0x49, 0x89, 0x01, 0xEB, 0x15,
        0x4C, 0x8B, 0x4C, 0x24, 0x08, 0x4C, 0x03, 0xC9, 0x4C, 0x03, 0xCA, 0x41,
        0x8B, 0x01, 0x03, 0x44, 0x24, 0x10, 0x41, 0x89, 0x01, 0x48, 0x83, 0xC7,
        0x02, 0xEB, 0xAE, 0x49, 0x8B, 0xF0, 0xEB, 0x93, 0x48, 0x8B, 0x34, 0x24,
        0x8B, 0x86, 0x90, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x84, 0xCA, 0x00,
        0x00, 0x00, 0x8B, 0x8E, 0x94, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x0F, 0x84,
        0xBC, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x74, 0x24, 0x08, 0x48, 0x03, 0xF0,
        0x8B, 0x46, 0x0C, 0x85, 0xC0, 0x0F, 0x84, 0xA9, 0x00, 0x00, 0x00, 0x4C,
        0x8B, 0xEE, 0x48, 0x8B, 0x7C, 0x24, 0x08, 0x48, 0x03, 0xF8, 0x48, 0x8B,
        0xCF, 0x48, 0x8B, 0x44, 0x24, 0x38, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x20, 0x48, 0x85, 0xC0, 0x74, 0x7B, 0x48, 0x89, 0x44,
        0x24, 0x58, 0x41, 0x8B, 0x45, 0x00, 0x85, 0xC0, 0x75, 0x04, 0x41, 0x8B,
        0x45, 0x10, 0x4C, 0x8B, 0x74, 0x24, 0x08, 0x4C, 0x03, 0xF0, 0x41, 0x8B,
        0x45, 0x10, 0x4C, 0x8B, 0x7C, 0x24, 0x08, 0x4C, 0x03, 0xF8, 0x49, 0x8B,
        0x06, 0x48, 0x85, 0xC0, 0x74, 0x4E, 0x48, 0x0F, 0xBA, 0xE0, 0x3F, 0x72,
        0x23, 0x48, 0x8B, 0x7C, 0x24, 0x08, 0x48, 0x8D, 0x7C, 0x07, 0x02, 0x48,
        0x8B, 0x4C, 0x24, 0x58, 0x48, 0x8B, 0xD7, 0x48, 0x8B, 0x44, 0x24, 0x40,
        0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0xEB, 0x17,
        0x48, 0x8B, 0x4C, 0x24, 0x58, 0x0F, 0xB7, 0xD0, 0x48, 0x8B, 0x44, 0x24,
        0x40, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0x49,
        0x89, 0x07, 0x49, 0x83, 0xC6, 0x08, 0x49, 0x83, 0xC7, 0x08, 0xEB, 0xAA,
        0x49, 0x83, 0xC5, 0x14, 0x49, 0x8B, 0xF5, 0xE9, 0x4C, 0xFF, 0xFF, 0xFF,
        0x48, 0x8B, 0x04, 0x24, 0x8B, 0x40, 0x28, 0x85, 0xC0, 0x74, 0x21, 0x48,
        0x8B, 0x4C, 0x24, 0x08, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00, 0x4D,
        0x33, 0xC0, 0x4C, 0x8B, 0x4C, 0x24, 0x08, 0x49, 0x03, 0xC1, 0x48, 0x83,
        0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x8B, 0x44, 0x24,
        0x08, 0x48, 0x8B, 0x4C, 0x24, 0x48, 0x48, 0x85, 0xC9, 0x74, 0x03, 0x48,
        0x89, 0x01, 0x8B, 0xC0, 0x48, 0x83, 0xC4, 0x60, 0x41, 0x5F, 0x41, 0x5E,
        0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5B, 0xC3, 0x33, 0xC0, 0xEB, 0xEC,
        0x41, 0x0F, 0xB7, 0x04, 0x24, 0x66, 0x3D, 0x4D, 0x5A, 0x0F, 0x85, 0x86,
        0x00, 0x00, 0x00, 0x41, 0x8B, 0x4C, 0x24, 0x3C, 0x49, 0x8D, 0x34, 0x0C,
        0x81, 0x3E, 0x50, 0x45, 0x00, 0x00, 0x75, 0x75, 0x8B, 0x86, 0x88, 0x00,
        0x00, 0x00, 0x85, 0xC0, 0x74, 0x6B, 0x49, 0x8D, 0x3C, 0x04, 0x8B, 0x47,
        0x18, 0x85, 0xC0, 0x74, 0x60, 0x44, 0x8B, 0xD8, 0x8B, 0x47, 0x20, 0x4D,
        0x8D, 0x2C, 0x04, 0x8B, 0x47, 0x24, 0x4D, 0x8D, 0x34, 0x04, 0x8B, 0x47,
        0x1C, 0x4D, 0x8D, 0x3C, 0x04, 0x45, 0x33, 0xD2, 0x45, 0x85, 0xDB, 0x74,
        0x40, 0x41, 0xFF, 0xCB, 0x43, 0x8B, 0x44, 0x95, 0x00, 0x49, 0x8D, 0x34,
        0x04, 0x53, 0x41, 0x50, 0x33, 0xC9, 0x8A, 0x04, 0x0E, 0x41, 0x8A, 0x1C,
        0x08, 0x3A, 0xC3, 0x75, 0x09, 0x84, 0xC0, 0x74, 0x0D, 0x48, 0xFF, 0xC1,
        0xEB, 0xEC, 0x41, 0x58, 0x5B, 0x41, 0xFF, 0xC2, 0xEB, 0xCE, 0x41, 0x58,
        0x5B, 0x43, 0x0F, 0xB7, 0x04, 0x56, 0x41, 0x8B, 0x04, 0x87, 0x49, 0x03,
        0xC4, 0x48, 0x8B, 0xD8, 0xC3, 0x48, 0x33, 0xDB, 0xC3, 0x6B, 0x65, 0x72,
        0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x56, 0x69,
        0x72, 0x74, 0x75, 0x61, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x00, 0x4C,
        0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00,
        0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65,
        0x73, 0x73,
        };
        public static readonly byte[] ManualMapX86 =
        {
        0x53, 0x56, 0x57, 0x55, 0x83, 0xEC, 0x4C, 0xFC, 0x8B, 0x44, 0x24, 0x60,
        0x8B, 0x08, 0x89, 0x4C, 0x24, 0x28, 0x8B, 0x48, 0x04, 0x89, 0x4C, 0x24,
        0x24, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x89, 0x5C, 0x24, 0x2C, 0x8B,
        0x44, 0x24, 0x28, 0x66, 0x81, 0x38, 0x4D, 0x5A, 0x0F, 0x85, 0xC1, 0x02,
        0x00, 0x00, 0x8B, 0x48, 0x3C, 0x8D, 0x34, 0x08, 0x81, 0x3E, 0x50, 0x45,
        0x00, 0x00, 0x0F, 0x85, 0xAF, 0x02, 0x00, 0x00, 0x0F, 0xB7, 0x46, 0x18,
        0x66, 0x3D, 0x0B, 0x01, 0x0F, 0x85, 0xA1, 0x02, 0x00, 0x00, 0x89, 0x34,
        0x24, 0x8B, 0x46, 0x50, 0x89, 0x44, 0x24, 0x0C, 0x8B, 0x46, 0x34, 0x89,
        0x44, 0x24, 0x10, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00, 0x8B, 0x40, 0x0C,
        0x8D, 0x78, 0x1C, 0x8B, 0x07, 0x89, 0x44, 0x24, 0x34, 0x3B, 0xC7, 0x0F,
        0x84, 0x76, 0x02, 0x00, 0x00, 0x8B, 0x50, 0x08, 0x85, 0xD2, 0x74, 0x4C,
        0x0F, 0xB7, 0x48, 0x1C, 0x66, 0x83, 0xF9, 0x18, 0x72, 0x42, 0x8B, 0x70,
        0x20, 0x8B, 0x4C, 0x24, 0x2C, 0x8D, 0xA9, 0x69, 0x03, 0x00, 0x00, 0x33,
        0xC9, 0x0F, 0xB7, 0x04, 0x4E, 0x0F, 0xB6, 0x54, 0x0D, 0x00, 0x83, 0xF8,
        0x41, 0x72, 0x08, 0x83, 0xF8, 0x5A, 0x77, 0x03, 0x83, 0xC8, 0x20, 0x83,
        0xFA, 0x41, 0x72, 0x08, 0x83, 0xFA, 0x5A, 0x77, 0x03, 0x83, 0xCA, 0x20,
        0x3B, 0xC2, 0x75, 0x0C, 0x85, 0xC0, 0x74, 0x10, 0x41, 0x83, 0xF9, 0x0D,
        0x72, 0xCF, 0xEB, 0x00, 0x8B, 0x44, 0x24, 0x34, 0x8B, 0x00, 0xEB, 0x99,
        0x8B, 0x44, 0x24, 0x34, 0x8B, 0x40, 0x08, 0x89, 0x44, 0x24, 0x14, 0x8B,
        0x7C, 0x24, 0x14, 0x8B, 0x4C, 0x24, 0x2C, 0x8D, 0xB1, 0x76, 0x03, 0x00,
        0x00, 0xE8, 0x01, 0x02, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x84, 0xF5, 0x01,
        0x00, 0x00, 0x89, 0x44, 0x24, 0x18, 0x8B, 0x4C, 0x24, 0x2C, 0x8D, 0xB1,
        0x83, 0x03, 0x00, 0x00, 0xE8, 0xE6, 0x01, 0x00, 0x00, 0x85, 0xC0, 0x0F,
        0x84, 0xDA, 0x01, 0x00, 0x00, 0x89, 0x44, 0x24, 0x1C, 0x8B, 0x4C, 0x24,
        0x2C, 0x8D, 0xB1, 0x90, 0x03, 0x00, 0x00, 0xE8, 0xCB, 0x01, 0x00, 0x00,
        0x85, 0xC0, 0x0F, 0x84, 0xBF, 0x01, 0x00, 0x00, 0x89, 0x44, 0x24, 0x20,
        0x8B, 0x44, 0x24, 0x0C, 0x6A, 0x40, 0x68, 0x00, 0x30, 0x00, 0x00, 0x50,
        0x6A, 0x00, 0x8B, 0x4C, 0x24, 0x28, 0xFF, 0xD1, 0x85, 0xC0, 0x0F, 0x84,
        0x9F, 0x01, 0x00, 0x00, 0x89, 0x44, 0x24, 0x04, 0x8B, 0xF8, 0x8B, 0x74,
        0x24, 0x28, 0x8B, 0x0C, 0x24, 0x8B, 0x49, 0x54, 0xF3, 0xA4, 0x8B, 0x34,
        0x24, 0x0F, 0xB7, 0x4E, 0x06, 0x89, 0x4C, 0x24, 0x30, 0x0F, 0xB7, 0x46,
        0x14, 0x8D, 0x76, 0x18, 0x03, 0xF0, 0x8B, 0x44, 0x24, 0x30, 0x85, 0xC0,
        0x74, 0x3A, 0x48, 0x89, 0x44, 0x24, 0x30, 0x8B, 0xEE, 0x8B, 0x7C, 0x24,
        0x04, 0x8B, 0x45, 0x0C, 0x03, 0xF8, 0x8B, 0x4D, 0x10, 0x8B, 0xD9, 0x85,
        0xC9, 0x74, 0x0B, 0x8B, 0x45, 0x14, 0x8B, 0x74, 0x24, 0x28, 0x03, 0xF0,
        0xF3, 0xA4, 0x8B, 0x45, 0x08, 0x3B, 0xC3, 0x76, 0x08, 0x2B, 0xC3, 0x8B,
        0xC8, 0x33, 0xC0, 0xF3, 0xAA, 0x83, 0xC5, 0x28, 0x8B, 0xF5, 0xEB, 0xBE,
        0x8B, 0x44, 0x24, 0x04, 0x2B, 0x44, 0x24, 0x10, 0x89, 0x44, 0x24, 0x08,
        0x74, 0x63, 0x8B, 0x34, 0x24, 0x8B, 0x86, 0xA0, 0x00, 0x00, 0x00, 0x85,
        0xC0, 0x74, 0x56, 0x8B, 0x8E, 0xA4, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74,
        0x4C, 0x8B, 0x74, 0x24, 0x04, 0x03, 0xF0, 0x8D, 0x2C, 0x0E, 0x3B, 0xF5,
        0x73, 0x3F, 0x8B, 0x46, 0x04, 0x85, 0xC0, 0x74, 0x38, 0x8B, 0x0E, 0x8D,
        0x7E, 0x08, 0x8D, 0x14, 0x06, 0x3B, 0xFA, 0x73, 0x28, 0x0F, 0xB7, 0x07,
        0x8B, 0xD8, 0x81, 0xE3, 0xFF, 0x0F, 0x00, 0x00, 0xC1, 0xE8, 0x0C, 0x83,
        0xF8, 0x03, 0x75, 0x10, 0x8B, 0x44, 0x24, 0x04, 0x03, 0xC1, 0x03, 0xC3,
        0x8B, 0x18, 0x03, 0x5C, 0x24, 0x08, 0x89, 0x18, 0x83, 0xC7, 0x02, 0xEB,
        0xD4, 0x8B, 0xF2, 0xEB, 0xBD, 0x8B, 0x34, 0x24, 0x8B, 0x86, 0x80, 0x00,
        0x00, 0x00, 0x85, 0xC0, 0x0F, 0x84, 0x87, 0x00, 0x00, 0x00, 0x8B, 0x8E,
        0x84, 0x00, 0x00, 0x00, 0x85, 0xC9, 0x74, 0x7D, 0x8B, 0x74, 0x24, 0x04,
        0x03, 0xF0, 0x8B, 0x46, 0x0C, 0x85, 0xC0, 0x74, 0x70, 0x8B, 0xEE, 0x8B,
        0x7C, 0x24, 0x04, 0x03, 0xF8, 0x57, 0x8B, 0x4C, 0x24, 0x20, 0xFF, 0xD1,
        0x85, 0xC0, 0x74, 0x56, 0x89, 0x44, 0x24, 0x30, 0x8B, 0x45, 0x00, 0x85,
        0xC0, 0x75, 0x03, 0x8B, 0x45, 0x10, 0x8B, 0x74, 0x24, 0x04, 0x03, 0xF0,
        0x8B, 0x45, 0x10, 0x8B, 0x7C, 0x24, 0x04, 0x03, 0xF8, 0x8B, 0x06, 0x85,
        0xC0, 0x74, 0x33, 0xA9, 0x00, 0x00, 0x00, 0x80, 0x75, 0x14, 0x03, 0x44,
        0x24, 0x04, 0x83, 0xC0, 0x02, 0x50, 0xFF, 0x74, 0x24, 0x34, 0x8B, 0x4C,
        0x24, 0x28, 0xFF, 0xD1, 0xEB, 0x0E, 0x0F, 0xB7, 0xC0, 0x50, 0xFF, 0x74,
        0x24, 0x34, 0x8B, 0x4C, 0x24, 0x28, 0xFF, 0xD1, 0x89, 0x07, 0x83, 0xC6,
        0x04, 0x83, 0xC7, 0x04, 0xEB, 0xC7, 0x83, 0xC5, 0x14, 0x8B, 0xF5, 0xEB,
        0x89, 0x8B, 0x04, 0x24, 0x8B, 0x40, 0x28, 0x85, 0xC0, 0x74, 0x0E, 0x03,
        0x44, 0x24, 0x04, 0x6A, 0x00, 0x6A, 0x01, 0xFF, 0x74, 0x24, 0x0C, 0xFF,
        0xD0, 0x8B, 0x44, 0x24, 0x04, 0x8B, 0x4C, 0x24, 0x24, 0x85, 0xC9, 0x74,
        0x02, 0x89, 0x01, 0x83, 0xC4, 0x4C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3, 0x33,
        0xC0, 0xEB, 0xF4, 0x66, 0x81, 0x3F, 0x4D, 0x5A, 0x0F, 0x85, 0x82, 0x00,
        0x00, 0x00, 0x8B, 0x4F, 0x3C, 0x8D, 0x14, 0x0F, 0x81, 0x3A, 0x50, 0x45,
        0x00, 0x00, 0x75, 0x74, 0x8B, 0x4A, 0x78, 0x85, 0xC9, 0x74, 0x6D, 0x8D,
        0x2C, 0x0F, 0x8B, 0x4D, 0x18, 0x85, 0xC9, 0x74, 0x63, 0x51, 0x6A, 0x00,
        0x8B, 0x45, 0x24, 0x03, 0xC7, 0x50, 0x8B, 0x45, 0x1C, 0x03, 0xC7, 0x50,
        0x8B, 0x45, 0x20, 0x03, 0xC7, 0x8B, 0xD8, 0x8B, 0x44, 0x24, 0x0C, 0x85,
        0xC0, 0x74, 0x42, 0x48, 0x89, 0x44, 0x24, 0x0C, 0x8B, 0x44, 0x24, 0x08,
        0x8B, 0x0C, 0x83, 0x03, 0xCF, 0x33, 0xC0, 0x8A, 0x14, 0x01, 0x8A, 0x34,
        0x06, 0x3A, 0xD6, 0x75, 0x0A, 0x84, 0xD2, 0x74, 0x0C, 0x40, 0x83, 0xF8,
        0x40, 0x72, 0xEC, 0xFF, 0x44, 0x24, 0x08, 0xEB, 0xCE, 0x8B, 0x44, 0x24,
        0x08, 0x8B, 0x4C, 0x24, 0x04, 0x0F, 0xB7, 0x04, 0x41, 0x8B, 0x0C, 0x24,
        0x8B, 0x04, 0x81, 0x03, 0xC7, 0x83, 0xC4, 0x10, 0xC3, 0x83, 0xC4, 0x10,
        0x33, 0xC0, 0xC3, 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32, 0x2E,
        0x64, 0x6C, 0x6C, 0x00, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41,
        0x6C, 0x6C, 0x6F, 0x63, 0x00, 0x4C, 0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62,
        0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F,
        0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73,
        };

        /// <summary>手动映射 DLL 卸载 shellcode（x64）：目标进程内调用 DllMain(DLL_PROCESS_DETACH) 后释放映射镜像内存。入口 RCX = MmUnmapArgs 指针（{ QWORD moduleBase; }），返回 1 成功 / 0 失败。</summary>
        public static readonly byte[] UnmapDllX64 =
        {
        0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48,
        0x83, 0xEC, 0x50, 0xFC, 0x48, 0x89, 0x4C, 0x24, 0x20, 0x48, 0x8B, 0x01,
        0x48, 0x89, 0x44, 0x24, 0x08, 0x48, 0x85, 0xC0, 0x0F, 0x84, 0x2D, 0x01,
        0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x48, 0x89, 0x5C, 0x24,
        0x28, 0x48, 0x8B, 0xD8, 0x66, 0x81, 0x3B, 0x4D, 0x5A, 0x0F, 0x85, 0x14,
        0x01, 0x00, 0x00, 0x8B, 0x4B, 0x3C, 0x48, 0x8D, 0x34, 0x0B, 0x81, 0x3E,
        0x50, 0x45, 0x00, 0x00, 0x0F, 0x85, 0x01, 0x01, 0x00, 0x00, 0x48, 0x89,
        0x34, 0x24, 0x8B, 0x46, 0x28, 0x85, 0xC0, 0x74, 0x1C, 0x48, 0x8B, 0x4C,
        0x24, 0x08, 0x33, 0xD2, 0x45, 0x33, 0xC0, 0x4C, 0x8B, 0x4C, 0x24, 0x08,
        0x49, 0x03, 0xC1, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4,
        0x20, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x48, 0x8B,
        0x40, 0x18, 0x48, 0x8D, 0x78, 0x20, 0x48, 0x8B, 0x07, 0x48, 0x3B, 0xC7,
        0x0F, 0x84, 0xBD, 0x00, 0x00, 0x00, 0x4C, 0x8B, 0xE8, 0x4C, 0x8B, 0x60,
        0x20, 0x4D, 0x85, 0xE4, 0x74, 0x54, 0x0F, 0xB7, 0x48, 0x48, 0x66, 0x83,
        0xF9, 0x18, 0x72, 0x4A, 0x4C, 0x8B, 0x40, 0x50, 0x48, 0x8B, 0x54, 0x24,
        0x28, 0x4C, 0x8D, 0x8A, 0xC5, 0x01, 0x00, 0x00, 0x45, 0x33, 0xD2, 0x43,
        0x0F, 0xB7, 0x04, 0x50, 0x43, 0x0F, 0xB6, 0x14, 0x11, 0x83, 0xF8, 0x41,
        0x72, 0x08, 0x83, 0xF8, 0x5A, 0x77, 0x03, 0x83, 0xC8, 0x20, 0x83, 0xFA,
        0x41, 0x72, 0x08, 0x83, 0xFA, 0x5A, 0x77, 0x03, 0x83, 0xCA, 0x20, 0x3B,
        0xC2, 0x75, 0x0F, 0x85, 0xC0, 0x74, 0x11, 0x41, 0xFF, 0xC2, 0x41, 0x83,
        0xFA, 0x0D, 0x72, 0xCB, 0xEB, 0x00, 0x49, 0x8B, 0x45, 0x00, 0xEB, 0x91,
        0x4C, 0x89, 0x64, 0x24, 0x10, 0x48, 0x8B, 0x54, 0x24, 0x28, 0x4C, 0x8D,
        0x82, 0xD2, 0x01, 0x00, 0x00, 0xE8, 0x45, 0x00, 0x00, 0x00, 0x48, 0x85,
        0xDB, 0x74, 0x3C, 0x48, 0x89, 0x5C, 0x24, 0x18, 0x48, 0x8B, 0x4C, 0x24,
        0x08, 0x48, 0x33, 0xD2, 0x41, 0xB8, 0x00, 0x80, 0x00, 0x00, 0x48, 0x8B,
        0x44, 0x24, 0x18, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD0, 0x48, 0x83, 0xC4,
        0x20, 0x48, 0x85, 0xC0, 0x74, 0x15, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x48,
        0x83, 0xC4, 0x50, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F,
        0x5E, 0x5B, 0xC3, 0x33, 0xC0, 0xEB, 0xEC, 0x41, 0x0F, 0xB7, 0x04, 0x24,
        0x66, 0x3D, 0x4D, 0x5A, 0x0F, 0x85, 0x86, 0x00, 0x00, 0x00, 0x41, 0x8B,
        0x4C, 0x24, 0x3C, 0x49, 0x8D, 0x34, 0x0C, 0x81, 0x3E, 0x50, 0x45, 0x00,
        0x00, 0x75, 0x75, 0x8B, 0x86, 0x88, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74,
        0x6B, 0x49, 0x8D, 0x3C, 0x04, 0x8B, 0x47, 0x18, 0x85, 0xC0, 0x74, 0x60,
        0x44, 0x8B, 0xD8, 0x8B, 0x47, 0x20, 0x4D, 0x8D, 0x2C, 0x04, 0x8B, 0x47,
        0x24, 0x4D, 0x8D, 0x34, 0x04, 0x8B, 0x47, 0x1C, 0x4D, 0x8D, 0x3C, 0x04,
        0x45, 0x33, 0xD2, 0x45, 0x85, 0xDB, 0x74, 0x40, 0x41, 0xFF, 0xCB, 0x43,
        0x8B, 0x44, 0x95, 0x00, 0x49, 0x8D, 0x34, 0x04, 0x53, 0x41, 0x50, 0x33,
        0xC9, 0x8A, 0x04, 0x0E, 0x41, 0x8A, 0x1C, 0x08, 0x3A, 0xC3, 0x75, 0x09,
        0x84, 0xC0, 0x74, 0x0D, 0x48, 0xFF, 0xC1, 0xEB, 0xEC, 0x41, 0x58, 0x5B,
        0x41, 0xFF, 0xC2, 0xEB, 0xCE, 0x41, 0x58, 0x5B, 0x43, 0x0F, 0xB7, 0x04,
        0x56, 0x41, 0x8B, 0x04, 0x87, 0x49, 0x03, 0xC4, 0x48, 0x8B, 0xD8, 0xC3,
        0x48, 0x33, 0xDB, 0xC3, 0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x33, 0x32,
        0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C,
        0x46, 0x72, 0x65, 0x65,
        };

        /// <summary>手动映射 DLL 卸载 shellcode（x86）：同上。入口 [esp+4] = MmUnmapArgs 指针（{ DWORD moduleBase; }）。</summary>
        public static readonly byte[] UnmapDllX86 =
        {
        0x53, 0x56, 0x57, 0x55, 0x83, 0xEC, 0x20, 0xFC, 0x8B, 0x44, 0x24, 0x34,
        0x8B, 0x00, 0x89, 0x04, 0x24, 0x85, 0xC0, 0x0F, 0x84, 0xFE, 0x00, 0x00,
        0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x89, 0x5C, 0x24, 0x10, 0x8B,
        0xD8, 0x66, 0x81, 0x3B, 0x4D, 0x5A, 0x0F, 0x85, 0xE7, 0x00, 0x00, 0x00,
        0x8B, 0x4B, 0x3C, 0x8D, 0x34, 0x0B, 0x81, 0x3E, 0x50, 0x45, 0x00, 0x00,
        0x0F, 0x85, 0xD5, 0x00, 0x00, 0x00, 0x89, 0x74, 0x24, 0x04, 0x8B, 0x46,
        0x28, 0x85, 0xC0, 0x74, 0x0D, 0x03, 0x04, 0x24, 0x6A, 0x00, 0x6A, 0x00,
        0xFF, 0x74, 0x24, 0x0C, 0xFF, 0xD0, 0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,
        0x8B, 0x40, 0x0C, 0x8D, 0x78, 0x1C, 0x8B, 0x07, 0x89, 0x44, 0x24, 0x14,
        0x3B, 0xC7, 0x0F, 0x84, 0xA3, 0x00, 0x00, 0x00, 0x8B, 0x50, 0x08, 0x85,
        0xD2, 0x74, 0x4C, 0x0F, 0xB7, 0x48, 0x1C, 0x66, 0x83, 0xF9, 0x18, 0x72,
        0x42, 0x8B, 0x70, 0x20, 0x8B, 0x4C, 0x24, 0x10, 0x8D, 0xA9, 0x8D, 0x01,
        0x00, 0x00, 0x33, 0xC9, 0x0F, 0xB7, 0x04, 0x4E, 0x0F, 0xB6, 0x54, 0x0D,
        0x00, 0x83, 0xF8, 0x41, 0x72, 0x08, 0x83, 0xF8, 0x5A, 0x77, 0x03, 0x83,
        0xC8, 0x20, 0x83, 0xFA, 0x41, 0x72, 0x08, 0x83, 0xFA, 0x5A, 0x77, 0x03,
        0x83, 0xCA, 0x20, 0x3B, 0xC2, 0x75, 0x0C, 0x85, 0xC0, 0x74, 0x10, 0x41,
        0x83, 0xF9, 0x0D, 0x72, 0xCF, 0xEB, 0x00, 0x8B, 0x44, 0x24, 0x14, 0x8B,
        0x00, 0xEB, 0x99, 0x8B, 0x44, 0x24, 0x14, 0x8B, 0x40, 0x08, 0x89, 0x44,
        0x24, 0x08, 0x8B, 0x7C, 0x24, 0x08, 0x8B, 0x4C, 0x24, 0x10, 0x8D, 0xB1,
        0x9A, 0x01, 0x00, 0x00, 0xE8, 0x2E, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74,
        0x26, 0x89, 0x44, 0x24, 0x0C, 0x8B, 0x04, 0x24, 0x68, 0x00, 0x80, 0x00,
        0x00, 0x6A, 0x00, 0x50, 0x8B, 0x4C, 0x24, 0x18, 0xFF, 0xD1, 0x85, 0xC0,
        0x74, 0x0D, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x83, 0xC4, 0x20, 0x5D, 0x5F,
        0x5E, 0x5B, 0xC3, 0x33, 0xC0, 0xEB, 0xF4, 0x66, 0x81, 0x3F, 0x4D, 0x5A,
        0x0F, 0x85, 0x82, 0x00, 0x00, 0x00, 0x8B, 0x4F, 0x3C, 0x8D, 0x14, 0x0F,
        0x81, 0x3A, 0x50, 0x45, 0x00, 0x00, 0x75, 0x74, 0x8B, 0x4A, 0x78, 0x85,
        0xC9, 0x74, 0x6D, 0x8D, 0x2C, 0x0F, 0x8B, 0x4D, 0x18, 0x85, 0xC9, 0x74,
        0x63, 0x51, 0x6A, 0x00, 0x8B, 0x45, 0x24, 0x03, 0xC7, 0x50, 0x8B, 0x45,
        0x1C, 0x03, 0xC7, 0x50, 0x8B, 0x45, 0x20, 0x03, 0xC7, 0x8B, 0xD8, 0x8B,
        0x44, 0x24, 0x0C, 0x85, 0xC0, 0x74, 0x42, 0x48, 0x89, 0x44, 0x24, 0x0C,
        0x8B, 0x44, 0x24, 0x08, 0x8B, 0x0C, 0x83, 0x03, 0xCF, 0x33, 0xC0, 0x8A,
        0x14, 0x01, 0x8A, 0x34, 0x06, 0x3A, 0xD6, 0x75, 0x0A, 0x84, 0xD2, 0x74,
        0x0C, 0x40, 0x83, 0xF8, 0x40, 0x72, 0xEC, 0xFF, 0x44, 0x24, 0x08, 0xEB,
        0xCE, 0x8B, 0x44, 0x24, 0x08, 0x8B, 0x4C, 0x24, 0x04, 0x0F, 0xB7, 0x04,
        0x41, 0x8B, 0x0C, 0x24, 0x8B, 0x04, 0x81, 0x03, 0xC7, 0x83, 0xC4, 0x10,
        0xC3, 0x83, 0xC4, 0x10, 0x33, 0xC0, 0xC3, 0x6B, 0x65, 0x72, 0x6E, 0x65,
        0x6C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x56, 0x69, 0x72, 0x74,
        0x75, 0x61, 0x6C, 0x46, 0x72, 0x65, 0x65,
        };

        /// <summary>把目标进程里刚写入的 shellcode 页从 RW 提升为 RX。
        /// 写入和执行分成两个阶段：分配时用 PAGE_READWRITE（不可执行），写完再改成 PAGE_EXECUTE_READ。
        /// 这样这块内存在整个生命周期里从来不是「可写且可执行」，不会成为 EDR / 漏洞利用最爱的 RWX 页。
        /// 改完必须 FlushInstructionCache：目标进程的指令缓存不会自动感知我们自己写进去的字节。</summary>
        private static bool SealShellcodePage(IntPtr hProcess, IntPtr buf, int size, Action<string> log)
        {
            if (!NativeMethods.VirtualProtectEx(hProcess, buf, (UIntPtr)size, NativeMethods.PAGE_EXECUTE_READ, out uint oldProtect))
            {
                log("警告: 把 shellcode 页改为 RX 失败 - " + NativeMethods.LastErrorText() + "（继续执行，该页仍可写）。");
                return false;
            }
            NativeMethods.FlushInstructionCache(hProcess, buf, (UIntPtr)size);
            return true;
        }

        /// <summary>手动映射注入（Manual Map）：把 DLL 文件字节与一段自包含、位置无关的映射 shellcode 写入目标进程，
        /// 创建远程线程执行 shellcode。Shellcode 在目标进程内不调用 LoadLibraryW 完成整个 PE 映射：
        /// 校验 PE 头 → PEB 定位 kernel32 → 解析导出表拿 VirtualAlloc / LoadLibraryA / GetProcAddress →
        /// 分配 SizeOfImage 内存 → 复制头部与各节（文件偏移）→ 重定位（DIR64 / HIGHLOW）→ 填 IAT →
        /// 调 DllMain(DLL_PROCESS_ATTACH)，最后把完整模块基址写回结果区。
        /// 与反射式注入的区别：反射式要求 DLL 自带 ReflectiveLoader（由 DLL 完成映射）；手动映射由注入器提供的
        /// shellcode 完成全部映射，普通 DLL 即可注入，且完全绕开基于 LoadLibrary 挂钩的检测点（EDR / 杀软常监控）。
        /// <returns>映射后的完整模块基址（经结果区读回，64 位不截断）；0 表示失败。</returns></summary>
        private static IntPtr ManualMapInjectIntoProcess(IntPtr hProcess, string dllPath, Action<string> log,
            out IntPtr remoteBuf, out IntPtr hRemoteThread)
        {
            remoteBuf = IntPtr.Zero;
            hRemoteThread = IntPtr.Zero;

            // 1. 读取 DLL 文件字节并校验 PE
            byte[] raw;
            try { raw = File.ReadAllBytes(dllPath); }
            catch (Exception ex) { log("错误: 读取 DLL 文件失败 - " + ex.Message); return IntPtr.Zero; }
            if (raw.Length < 0x40 || BitConverter.ToUInt16(raw, 0) != 0x5A4D)
            { log("错误: 文件不是有效的 PE 文件（缺少 MZ 头）。"); return IntPtr.Zero; }
            int peOff = BitConverter.ToInt32(raw, 0x3C);
            if (peOff + 0x40 > raw.Length || BitConverter.ToUInt32(raw, peOff) != 0x4550)
            { log("错误: PE 头无效。"); return IntPtr.Zero; }
            ushort magic = BitConverter.ToUInt16(raw, peOff + 0x18);
            if (magic != 0x20B && magic != 0x10B)
            { log("错误: 不支持的 PE 格式。"); return IntPtr.Zero; }
            bool is32 = (magic == 0x10B);

            // 2. 按位数选择 shellcode（x86 注入器 → 32 位目标；x64 注入器 → 64 位目标）
            byte[] sc = is32 ? ManualMapX86 : ManualMapX64;
            int ptrSize = IntPtr.Size;

            // 3. 目标进程内分配：rawBuf(DLL 字节) + argsBuf(MmArgs + 结果区) + scBuf(shellcode)
            //    MmArgs 布局（x64：QWORD dllRaw + QWORD resultPtr + QWORD result；x86 对应 DWORD）
            IntPtr rawBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)raw.Length,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (rawBuf == IntPtr.Zero)
            { log("错误: 在目标进程分配 DLL 字节内存失败 - " + NativeMethods.LastErrorText()); return IntPtr.Zero; }

            int argsSize = ptrSize * 3;
            IntPtr argsBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)argsSize,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (argsBuf == IntPtr.Zero)
            {
                log("错误: 在目标进程分配参数内存失败 - " + NativeMethods.LastErrorText());
                NativeMethods.VirtualFreeEx(hProcess, rawBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return IntPtr.Zero;
            }

            // shellcode 页先按 RW 分配（不可执行），写完字节后再 VirtualProtect 成 RX。
            // 绝不用 PAGE_EXECUTE_READWRITE 分配：那会让这块页在整个生命周期里既写又执行，
            // 是 EDR / 漏洞利用最典型的特征，也违反 DEP 的基本意图。
            IntPtr scBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)sc.Length,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (scBuf == IntPtr.Zero)
            {
                log("错误: 在目标进程分配 shellcode 内存失败 - " + NativeMethods.LastErrorText());
                NativeMethods.VirtualFreeEx(hProcess, rawBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return IntPtr.Zero;
            }

            // 写入 DLL 字节
            if (!NativeMethods.WriteProcessMemory(hProcess, rawBuf, raw, (UIntPtr)raw.Length, out _))
            { log("错误: 写入 DLL 字节失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }

            // 写入 MmArgs + 结果区（结果区清零，shellcode 完成后回写完整基址）
            byte[] args = new byte[argsSize];
            if (ptrSize == 8)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(rawBuf.ToInt64()), 0, args, 0, 8);
                Buffer.BlockCopy(BitConverter.GetBytes(argsBuf.ToInt64() + 16), 0, args, 8, 8);
            }
            else
            {
                Buffer.BlockCopy(BitConverter.GetBytes(rawBuf.ToInt32()), 0, args, 0, 4);
                Buffer.BlockCopy(BitConverter.GetBytes(argsBuf.ToInt32() + 8), 0, args, 4, 4);
            }
            if (!NativeMethods.WriteProcessMemory(hProcess, argsBuf, args, (UIntPtr)args.Length, out _))
            { log("错误: 写入参数内存失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }

            // 写入 shellcode
            if (!NativeMethods.WriteProcessMemory(hProcess, scBuf, sc, (UIntPtr)sc.Length, out _))
            { log("错误: 写入 shellcode 失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }

            // 写完了，把页封成 RX：此后这块内存只能读和执行，不能再被写。
            SealShellcodePage(hProcess, scBuf, sc.Length, log);

            log($"已写入手动映射 shellcode（{sc.Length} 字节）与 DLL 原始字节（{raw.Length} 字节）到目标进程，创建远程线程执行映射...");

            // 4. 启动远程线程执行 shellcode（参数 = argsBuf）
            hRemoteThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, scBuf, argsBuf, 0, out _);
            if (hRemoteThread == IntPtr.Zero)
            { log("错误: 创建手动映射远程线程失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }

            uint wait = NativeMethods.WaitForSingleObject(hRemoteThread, 15000);
            if (wait == NativeMethods.WAIT_TIMEOUT) { log("警告: 手动映射超时（15 秒），shellcode 可能在映射过程中阻塞。"); goto failCleanup; }
            if (wait == NativeMethods.WAIT_FAILED) { log("错误: WaitForSingleObject 失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }
            if (!NativeMethods.GetExitCodeThread(hRemoteThread, out uint code))
            { log("错误: GetExitCodeThread 失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }
            if (code == 0)
            {
                log("警告: 手动映射 shellcode 返回 0，映射失败（检查 DLL 是否为有效 PE / 位数是否匹配 / 依赖 DLL 是否可用）。");
                goto failCleanup;
            }

            // 5. 从结果区读回完整模块基址（64 位下线程退出码会截断，基址经结果区完整回传）
            long fullBase = 0;
            byte[] rb = new byte[ptrSize];
            IntPtr resultAddr = new IntPtr(argsBuf.ToInt64() + ptrSize * 2);
            if (!NativeMethods.ReadProcessMemory(hProcess, resultAddr, rb, (UIntPtr)ptrSize, out _))
            { log("错误: 读取手动映射结果区失败 - " + NativeMethods.LastErrorText()); goto failCleanup; }
            fullBase = ptrSize == 8 ? BitConverter.ToInt64(rb, 0) : BitConverter.ToInt32(rb, 0);
            if (fullBase == 0) { log("错误: 手动映射结果区为空，映射失败。"); goto failCleanup; }

            log($"手动映射成功！DLL 已由 shellcode 在目标进程内完成 PE 映射并执行 DllMain（模块基址 0x{fullBase:X}）。");

            // 6. 映射已完成，临时内存（DLL 字节 / 参数 / shellcode）不再需要，全部释放
            NativeMethods.VirtualFreeEx(hProcess, rawBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            NativeMethods.VirtualFreeEx(hProcess, scBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            return new IntPtr(fullBase);

        failCleanup:
            if (hRemoteThread != IntPtr.Zero) { NativeMethods.CloseHandle(hRemoteThread); hRemoteThread = IntPtr.Zero; }
            NativeMethods.VirtualFreeEx(hProcess, rawBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            NativeMethods.VirtualFreeEx(hProcess, scBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            return IntPtr.Zero;
        }
        /// <summary>卸载手动映射注入的 DLL：目标进程内执行卸载 shellcode，
        /// 调用 DllMain(DLL_PROCESS_DETACH) 后释放映射镜像内存（VirtualFree）。</summary>
        private static bool UnmapManualMapIntoProcess(IntPtr hProcess, long baseAddr, Action<string> log)
        {
            byte[] sc = IntPtr.Size == 8 ? UnmapDllX64 : UnmapDllX86;
            int ptrSize = IntPtr.Size;

            // 参数区：MmUnmapArgs { moduleBase }
            int argsSize = ptrSize;
            IntPtr argsBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)argsSize,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (argsBuf == IntPtr.Zero)
            { log("错误: 在目标进程分配卸载参数内存失败 - " + NativeMethods.LastErrorText()); return false; }
            byte[] args = new byte[argsSize];
            if (ptrSize == 8)
                Buffer.BlockCopy(BitConverter.GetBytes(baseAddr), 0, args, 0, 8);
            else
                Buffer.BlockCopy(BitConverter.GetBytes((int)baseAddr), 0, args, 0, 4);
            if (!NativeMethods.WriteProcessMemory(hProcess, argsBuf, args, (UIntPtr)args.Length, out _))
            {
                log("错误: 写入卸载参数失败 - " + NativeMethods.LastErrorText());
                NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return false;
            }

            // 同样先 RW 再封 RX：这块页只放一段短 shellcode，没有任何需要写回的理由。
            IntPtr scBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)sc.Length,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (scBuf == IntPtr.Zero)
            {
                log("错误: 在目标进程分配卸载 shellcode 内存失败 - " + NativeMethods.LastErrorText());
                NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return false;
            }
            if (!NativeMethods.WriteProcessMemory(hProcess, scBuf, sc, (UIntPtr)sc.Length, out _))
            {
                log("错误: 写入卸载 shellcode 失败 - " + NativeMethods.LastErrorText());
                NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                NativeMethods.VirtualFreeEx(hProcess, scBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return false;
            }
            SealShellcodePage(hProcess, scBuf, sc.Length, log);

            log($"已写入手动映射卸载 shellcode（{sc.Length} 字节）到目标进程，创建远程线程执行卸载...");
            IntPtr hThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, scBuf, argsBuf, 0, out _);
            if (hThread == IntPtr.Zero)
            {
                log("错误: 创建手动映射卸载远程线程失败 - " + NativeMethods.LastErrorText());
                NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                NativeMethods.VirtualFreeEx(hProcess, scBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return false;
            }

            uint wait = NativeMethods.WaitForSingleObject(hThread, 15000);
            bool ok;
            if (wait == NativeMethods.WAIT_TIMEOUT)
            { log("警告: 手动映射卸载超时（15 秒），DllMain(DLL_PROCESS_DETACH) 可能阻塞。"); ok = false; }
            else if (wait == NativeMethods.WAIT_FAILED)
            { log("错误: WaitForSingleObject 失败 - " + NativeMethods.LastErrorText()); ok = false; }
            else if (NativeMethods.GetExitCodeThread(hThread, out uint code) && code == 1)
            { log("手动映射卸载成功（DllMain 已收到 DLL_PROCESS_DETACH，镜像内存已释放）。"); ok = true; }
            else if (NativeMethods.GetExitCodeThread(hThread, out uint code2) && code2 != 0)
            { log($"警告: 卸载 shellcode 返回异常码 0x{code2:X}（非 1），卸载可能未完成（如 DllMain(DETACH) 或 VirtualFree 异常）。"); ok = false; }
            else
            { log("警告: 卸载 shellcode 返回 0，可能失败（模块基址无效或 VirtualFree 被拒）。"); ok = false; }

            NativeMethods.CloseHandle(hThread);
            NativeMethods.VirtualFreeEx(hProcess, argsBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            NativeMethods.VirtualFreeEx(hProcess, scBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            return ok;
        }


        /// <summary>反射式注入（Reflective DLL Injection）：把 DLL 的原始文件字节直接搬运进目标进程内存，
        /// 创建远程线程调用 DLL 自带的 ReflectiveLoader 导出函数，由 DLL 自身在目标进程内完成 PE 映射、
        /// 重定位、导入表填充与 DllMain 调用。注入器只负责"搬运内存 + 启动 Loader"，不在目标进程执行任何注入器代码。
        /// <returns>ReflectiveLoader 返回的映射模块句柄；0 表示失败。注：64 位下该句柄经线程退出码返回会被截断为低 32 位，
        /// 仅用于成功判断（非 0 即映射成功），完整基址由反射 DLL 自行管理。</returns></summary>
        private static IntPtr ReflectiveInjectIntoProcess(IntPtr hProcess, string dllPath, Action<string> log,
            out IntPtr remoteBuf, out IntPtr hRemoteThread)
        {
            remoteBuf = IntPtr.Zero;
            hRemoteThread = IntPtr.Zero;

            // 1. 读取 DLL 文件字节
            byte[] raw;
            try { raw = File.ReadAllBytes(dllPath); }
            catch (Exception ex) { log("错误: 读取反射 DLL 文件失败 - " + ex.Message); return IntPtr.Zero; }
            if (raw.Length < 0x40 || BitConverter.ToUInt16(raw, 0) != 0x5A4D)
            { log("错误: 文件不是有效的 PE 文件（缺少 MZ 头）。"); return IntPtr.Zero; }

            // 2. 解析 PE 头，取得镜像尺寸/映像基址/节表，用于"内存布局展开"
            int peOff = BitConverter.ToInt32(raw, 0x3C);
            if (peOff + 0x40 > raw.Length || BitConverter.ToUInt32(raw, peOff) != 0x4550)
            { log("错误: PE 头无效。"); return IntPtr.Zero; }
            ushort magic = BitConverter.ToUInt16(raw, peOff + 0x18);
            int fileHeader = peOff + 4;
            ushort numSections = BitConverter.ToUInt16(raw, fileHeader + 2);
            ushort optSize = BitConverter.ToUInt16(raw, fileHeader + 16);
            int opt = fileHeader + 20;
            long imageBase;
            if (magic == 0x20B) imageBase = BitConverter.ToInt64(raw, opt + 0x18);      // PE32+
            else if (magic == 0x10B) imageBase = BitConverter.ToUInt32(raw, opt + 0x1C); // PE32
            else { log("错误: 不支持的 PE 格式。"); return IntPtr.Zero; }
            uint sizeOfImage = BitConverter.ToUInt32(raw, opt + 0x38);
            uint sizeOfHeaders = BitConverter.ToUInt32(raw, opt + 0x3C);
            int sectionStart = opt + optSize;
            if (sizeOfImage == 0 || sectionStart + numSections * 40 > raw.Length)
            { log("错误: PE 节表无效。"); return IntPtr.Zero; }
            bool is32 = (magic == 0x10B);

            // 3. 定位 ReflectiveLoader 导出 RVA（必须在 DLL 自带该导出，普通 DLL 无法反射注入）
            long loaderRva = PeHelper.GetExportRva(dllPath, "ReflectiveLoader");
            if (loaderRva < 0)
            {
                log("错误: 反射式注入要求 DLL 自带 ReflectiveLoader 导出函数，但 " + Path.GetFileName(dllPath) + " 中未找到（普通 LoadLibrary 型 DLL 请改用 CRT/NTC/APC 方式）。");
                return IntPtr.Zero;
            }

            // 4. 分配"内存布局"镜像（SizeOfImage）。x86 反射 DLL 对全局量/常量采用绝对寻址，必须落在映像基址；
            //    x64 走 RIP 相对寻址，映像基址分配失败时可回退任意地址。
            //    先按 RW 分配只是为了写得进去：远程线程的入口就是这块缓冲里的 ReflectiveLoader
            //    （baseAddr + loaderRva），所以写完各节后必须立刻补上执行权限，否则线程一取指就是
            //    STATUS_ACCESS_VIOLATION(0xC0000005)，目标进程当场被打死。
            //    这里给 RWX 而不是 RX：ReflectiveLoader 自己的全局变量（已解析的 CreateFileA 等）
            //    就落在这块缓冲的 .data 里，loader 运行期间需要可写。跑完之后再收成 RX。
            IntPtr baseAddr = NativeMethods.VirtualAllocEx(hProcess, new IntPtr(imageBase), (UIntPtr)sizeOfImage,
                NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            if (baseAddr == IntPtr.Zero && !is32)
            {
                log($"提示: 映像基址 0x{imageBase:X} 分配失败，回退任意地址（x64 反射允许任意基址）。");
                baseAddr = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)sizeOfImage,
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
            }
            if (baseAddr == IntPtr.Zero)
            {
                if (is32)
                    log($"错误: 32 位反射要求映像基址 0x{imageBase:X} 在目标进程空闲可分配（x86 反射 DLL 用绝对寻址），但分配失败 - " + NativeMethods.LastErrorText());
                else
                    log("错误: 在目标进程分配反射 DLL 镜像内存失败 - " + NativeMethods.LastErrorText());
                return IntPtr.Zero;
            }

            // 5. 写入内存布局：头部 + 各节复制到各自的 VirtualAddress（而非文件偏移）
            if (!NativeMethods.WriteProcessMemory(hProcess, baseAddr, raw, (UIntPtr)sizeOfHeaders, out _))
            { log("错误: 写入镜像头失败 - " + NativeMethods.LastErrorText()); return IntPtr.Zero; }
            for (int i = 0; i < numSections; i++)
            {
                int s = sectionStart + i * 40;
                uint vaddr = BitConverter.ToUInt32(raw, s + 12);
                uint rsize = BitConverter.ToUInt32(raw, s + 16);
                uint roff = BitConverter.ToUInt32(raw, s + 20);
                if (rsize > 0 && roff + rsize <= raw.Length)
                {
                    byte[] sec = new byte[rsize];
                    Array.Copy(raw, (long)roff, sec, 0, (long)rsize);
                    if (!NativeMethods.WriteProcessMemory(hProcess, new IntPtr(baseAddr.ToInt64() + vaddr), sec, (UIntPtr)rsize, out _))
                    { log($"错误: 写入节 [{i}] (RVA 0x{vaddr:X}) 失败 - " + NativeMethods.LastErrorText()); return IntPtr.Zero; }
                }
            }
            remoteBuf = baseAddr;
            log($"已按内存布局展开反射 DLL（{numSections} 节，镜像 {sizeOfImage} 字节）到目标进程基址 0x{baseAddr.ToInt64():X}（映像基址 0x{imageBase:X}）。");

            // 5.5 把镜像页从 RW 提成 RWX —— 必须在创建远程线程之前。
            //     漏了这一步的表现极具误导性：注入器照样打印「反射加载成功」，
            //     因为线程退出码是 0xC0000005（非 0，被当成成功），而目标进程已经死了。
            if (!NativeMethods.VirtualProtectEx(hProcess, baseAddr, (UIntPtr)sizeOfImage,
                    NativeMethods.PAGE_EXECUTE_READWRITE, out uint oldProtect))
            {
                log("错误: 反射镜像页无法设为可执行（ReflectiveLoader 就在这块内存里，必须有执行权限）- " + NativeMethods.LastErrorText());
                return IntPtr.Zero;
            }

            // 6. 计算 ReflectiveLoader 在目标进程中的地址（base + RVA）并创建远程线程（参数 NULL，Loader 通过返回地址自行定位基址）
            IntPtr loaderAddr = new IntPtr(baseAddr.ToInt64() + loaderRva);
            log($"ReflectiveLoader RVA 0x{loaderRva:X} -> 目标地址 0x{loaderAddr.ToInt64():X}，创建远程线程...");

            hRemoteThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero, loaderAddr, IntPtr.Zero, 0, out _);
            if (hRemoteThread == IntPtr.Zero)
            {
                log("错误: 创建反射注入远程线程失败 - " + NativeMethods.LastErrorText());
                return IntPtr.Zero;
            }

            uint wait = NativeMethods.WaitForSingleObject(hRemoteThread, 15000);
            if (wait == NativeMethods.WAIT_TIMEOUT) { log("警告: 反射加载超时（15 秒），DLL 可能在映射过程中阻塞。"); return IntPtr.Zero; }
            if (wait == NativeMethods.WAIT_FAILED) { log("错误: WaitForSingleObject 失败 - " + NativeMethods.LastErrorText()); return IntPtr.Zero; }
            if (!NativeMethods.GetExitCodeThread(hRemoteThread, out uint code))
            {
                log("错误: GetExitCodeThread 失败 - " + NativeMethods.LastErrorText());
                return IntPtr.Zero;
            }
            if (code == 0)
            {
                log("警告: ReflectiveLoader 返回 0，反射映射失败（检查 DLL 的 ReflectiveLoader 实现是否完整）。");
                return IntPtr.Zero;
            }
            // 只判「非 0」是不够的：远程线程的退出码是一个 DWORD，loader 在映射过程中崩掉时
            // 拿到的是 NTSTATUS（0xC0000005 访问违例、0xC00000FD 栈溢出等），这些值一样非 0。
            // 曾经因此长期「假成功」——注入器打印成功，目标进程其实当场被打死了。
            // NTSTATUS 错误码都在 0xC0000000..0xC0000FFF，而真实映射基址不可能落在这里
            // （x64 用户态基址远高于该区间，x86 用户态上限 0x7FFFFFFF），所以按这个区间排除。
            if ((code & 0xFFFFF000u) == 0xC0000000u)
            {
                log($"警告: ReflectiveLoader 以 NTSTATUS 0x{code:X8} 结束，说明它在映射途中崩溃了"
                    + "（目标进程可能已经退出）。请确认 DLL 的 ReflectiveLoader 不依赖尚未填充的 IAT。");
                return IntPtr.Zero;
            }
            log($"反射加载成功！DLL 已由 ReflectiveLoader 自行映射执行（模块句柄 0x{code:X}）。");

            // 7. 加载器已退出，把这块「搬运源」缓冲从 RW 封成 RX：
            //    ReflectiveLoader 运行期间必须可写（它自己的全局变量就落在这块镜像里），
            //    但跑完之后没有任何理由再让它可写。保留执行权限是为了兼容少数会在加载后回调自身代码的 loader。
            SealShellcodePage(hProcess, baseAddr, (int)sizeOfImage, log);
            return new IntPtr(code);
        }

        /// <summary>
        /// 静默查询目标进程模块列表里这个 DLL 的基址（不打日志），未加载返回 <see cref="IntPtr.Zero"/>。
        /// 单独抽出来是为了让 APC 等待能安静地轮询——那里每 100ms 打一条日志只会刷屏。
        /// 返回基址而不是 bool：核验那边要把基址写进日志，拿 bool 就得再枚举一遍。
        /// </summary>
        private static IntPtr FindModuleBaseByName(int pid, string dllPath)
        {
            string name = Path.GetFileName(dllPath);
            try
            {
                using var proc = System.Diagnostics.Process.GetProcessById(pid);
                foreach (System.Diagnostics.ProcessModule m in proc.Modules)
                {
                    try
                    {
                        if (string.Equals(Path.GetFileName(m.FileName), name, StringComparison.OrdinalIgnoreCase))
                            return m.BaseAddress;
                    }
                    catch { }
                }
            }
            catch { }
            return IntPtr.Zero;
        }

        /// <summary>
        /// 等待 APC 队列里的 LoadLibraryW 真正执行完。
        ///
        /// QueueUserAPC 是异步的：恢复主线程只是让 APC “可以”执行，真正跑起来要等目标主线程
        /// 进入可告警等待（SleepEx / WaitForSingleObjectEx / GetMessage 消息循环）。
        /// 不等就直接调导出函数，会撞上“模块还没加载”：注入器先打一行
        /// “未找到已加载的模块”的错误，紧接着核验又报“核验通过”——两条互相矛盾的输出。
        /// 这不是测试间歇性问题，而是产品对异步路径的常识性忽视。
        /// </summary>
        private static bool WaitApcloaded(int pid, string[] dlls, Action<string> log, int timeoutMs = 3000)
        {
            bool allSeen = true;
            foreach (var dll in dlls)
            {
                string name = Path.GetFileName(dll);
                bool seen = false;
                int waited = 0;
                for (; waited < timeoutMs && !seen; waited += 100)
                {
                    if (FindModuleBaseByName(pid, dll) != IntPtr.Zero) { seen = true; break; }
                    System.Threading.Thread.Sleep(100);
                }
                if (seen)
                    log($"APC 已执行：{name} 已加载（等了约 {waited}ms），可以调导出函数。");
                else
                {
                    log($"警告: 等待 {timeoutMs}ms 后 {name} 仍未加载（目标主线程可能不在可告警等待）。");
                    allSeen = false;
                }
            }
            return allSeen;
        }

        /// <summary>注入结果核验：按文件名在目标进程模块列表中查找（带重试容忍枚举时序延迟）</summary>
        public static bool VerifyModuleLoaded(int pid, string dllPath, Action<string> log)
        {
            string name = Path.GetFileName(dllPath);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                IntPtr baseAddr = FindModuleBaseByName(pid, dllPath);
                if (baseAddr != IntPtr.Zero)
                {
                    log($"核验通过：{name} 已在目标进程模块列表（基址 0x{baseAddr.ToInt64():X}）。");
                    return true;
                }
                System.Threading.Thread.Sleep(300);
            }
            log($"警告: 核验未通过——未在目标进程模块列表中找到 {name}（可能已卸载或枚举延迟）。");
            return false;
        }

        /// <summary>注入后远程调用 DLL 的导出函数（模块基址 + RVA 计算地址，规避 64 位句柄/地址截断）。</summary>
        /// <param name="callArg">可选参数：以 UTF-16 字符串写入目标进程内存，作为导出函数唯一指针参数；为空则传 NULL。</param>
        /// <param name="knownBase">已知模块基址（手动映射注入的模块不在进程模块列表，由 shellcode 返回完整基址）；0 时自动枚举模块列表。</param>
        private static bool CallExport(IntPtr hProcess, int pid, string dllPath, string funcName, string callArg, Action<string> log, long knownBase = 0)
        {
            log("----- 调用导出函数: " + funcName + " -----");
            long rva = PeHelper.GetExportRva(dllPath, funcName);
            if (rva < 0)
            {
                log("错误: 未在 " + Path.GetFileName(dllPath) + " 中找到导出函数 " + funcName);
                return false;
            }

            // 枚举目标进程模块，取得完整（64 位）模块基址（LoadLibrary 返回句柄会被截断）
            string moduleName = Path.GetFileName(dllPath);
            IntPtr moduleBase = IntPtr.Zero;
            if (knownBase != 0)
            {
                moduleBase = new IntPtr(knownBase);   // 手动映射注入：shellcode 返回的完整基址（模块不进列表）
                log($"使用手动映射返回的模块基址 0x{moduleBase.ToInt64():X}（该模块不在进程模块列表，属正常）。");
            }
            else
            {
                for (int attempt = 0; attempt < 3 && moduleBase == IntPtr.Zero; attempt++)
                {
                    try
                    {
                        using var proc = System.Diagnostics.Process.GetProcessById(pid);
                        foreach (System.Diagnostics.ProcessModule m in proc.Modules)
                        {
                            try
                            {
                                if (string.Equals(Path.GetFileName(m.FileName), moduleName, StringComparison.OrdinalIgnoreCase))
                                { moduleBase = m.BaseAddress; break; }
                            }
                            catch { }
                        }
                    }
                    catch (Exception ex) { log("错误: 枚举目标进程模块失败 - " + ex.Message); return false; }
                    if (moduleBase == IntPtr.Zero) System.Threading.Thread.Sleep(200);
                }
            }
            if (moduleBase == IntPtr.Zero)
            {
                log("错误: 未在目标进程（PID=" + pid + "）中找到已加载的模块 " + moduleName);
                return false;
            }
            long targetAddr = moduleBase.ToInt64() + rva;
            log($"模块基址 0x{moduleBase.ToInt64():X} + 导出 RVA 0x{rva:X} = 0x{targetAddr:X}");

            // 可选参数内存（UTF-16）
            // 约定：调用参数内用 "||" 分隔多个参数；>1 个时在目标进程构造
            //   NULL 结尾的字符串指针数组（LPVOID* args），导出函数用 args[i] 访问；
            //   单参数（无 ||）时保持原行为（直接传字符串指针，兼容 InstallHook 等）。
            IntPtr argBuf = IntPtr.Zero;
            string[] multiParts = null;
            if (!string.IsNullOrEmpty(callArg))
            {
                var parts = callArg.Split(new[] { "||" }, StringSplitOptions.None);
                if (parts.Length > 1) multiParts = parts;
            }

            if (multiParts != null)
            {
                int ptrSize = IntPtr.Size;
                int arrSize = (multiParts.Length + 1) * ptrSize;   // 含结尾 NULL
                var enc = Encoding.Unicode;
                var strBytes = new System.Collections.Generic.List<byte[]>(multiParts.Length);
                int strTotal = 0;
                foreach (var p in multiParts)
                {
                    var b = enc.GetBytes(p);
                    strBytes.Add(b);
                    strTotal += b.Length + 2;
                }
                long total = (long)arrSize + strTotal;
                IntPtr buf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)total,
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
                if (buf == IntPtr.Zero)
                {
                    log("错误: 在目标进程分配多参数内存失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                long strBase = buf.ToInt64() + arrSize;
                byte[] arr = new byte[arrSize];   // 零初始化（含结尾 NULL）
                long off = 0;
                bool writeOk = true;
                for (int i = 0; i < multiParts.Length; i++)
                {
                    var b = strBytes[i];
                    if (!NativeMethods.WriteProcessMemory(hProcess, new IntPtr(strBase + off), b, (UIntPtr)b.Length, out _)
                        || !NativeMethods.WriteProcessMemory(hProcess, new IntPtr(strBase + off + b.Length), new byte[2], (UIntPtr)2, out _))
                    { writeOk = false; break; }
                    long pv = strBase + off;
                    byte[] pb = ptrSize == 8 ? BitConverter.GetBytes(pv) : BitConverter.GetBytes((int)pv);
                    Buffer.BlockCopy(pb, 0, arr, i * ptrSize, ptrSize);
                    off += b.Length + 2;
                }
                if (!writeOk || !NativeMethods.WriteProcessMemory(hProcess, buf, arr, (UIntPtr)arrSize, out _))
                {
                    log("错误: 写入多参数失败 - " + NativeMethods.LastErrorText());
                    NativeMethods.VirtualFreeEx(hProcess, buf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                    return false;
                }
                argBuf = buf;
                log("参数已写入目标进程（UTF-16 参数数组，共 " + multiParts.Length + " 个）：" + string.Join(" | ", multiParts));
            }
            else if (!string.IsNullOrEmpty(callArg))
            {
                byte[] bytes = Encoding.Unicode.GetBytes(callArg);
                argBuf = NativeMethods.VirtualAllocEx(hProcess, IntPtr.Zero, (UIntPtr)(bytes.Length + 2),
                    NativeMethods.MEM_COMMIT | NativeMethods.MEM_RESERVE, NativeMethods.PAGE_READWRITE);
                if (argBuf == IntPtr.Zero)
                {
                    log("错误: 在目标进程分配参数内存失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                if (!NativeMethods.WriteProcessMemory(hProcess, argBuf, bytes, (UIntPtr)bytes.Length, out _))
                {
                    log("错误: 写入参数失败 - " + NativeMethods.LastErrorText());
                    NativeMethods.VirtualFreeEx(hProcess, argBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                    return false;
                }
                log("参数已写入目标进程（UTF-16）：" + callArg);
            }

            IntPtr hThread = NativeMethods.CreateRemoteThread(hProcess, IntPtr.Zero, UIntPtr.Zero,
                new IntPtr(targetAddr), argBuf, 0, out _);
            if (hThread == IntPtr.Zero)
            {
                log("错误: 创建调用线程失败 - " + NativeMethods.LastErrorText());
                if (argBuf != IntPtr.Zero) NativeMethods.VirtualFreeEx(hProcess, argBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                return false;
            }
            // argBufBusy：远程线程可能还在读 argBuf，此时**不能**释放它。
            // 释放后目标进程的导出函数会读到已解映射的内存（use-after-free），
            // 轻则参数变成垃圾、重则整个进程被访问违例打死——而这发生在别人的游戏里。
            bool argBufBusy = false;
            try
            {
                uint wait = NativeMethods.WaitForSingleObject(hThread, 15000);
                if (wait == NativeMethods.WAIT_TIMEOUT)
                {
                    argBufBusy = true;
                    log("警告: 等待导出函数执行超时（15 秒），函数可能阻塞；参数缓冲区保留在目标进程内（远程线程仍可能在使用它），不再释放。");
                    return false;
                }
                if (wait == NativeMethods.WAIT_FAILED)
                {
                    argBufBusy = true;
                    log("警告: WaitForSingleObject 失败 - " + NativeMethods.LastErrorText() + "；线程状态未知，参数缓冲区不再释放。");
                    return false;
                }
                if (!NativeMethods.GetExitCodeThread(hThread, out uint ret))
                {
                    log("警告: 读取导出函数返回码失败 - " + NativeMethods.LastErrorText());
                    return false;
                }
                log($"导出函数 {funcName} 调用完成（返回 {ret}，0 通常表示失败或无返回值）。");
            }
            finally
            {
                NativeMethods.CloseHandle(hThread);
                if (argBuf != IntPtr.Zero && !argBufBusy) NativeMethods.VirtualFreeEx(hProcess, argBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
            }
            return true;
        }

        /// <summary>解析 DLL 输入内容为路径列表（支持 ; | 换行 分隔，自动去引号去空白）</summary>
        public static string[] SplitDlls(string text)
        {
            if (string.IsNullOrWhiteSpace(text)) return Array.Empty<string>();
            var list = new System.Collections.Generic.List<string>();
            foreach (var part in text.Split(new[] { ';', '|', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string p = part.Trim().Trim('"');
                if (p.Length > 0) list.Add(p);
            }
            return list.ToArray();
        }
    }

    /// <summary>配置存储：键值对格式（兼容旧的两行 exe/dll 格式），配置文件优先放注入器同目录，目录不可写时回退到 %AppData%</summary>
    internal static class ConfigStore
    {
        private static string _path;
        private static readonly Dictionary<string, string> _data = new();
        private static bool _loaded;              // 缓存是否已从磁盘填充过
        private static DateTime _stamp;           // 上次读取时的文件时间戳（UTC）
        private static long _stampLen = -1;       // 上次读取时的文件长度

        static ConfigStore()
        {
            // 优先使用注入器所在目录（与用户把目标文件放同目录的使用习惯一致）
            string exeDir = AppContext.BaseDirectory;
            try
            {
                if (Directory.Exists(exeDir))
                {
                    string probe = Path.Combine(exeDir, ".dllinjector_wtest");
                    File.WriteAllText(probe, "t");
                    File.Delete(probe);
                    _path = Path.Combine(exeDir, "DllInjector.config");
                    return;
                }
            }
            catch { }

            // 回退：%AppData%\DllInjector\config.txt
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string dir = Path.Combine(appData, "DllInjector");
            try { Directory.CreateDirectory(dir); } catch { }
            _path = Path.Combine(dir, "config.txt");
        }

        /// <summary>配置文件路径（用于日志展示）</summary>
        public static string ConfigPath => _path ?? "";

        /// <summary>重新从磁盘读取全部配置</summary>
        /// <remarks>
        /// 只在文件真的变了（时间戳或长度不同）时才重新解析。
        /// 为什么需要这层缓存：<see cref="Get"/> 会被 <see cref="Method"/>、
        /// <see cref="WindowPos"/> 的 getter 各自调用，而这些 getter 都跑在 UI 线程上；
        /// 每次都 ReadAllLines + Split 一遍，等于每读一个属性就做一次完整文件 IO。
        /// 但它**不能**退化成「只读一次」：用户会手工编辑 DllInjector.config 再切回窗口，
        /// 那时必须看到新值，否则就像配置没生效一样。
        /// </remarks>
        private static void ReloadIfNeeded()
        {
            if (_path == null) return;

            DateTime mtime;
            long length;
            try
            {
                var fi = new FileInfo(_path);
                if (!fi.Exists)
                {
                    // 文件被删了：清掉缓存，下次 Get 返回默认值
                    if (_loaded) { _data.Clear(); _loaded = false; _stamp = default; _stampLen = -1; }
                    return;
                }
                mtime  = fi.LastWriteTimeUtc;
                length = fi.Length;
            }
            catch { return; }   // 权限/占用问题：沿用现有缓存，不让读配置变成异常源

            if (_loaded && mtime == _stamp && length == _stampLen) return;

            _data.Clear();
            try
            {
                var lines = File.ReadAllLines(_path);
                if (lines.Length > 0)
                {
                    // 兼容旧格式：第一行不含 '=' 时视为纯 exe/dll 两行
                    if (!lines[0].Contains('='))
                    {
                        _data["exe"] = lines[0].Trim();
                        if (lines.Length > 1) _data["dll"] = lines[1].Trim();
                    }
                    else
                    {
                        foreach (var line in lines)
                        {
                            int i = line.IndexOf('=');
                            if (i > 0) _data[line.Substring(0, i).Trim()] = line.Substring(i + 1).Trim();
                        }
                    }
                }
                _stamp = mtime;
                _stampLen = length;
                _loaded = true;
            }
            catch { /* 读失败：保持空表，按默认值走 */ }
        }

        /// <summary>把内存里的键值写回磁盘（原子替换）</summary>
        /// <remarks>
        /// 为什么不用 File.WriteAllLines 直接覆盖：写到一半进程被杀（用户在注入
        /// 过程中关窗口、或者机器断电），配置文件就变成半截甚至空文件——下次启动
        /// 所有记忆全丢，而且用户完全不知道发生了什么。
        /// 改为「写临时文件 → File.Replace 原子替换」：任何时刻磁盘上都存在一个
        /// 完整的旧版本或新版本，不存在中间态。
        /// </remarks>
        private static void Flush()
        {
            if (_path == null) return;
            var lines = new System.Collections.Generic.List<string>();
            foreach (var kv in _data)
                lines.Add(kv.Key + "=" + kv.Value);

            string tmp = _path + ".tmp";
            try
            {
                File.WriteAllLines(tmp, lines, new UTF8Encoding(false));
                if (File.Exists(_path))
                {
                    // File.Replace 需要备份文件名参数；传 null 表示不留备份
                    File.Replace(tmp, _path, null);
                }
                else
                {
                    File.Move(tmp, _path);
                }
            }
            catch
            {
                // 原子替换失败（目录只读、被杀软占用等）时退回直接覆盖，
                // 至少保住「这次能存上」，而不是让用户的选择无声消失。
                try { File.WriteAllLines(_path, lines, new UTF8Encoding(false)); } catch { }
            }
            finally
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
            }

            // 刚写的内容就是缓存内容，刷新一下戳记，避免下次 Get 又白读一遍
            try
            {
                var fi = new FileInfo(_path);
                if (fi.Exists) { _stamp = fi.LastWriteTimeUtc; _stampLen = fi.Length; _loaded = true; }
            }
            catch { }
        }

        private static string Get(string key, string def = "")
        {
            ReloadIfNeeded();
            return _data.TryGetValue(key, out var v) ? v : def;
        }

        /// <summary>读取上次记忆的 exe / dll 路径；不存在则返回 null。</summary>
        public static void Load(out string exe, out string dll)
        {
            exe = Get("exe"); if (string.IsNullOrEmpty(exe)) exe = null;
            dll = Get("dll"); if (string.IsNullOrEmpty(dll)) dll = null;
        }

        /// <summary>保存本次选择的 exe / dll 路径（保留其它配置项）</summary>
        public static void Save(string exe, string dll)
        {
            if (_path == null) return;
            ReloadIfNeeded();
            _data["exe"] = exe ?? "";
            _data["dll"] = dll ?? "";
            Flush();
        }

        /// <summary>
        /// 上次使用的注入方式，默认 0（CreateRemoteThread）。
        /// 编号必须与 NativeMethods.INJECT_* 常量、GUI 下拉框顺序保持一致：
        /// 0=CRT 1=NTC 2=APC 3=RFI 4=MM。新增方式只能追加在末尾，
        /// 因为这里靠 m &lt;= 4 这个上限做校验。
        /// </summary>
        public static int Method
        {
            get { int m; return int.TryParse(Get("method", "0"), out m) && m >= NativeMethods.INJECT_CRT && m <= NativeMethods.INJECT_MM ? m : NativeMethods.INJECT_CRT; }
            set { if (_path == null) return; ReloadIfNeeded(); _data["method"] = value.ToString(); Flush(); }
        }

        /// <summary>窗口位置 "x,y,w,h"，空表示未记忆</summary>
        public static string WindowPos
        {
            get { return Get("winpos", ""); }
            set { if (_path == null) return; ReloadIfNeeded(); _data["winpos"] = value; Flush(); }
        }
    }

    /// <summary>主题色板（固定暗色）</summary>
    internal static class Theme
    {
        public static bool Dark = true;
        public static Color Back => Dark ? Color.FromArgb(32, 32, 36) : Color.White;
        public static Color Fore => Dark ? Color.FromArgb(232, 232, 232) : Color.FromArgb(20, 20, 20);
        public static Color BoxBack => Dark ? Color.FromArgb(45, 45, 48) : Color.White;
        public static Color BoxFore => Dark ? Color.FromArgb(240, 240, 240) : Color.Black;
        public static Color TipFore => Dark ? Color.FromArgb(160, 160, 160) : Color.Gray;
        public static Color ButtonBack => Dark ? Color.FromArgb(63, 63, 70) : Color.FromArgb(240, 240, 240);
        public static Color Accent => Color.FromArgb(22, 119, 255);
    }

    internal static class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            // 图形界面模式：非管理员时自动请求管理员权限（UAC）。
            // 用户取消则继续以普通权限运行（注入普通进程通常无需提权）。
            if (args.Length == 0 && !IsAdministrator())
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo
                    {
                        FileName = Environment.ProcessPath,
                        Arguments = "--elevated",
                        UseShellExecute = true,
                        Verb = "runas",
                        WorkingDirectory = AppContext.BaseDirectory
                    };
                    System.Diagnostics.Process.Start(psi);
                    return;   // 提权后的新实例将带 --elevated 参数重新进入本方法
                }
                catch (Win32Exception) { /* 用户取消 UAC，继续以普通权限运行 */ }
            }

            // -help / -version 是只读查询：不注入、不写 inject_log.txt，直接退出。
            // 放在这里而不是下面的分发分支里，是因为那里会先准备好日志文件并走
            // ok ? 0 : 1 的成败语义；帮助信息不该留下日志，也不该被当成失败。
            if (args.Length >= 1 && IsHelpArg(args[0]))
            {
                Console.WriteLine(BuildUsage());
                Environment.Exit(0);
            }
            if (args.Length >= 1 && IsVersionArg(args[0]))
            {
                Console.WriteLine(GetVersionText());
                Environment.Exit(0);
            }

            InjectorCore.LoadMmMap();

            // 无头命令行模式（用于自动化 / 测试）：
            //   -inject     <exe路径> <dll1> [dll2...] [-args <参数>] [-method crt|ntc|apc|rfi|mm] [-export <函数>] [-exportarg <参数>]
            //   -injectpid  <pid1[,pid2...]> <dll1> [dll2...] [-method crt|ntc|rfi|mm] [-export <函数>] [-exportarg <参数>]   （多 PID 用逗号分隔 = 批量）
            //   -injectname <进程名> <dll1> [dll2...] [-method crt|ntc|rfi|mm] [-export <函数>] [-exportarg <参数>]            （按进程名批量，支持 * ? 通配）
            //   -eject      <pid> <dll文件名>
            //   -checkdll   <dll1> [dll2...]   （注入前 PE 体检，不执行注入）
            //   -status     <pid> [dll...] [-pipe <名称>]   （只读状态查询）
            if (args.Length >= 1 &&
                (string.Equals(args[0], "-inject", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-injectpid", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-injectname", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-eject", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-status", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-checkdll", StringComparison.OrdinalIgnoreCase)))
            {
                int code = 1;
                try
                {
                    string logPath = Path.Combine(AppContext.BaseDirectory, "inject_log.txt");
                    var lines = new System.Collections.Generic.List<string>();
                    Action<string> log = s => { lines.Add(s); Console.WriteLine(s); };

                    bool ok = false;
                    if (string.Equals(args[0], "-inject", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
                    {
                        // -inject <exe> <dll...> [-args ...] [-method ...] [-export ...] [-exportarg ...]
                        string exe = args[1];
                        var dlls = new System.Collections.Generic.List<string>();
                        string cmdArgs = "", exportFunc = "", exportArg = "";
                        int method = NativeMethods.INJECT_CRT;
                        bool inArgs = false;
                        for (int i = 2; i < args.Length; i++)
                        {
                            if (string.Equals(args[i], "-args", StringComparison.OrdinalIgnoreCase)) { inArgs = true; continue; }
                            if (string.Equals(args[i], "-method", StringComparison.OrdinalIgnoreCase))
                            { inArgs = false; if (i + 1 < args.Length) method = ParseMethod(args[++i]); continue; }
                            if (string.Equals(args[i], "-export", StringComparison.OrdinalIgnoreCase))
                            { inArgs = false; if (i + 1 < args.Length) exportFunc = args[++i]; continue; }
                            if (string.Equals(args[i], "-exportarg", StringComparison.OrdinalIgnoreCase))
                            { inArgs = false; if (i + 1 < args.Length) exportArg = args[++i]; continue; }
                            if (inArgs) cmdArgs = (cmdArgs.Length > 0 ? cmdArgs + " " : "") + args[i];
                            else dlls.Add(args[i]);
                        }
                        ok = InjectorCore.Run(exe, dlls.ToArray(), cmdArgs, method, exportFunc, exportArg, log);
                    }
                    else if (string.Equals(args[0], "-injectpid", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
                    {
                        // -injectpid <pid1[,pid2...]> <dll...> [-method ...] [-export ...] [-exportarg ...]
                        var pidList = new System.Collections.Generic.List<int>();
                        foreach (var pp in args[1].Split(','))
                            if (int.TryParse(pp.Trim(), out int v) && v > 0) pidList.Add(v);
                        var dlls = new System.Collections.Generic.List<string>();
                        int method = NativeMethods.INJECT_CRT;
                        string exportFunc = "", exportArg = "";
                        for (int i = 2; i < args.Length; i++)
                        {
                            if (string.Equals(args[i], "-method", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) method = ParseMethod(args[++i]); continue; }
                            if (string.Equals(args[i], "-export", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) exportFunc = args[++i]; continue; }
                            if (string.Equals(args[i], "-exportarg", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) exportArg = args[++i]; continue; }
                            dlls.Add(args[i]);
                        }
                        if (pidList.Count == 0) { log("错误: 无效 PID: " + args[1]); }
                        else if (pidList.Count == 1)
                            ok = InjectorCore.InjectToProcess(pidList[0], dlls.ToArray(), method, exportFunc, exportArg, log);
                        else
                            ok = InjectorCore.BatchInjectProcesses(pidList.ToArray(), dlls.ToArray(), method, exportFunc, exportArg, log);
                    }
                    else if (string.Equals(args[0], "-injectname", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
                    {
                        // -injectname <进程名> <dll...>：枚举匹配进程名的进程批量注入（支持 * ? 通配，位数不符自动跳过）
                        string pattern = args[1].Trim();
                        var dlls = new System.Collections.Generic.List<string>();
                        int method = NativeMethods.INJECT_CRT;
                        string exportFunc = "", exportArg = "";
                        for (int i = 2; i < args.Length; i++)
                        {
                            if (string.Equals(args[i], "-method", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) method = ParseMethod(args[++i]); continue; }
                            if (string.Equals(args[i], "-export", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) exportFunc = args[++i]; continue; }
                            if (string.Equals(args[i], "-exportarg", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) exportArg = args[++i]; continue; }
                            dlls.Add(args[i]);
                        }
                        var pids = new System.Collections.Generic.List<int>();
                        foreach (var p in System.Diagnostics.Process.GetProcesses())
                        {
                            try
                            {
                                // 进程名可能带 .exe 后缀，两种都匹配
                                if (p.Id > 0 && !string.IsNullOrEmpty(p.ProcessName) &&
                                    (WildcardMatch(pattern, p.ProcessName) || WildcardMatch(pattern, p.ProcessName + ".exe")))
                                    pids.Add(p.Id);
                            }
                            catch { }
                        }
                        if (pids.Count == 0) { log("未找到匹配的进程（名称模式: " + pattern + "）。"); }
                        else
                        {
                            log($"按进程名匹配到 {pids.Count} 个进程: {string.Join(", ", pids)}");
                            ok = InjectorCore.BatchInjectProcesses(pids.ToArray(), dlls.ToArray(), method, exportFunc, exportArg, log);
                        }
                    }
                    else if (string.Equals(args[0], "-eject", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
                    {
                        if (int.TryParse(args[1], out int ejectPid) && ejectPid > 0)
                            ok = InjectorCore.EjectDll(ejectPid, args[2], log);
                        else
                            log("错误: 无效 PID: " + args[1]);
                    }
                    else if (string.Equals(args[0], "-status", StringComparison.OrdinalIgnoreCase) && args.Length >= 2)
                    {
                        // -status <pid> [dll...] [-pipe <名称>]
                        if (int.TryParse(args[1], out int stPid) && stPid > 0)
                        {
                            var stDlls = new System.Collections.Generic.List<string>();
                            string stPipe = "GalToolText";   // 与 TextHookDll 的默认值一致
                            for (int i = 2; i < args.Length; i++)
                            {
                                if (string.Equals(args[i], "-pipe", StringComparison.OrdinalIgnoreCase))
                                { if (i + 1 < args.Length) stPipe = args[++i]; continue; }
                                stDlls.Add(args[i]);
                            }
                            ok = InjectorCore.Status(stPid, stDlls.ToArray(), stPipe, log);
                        }
                        else
                            log("错误: 无效 PID: " + args[1]);
                    }
                    else if (string.Equals(args[0], "-checkdll", StringComparison.OrdinalIgnoreCase) && args.Length >= 2)
                    {
                        // -checkdll <dll...>：仅做注入前 PE 体检
                        bool allValid = true;
                        for (int i = 1; i < args.Length; i++)
                        {
                            string dll = args[i].Trim().Trim('"');
                            if (!File.Exists(dll)) { log("文件不存在: " + dll); allValid = false; continue; }
                            var insp = PeHelper.InspectDll(dll);
                            log($"体检: {Path.GetFileName(dll)} -> 有效PE={insp.IsValidPe}, 位数={insp.Bitness}, DLL标志={insp.IsDll}, 导出表={insp.HasExportTable}（{insp.ExportCount}）, 重定位段={insp.HasRelocSection}, 可执行段={insp.HasExecSection}, 大小={insp.FileSize} 字节 | {insp.Detail}");
                            if (!insp.IsValidPe || !insp.IsDll) allValid = false;
                        }
                        ok = allValid;
                    }
                    else
                        Console.WriteLine(BuildUsage());

                    File.WriteAllLines(logPath, lines);
                    code = ok ? 0 : 1;
                }
                catch (Exception ex)
                {
                    Console.WriteLine("异常: " + ex.Message);
                    code = 1;
                }
                Environment.Exit(code);
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
            Application.Run(new MainForm());
        }

        /// <summary>是否是帮助开关（-h / -help / --help / /?）</summary>
        private static bool IsHelpArg(string s)
        {
            return string.Equals(s, "-h", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "-help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "--help", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "/?", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>是否是版本查询开关（-v / -version / --version）</summary>
        private static bool IsVersionArg(string s)
        {
            return string.Equals(s, "-v", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "-version", StringComparison.OrdinalIgnoreCase)
                || string.Equals(s, "--version", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>版本号文本，取自 csproj 的 Version（不要在源码里再写死一份）</summary>
        private static string GetVersionText()
        {
            var asm = typeof(Program).Assembly;
            var info = asm.GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false);
            if (info.Length > 0 && info[0] is System.Reflection.AssemblyInformationalVersionAttribute iv
                && !string.IsNullOrEmpty(iv.InformationalVersion))
            {
                // 单文件发布时 InformationalVersion 会带上 "+<commit sha>" 后缀，去掉更好读
                string v = iv.InformationalVersion;
                int plus = v.IndexOf('+');
                if (plus > 0) v = v.Substring(0, plus);
                return "DllInjector " + v;
            }
            return "DllInjector " + asm.GetName().Version;
        }

        /// <summary>
        /// CLI 用法说明。-help 与「参数不认识」两条路径共用同一份文本，
        /// 避免两处措辞各自漂移。
        /// </summary>
        private static string BuildUsage()
        {
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("DLL 注入器 - 命令行用法");
            sb.AppendLine();
            sb.AppendLine("  DllInjector.exe                                    不带参数 = 启动图形界面");
            sb.AppendLine("  DllInjector.exe -inject    <exe> <dll...> [-args <参数>] [-method <方式>] [-export <函数>] [-exportarg <参数>]");
            sb.AppendLine("  DllInjector.exe -injectpid <pid1[,pid2...]> <dll...> [-method <方式>] [-export <函数>] [-exportarg <参数>]");
            sb.AppendLine("  DllInjector.exe -injectname <进程名> <dll...> [-method <方式>] [-export <函数>] [-exportarg <参数>]");
            sb.AppendLine("  DllInjector.exe -eject     <pid> <dll文件名>");
            sb.AppendLine("  DllInjector.exe -status    <pid> [dll...] [-pipe <管道名>]");
            sb.AppendLine("  DllInjector.exe -checkdll  <dll...>");
            sb.AppendLine("  DllInjector.exe -help | -version");
            sb.AppendLine();
            sb.AppendLine("  -method   crt（默认，CreateRemoteThread）| ntc（NtCreateThreadEx）");
            sb.AppendLine("            apc（QueueUserAPC，仅对启动中的进程有效）");
            sb.AppendLine("            rfi（反射式注入）| mm（手动映射注入）");
            sb.AppendLine("  -export   注入后调用的导出函数名，例如 InstallConfig");
            sb.AppendLine("  -exportarg 传给该导出函数的字符串参数");
            sb.AppendLine();
            sb.AppendLine("  多个 DLL 用空格分隔，也可用 ; 或 | 分隔（放在同一个参数里时需要加引号）。");
            sb.AppendLine("  -exportarg 内部的多个参数用 || 分隔，会被打包成 LPVOID 数组传给导出函数。");
            sb.AppendLine();
            sb.AppendLine("  -injectname 的进程名支持 * 和 ? 通配，位数不符的进程会自动跳过。");
            sb.AppendLine("  -status   只读查询：进程位数、模块是否已加载、手动映射基址、文本 Hook 管道是否在线。");
            sb.AppendLine("  退出码：0 = 成功，1 = 失败。");
            return sb.ToString();
        }

        /// <summary>解析 CLI 注入方式参数（crt / ntc / apc / rfi / mm，默认 crt）</summary>
        /// <remarks>internal 而非 private：test/DllInjectorTests 直接链接本文件做回归测试。</remarks>
        internal static int ParseMethod(string s)
        {
            if (string.Equals(s, "ntc", StringComparison.OrdinalIgnoreCase)) return NativeMethods.INJECT_NTC;
            if (string.Equals(s, "apc", StringComparison.OrdinalIgnoreCase)) return NativeMethods.INJECT_APC;
            if (string.Equals(s, "rfi", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "reflect", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "reflective", StringComparison.OrdinalIgnoreCase)) return NativeMethods.INJECT_RFI;
            if (string.Equals(s, "mm", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "manualmap", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(s, "manual-map", StringComparison.OrdinalIgnoreCase)) return NativeMethods.INJECT_MM;
            return NativeMethods.INJECT_CRT;
        }

        /// <summary>进程名通配匹配（支持 * 与 ?，大小写不敏感）</summary>
        internal static bool WildcardMatch(string pattern, string text)
        {
            try
            {
                string rx = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
                    .Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
                return System.Text.RegularExpressions.Regex.IsMatch(text, rx, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            catch { return string.Equals(pattern, text, StringComparison.OrdinalIgnoreCase); }
        }

        /// <summary>当前进程是否以管理员身份运行</summary>
        private static bool IsAdministrator()
        {
            try
            {
                using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
                return new System.Security.Principal.WindowsPrincipal(id)
                    .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch { return false; }
        }
    }
}
