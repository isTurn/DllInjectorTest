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
        public const uint INFINITE          = 0xFFFFFFFF;
        public const uint WAIT_TIMEOUT      = 0x00000102;
        public const uint WAIT_FAILED       = 0xFFFFFFFF;

        // 进程访问权限
        public const uint PROCESS_CREATE_THREAD     = 0x0002;
        public const uint PROCESS_VM_OPERATION      = 0x0008;
        public const uint PROCESS_VM_READ           = 0x0010;
        public const uint PROCESS_VM_WRITE          = 0x0020;
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;

        /// <summary>注入 / 卸载所需的最小权限组合</summary>
        public const uint PROCESS_ACCESS_FOR_INJECT =
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION;

        // 注入方式
        public const int INJECT_CRT = 0;   // CreateRemoteThread（默认，兼容性最好）
        public const int INJECT_NTC = 1;   // NtCreateThreadEx（底层，隐蔽性较好）
        public const int INJECT_APC = 2;   // QueueUserAPC（仅启动时注入，需挂起主线程）

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
        public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeThread(IntPtr hThread, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

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
    }

    public class MainForm : Form
    {
        private Label _lblExe, _lblDll, _tip, _lblLog;
        private TextBox _txtExe;
        private TextBox _txtDll;
        private Button _btnExe;
        private Button _btnDll;
        private Button _btnInject;
        private Label _lblProc;
        private ComboBox _cboProc;
        private Label _lblArgs;
        private TextBox _txtArgs;
        private Label _lblMethod;
        private ComboBox _cboMethod;
        private Button _btnRefresh;
        private Button _btnInjectProc;
        private Button _btnEject;
        private TextBox _log;

        // 96 DPI 逻辑布局基准值
        private const int PadLeft = 12;      // 左侧留白
        private const int LabelWidth = 112;  // 标签区宽度（足够容纳"目标程序:"/"DLL 文件:"）
        private const int BrowseWidth = 120; // 浏览按钮宽度
        private const int RowHeight = 34;

        private float _scale = 1f;  // 当前 DPI 缩放系数（144 DPI 时为 1.5）
        private bool _layouting;    // 防重入

        public MainForm()
        {
            Text = "DLL 注入器";
            Font = new Font("Microsoft YaHei UI", 9F);
            // 关闭框架自动缩放（.NET 8 下对代码构建的窗体不会按 DPI 缩放），改为手动精确缩放
            AutoScaleMode = AutoScaleMode.None;
            ClientSize = new Size(720, 640);
            MinimumSize = new Size(620, 600);
            StartPosition = FormStartPosition.CenterScreen;

            BuildUi();
            ApplyTheme();
            LoadLastSelection();
            _cboMethod.SelectedIndex = ConfigStore.Method;   // 记忆上次注入方式
            Resize += (s, e) => LayoutAll();
            Log($"{"注入器已启动"}（{IntPtr.Size * 8} 位）。");
            Log("使用方式①：选择目标 exe 和 dll（多个用 ; 分隔），可填启动参数，点击\"注入并启动\"。");
            Log("使用方式②：在下方选择运行中的进程，点击\"注入到进程\"或\"卸载 DLL\"。");
            Log("注入方式：CreateRemoteThread / NtCreateThreadEx / QueueUserAPC（仅启动时）。");
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
            if (parts.Length == 4 &&
                int.TryParse(parts[0], out int x) && int.TryParse(parts[1], out int y) &&
                int.TryParse(parts[2], out int w) && int.TryParse(parts[3], out int h) &&
                w >= MinimumSize.Width && h >= MinimumSize.Height)
            {
                var rect = new Rectangle(x, y, w, h);
                bool visible = false;
                foreach (var s in Screen.AllScreens)
                    if (s.WorkingArea.IntersectsWith(rect)) { visible = true; break; }
                if (visible)
                {
                    StartPosition = FormStartPosition.Manual;
                    Bounds = rect;
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
                ClientSize = new Size(Scale(720), Scale(640));
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
                () => _txtExe.Text = PickFile("可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*", _txtExe.Text));

            _lblDll = MakeLabel("DLL 文件:");
            _txtDll = MakeBox();
            _btnDll = MakeBrowseButton("浏览",
                () => { string f = PickFiles("DLL 文件 (*.dll)|*.dll|所有文件 (*.*)|*.*"); if (f != null) _txtDll.Text = f; });

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
                "QueueUserAPC（仅启动时）"
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

            Controls.AddRange(new Control[] { _lblExe, _txtExe, _btnExe, _lblDll, _txtDll, _btnDll,
                _lblArgs, _txtArgs, _btnInject, _tip,
                _lblProc, _cboProc, _btnRefresh, _btnInjectProc, _btnEject, _lblMethod, _cboMethod,
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

                // 第 2 行：DLL 文件
                _lblDll.Location = new Point(padL, y + Scale(6));
                _txtDll.Location = new Point(labelW, y);
                _btnDll.Location = new Point(ClientSize.Width - padL - browseW, y);
                _txtDll.Size = new Size(ClientSize.Width - padL - labelW - gap - browseW - padL, boxH);
                _btnDll.Size = new Size(browseW, boxH);
                y += rowH + Scale(4);

                // 第 3 行：启动参数（全宽输入框）
                _lblArgs.Location = new Point(padL, y + Scale(6));
                _txtArgs.Location = new Point(labelW, y);
                _txtArgs.Size = new Size(ClientSize.Width - padL - labelW - padL, boxH);
                y += rowH + Scale(4);

                // 第 4 行：注入并启动 + 提示
                _btnInject.Location = new Point(labelW, y);
                _btnInject.Size = new Size(Scale(150), btnH);
                _tip.Location = new Point(labelW + Scale(160), y + Scale(7));
                y += rowH + Scale(8);

                // 第 5 行：运行中进程（下拉框 + 刷新）
                _lblProc.Location = new Point(padL, y + Scale(6));
                int refreshW = Scale(70);
                _cboProc.Location = new Point(labelW, y);
                _cboProc.Size = new Size(ClientSize.Width - padL - labelW - gap - refreshW - padL, boxH);
                _btnRefresh.Location = new Point(ClientSize.Width - padL - refreshW, y);
                _btnRefresh.Size = new Size(refreshW, boxH);
                y += rowH;

                // 第 6 行：注入到进程 / 卸载 DLL
                _btnInjectProc.Location = new Point(labelW, y);
                _btnInjectProc.Size = new Size(Scale(150), btnH);
                _btnEject.Location = new Point(labelW + Scale(160), y);
                _btnEject.Size = new Size(Scale(150), btnH);
                y += rowH + Scale(6);

                // 第 7 行：注入方式（下拉框）
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
                MinimumSize = new Size(Scale(620), Scale(600));

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
        private string PickFile(string filter, string currentPath)
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

        private void Log(string msg)
        {
            if (InvokeRequired) { BeginInvoke(new Action<string>(Log), msg); return; }
            _log.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}{Environment.NewLine}");
            // 日志最大行数控制（固定 1000 行）
            int max = 1000;
            string[] lines = _log.Text.Split('\n');
            if (lines.Length > max)
                _log.Text = string.Join("\n", lines, lines.Length - max, max);
            _log.SelectionStart = _log.TextLength;
            _log.ScrollToCaret();
        }

        private async void BtnInject_Click(object sender, EventArgs e)
        {
            string exe = _txtExe.Text.Trim().Trim('"');
            string[] dlls = InjectorCore.SplitDlls(_txtDll.Text);
            string args = _txtArgs.Text.Trim();
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
                await Task.Run(() => InjectorCore.Run(exe, dlls, args, method, Log));
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
            int method = _cboMethod.SelectedIndex;
            ConfigStore.Method = method;   // 记忆注入方式
            var btn = sender as Button;
            btn.Enabled = false;
            try
            {
                await Task.Run(() => InjectorCore.InjectToProcess(pid, dlls, method, Log));
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
    }

    /// <summary>注入核心逻辑（GUI 与命令行模式共用）</summary>
    internal static class InjectorCore
    {
        /// <summary>核心注入流程：挂起启动 -> 逐个注入 DLL -> 恢复主线程 -> 注入结果核验</summary>
        public static bool Run(string exePath, string[] dllPaths, string args, int method, Action<string> log)
        {
            log("================ 开始注入 ================");
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
                    IntPtr remoteBuf, hRemoteThread;
                    if (LoadLibraryIntoProcess(pi.hProcess, pi.hThread, dll, method, log, out remoteBuf, out hRemoteThread))
                    {
                        injected.Add(dll);
                        // CRT/NTC 为同步等待（LoadLibraryW 已完成），路径内存可立即释放；
                        // APC 为异步排队（LoadLibraryW 要等主线程可告警后才执行），其路径内存保留在目标进程内，随进程退出回收。
                        if (method != NativeMethods.INJECT_APC && remoteBuf != IntPtr.Zero)
                            NativeMethods.VirtualFreeEx(pi.hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                    }
                    else if (remoteBuf != IntPtr.Zero)
                        NativeMethods.VirtualFreeEx(pi.hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);

                    if (hRemoteThread != IntPtr.Zero)
                        NativeMethods.CloseHandle(hRemoteThread);
                }
            }
            finally
            {
                NativeMethods.ResumeThread(pi.hThread);
                log("主线程已恢复，目标程序开始运行。");
                NativeMethods.CloseHandle(pi.hThread);
                NativeMethods.CloseHandle(pi.hProcess);
            }

            // 注入结果核验（目标进程已运行，模块列表齐全）
            if (injected.Count > 0)
            {
                log("----- 注入结果核验 -----");
                bool verifyOk = true;
                foreach (var dll in injected)
                    if (!VerifyModuleLoaded(pi.dwProcessId, dll, log)) verifyOk = false;
                if (!verifyOk && method == NativeMethods.INJECT_APC)
                    log("提示: QueueUserAPC 需要目标主线程处于可告警(alertable)等待（如 SleepEx / GetMessage 消息循环），否则 APC 不会执行；失败请改用 CreateRemoteThread 或 NtCreateThreadEx。");
            }

            log(allOk ? "===== 注入流程完成 =====" : "===== 注入流程结束（部分 DLL 未成功，见上方日志）=====");
            return allOk;
        }

        /// <summary>向已运行的进程注入 DLL（OpenProcess + 远程 LoadLibraryW，支持多 DLL）</summary>
        public static bool InjectToProcess(int pid, string[] dllPaths, int method, Action<string> log)
        {
            log("================ 注入到运行中进程 ================");
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

                bool allOk = true;
                var injected = new System.Collections.Generic.List<string>();
                foreach (var dll in dllPaths)
                {
                    log("----- 注入: " + Path.GetFileName(dll) + " -----");
                    IntPtr remoteBuf, hThread;
                    if (LoadLibraryIntoProcess(hProcess, IntPtr.Zero, dll, useMethod, log, out remoteBuf, out hThread))
                        injected.Add(dll);
                    else
                        allOk = false;
                    if (remoteBuf != IntPtr.Zero)
                        NativeMethods.VirtualFreeEx(hProcess, remoteBuf, UIntPtr.Zero, NativeMethods.MEM_RELEASE);
                    if (hThread != IntPtr.Zero)
                        NativeMethods.CloseHandle(hThread);
                }

                if (injected.Count > 0)
                {
                    log("----- 注入结果核验 -----");
                    foreach (var dll in injected)
                        VerifyModuleLoaded(pid, dll, log);
                }

                log(allOk ? "===== 注入到进程完成 =====" : "===== 注入到进程结束（部分 DLL 未成功）=====");
                return allOk;
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        /// <summary>从运行中的进程卸载 DLL（注入器侧枚举模块基址 + 远程 FreeLibrary）</summary>
        public static bool EjectDll(int pid, string dllNameOrPath, Action<string> log)
        {
            log("================ 卸载 DLL ================");
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
                    log($"FreeLibrary 调用完成（返回 {freeResult}，0 表示卸载失败或仍被引用）。");
                }
                finally
                {
                    NativeMethods.CloseHandle(hThread);
                }
                log("===== 卸载完成 =====");
                return true;
            }
            finally
            {
                NativeMethods.CloseHandle(hProcess);
            }
        }

        /// <summary>在目标进程内远程调用 LoadLibraryW 加载 DLL。失败时通过 out 返回已分配资源，由调用方负责清理。</summary>
        private static bool LoadLibraryIntoProcess(IntPtr hProcess, IntPtr hTargetThread, string dllPath, int method, Action<string> log,
            out IntPtr remoteBuf, out IntPtr hRemoteThread)
        {
            remoteBuf = IntPtr.Zero;
            hRemoteThread = IntPtr.Zero;

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
                log("警告: 等待超时（15 秒），DLL 可能在 DllMain 中阻塞。");
                return false;
            }
            if (wait == NativeMethods.WAIT_FAILED)
            {
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

        /// <summary>注入结果核验：按文件名在目标进程模块列表中查找（带重试容忍枚举时序延迟）</summary>
        public static bool VerifyModuleLoaded(int pid, string dllPath, Action<string> log)
        {
            string name = Path.GetFileName(dllPath);
            for (int attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    using var proc = System.Diagnostics.Process.GetProcessById(pid);
                    foreach (System.Diagnostics.ProcessModule m in proc.Modules)
                    {
                        try
                        {
                            if (string.Equals(Path.GetFileName(m.FileName), name, StringComparison.OrdinalIgnoreCase))
                            {
                                log($"核验通过：{name} 已在目标进程模块列表（基址 0x{m.BaseAddress.ToInt64():X}）。");
                                return true;
                            }
                        }
                        catch { }
                    }
                }
                catch (Exception ex)
                {
                    log("警告: 无法枚举目标进程模块（权限不足？）" + ex.Message);
                    return false;
                }
                System.Threading.Thread.Sleep(300);
            }
            log($"警告: 核验未通过——未在目标进程模块列表中找到 {name}（可能已卸载或枚举延迟）。");
            return false;
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
        private static void Reload()
        {
            _data.Clear();
            if (_path == null || !File.Exists(_path)) return;
            var lines = File.ReadAllLines(_path);
            if (lines.Length == 0) return;
            // 兼容旧格式：第一行不含 '=' 时视为纯 exe/dll 两行
            if (!lines[0].Contains('='))
            {
                _data["exe"] = lines[0].Trim();
                if (lines.Length > 1) _data["dll"] = lines[1].Trim();
                return;
            }
            foreach (var line in lines)
            {
                int i = line.IndexOf('=');
                if (i > 0) _data[line.Substring(0, i).Trim()] = line.Substring(i + 1).Trim();
            }
        }

        private static void Flush()
        {
            if (_path == null) return;
            var lines = new System.Collections.Generic.List<string>();
            foreach (var kv in _data)
                lines.Add(kv.Key + "=" + kv.Value);
            File.WriteAllLines(_path, lines, new UTF8Encoding(false));
        }

        private static string Get(string key, string def = "")
        {
            Reload();
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
            Reload();
            _data["exe"] = exe ?? "";
            _data["dll"] = dll ?? "";
            Flush();
        }

        /// <summary>上次使用的注入方式（0/1/2），默认 0（CreateRemoteThread）</summary>
        public static int Method
        {
            get { int m; return int.TryParse(Get("method", "0"), out m) && m >= 0 && m <= 2 ? m : 0; }
            set { if (_path == null) return; Reload(); _data["method"] = value.ToString(); Flush(); }
        }

        /// <summary>窗口位置 "x,y,w,h"，空表示未记忆</summary>
        public static string WindowPos
        {
            get { return Get("winpos", ""); }
            set { if (_path == null) return; Reload(); _data["winpos"] = value; Flush(); }
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

            // 无头命令行模式（用于自动化 / 测试）：
            //   -inject     <exe路径> <dll1> [dll2...] [-args <参数>] [-method crt|ntc|apc]
            //   -injectpid  <pid> <dll1> [dll2...] [-method crt|ntc]
            //   -eject      <pid> <dll文件名>
            if (args.Length >= 1 &&
                (string.Equals(args[0], "-inject", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-injectpid", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(args[0], "-eject", StringComparison.OrdinalIgnoreCase)))
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
                        // -inject <exe> <dll...> [-args ...] [-method ...]
                        string exe = args[1];
                        var dlls = new System.Collections.Generic.List<string>();
                        string cmdArgs = "";
                        int method = NativeMethods.INJECT_CRT;
                        bool inArgs = false;
                        for (int i = 2; i < args.Length; i++)
                        {
                            if (string.Equals(args[i], "-args", StringComparison.OrdinalIgnoreCase)) { inArgs = true; continue; }
                            if (string.Equals(args[i], "-method", StringComparison.OrdinalIgnoreCase))
                            { inArgs = false; if (i + 1 < args.Length) method = ParseMethod(args[++i]); continue; }
                            if (inArgs) cmdArgs = (cmdArgs.Length > 0 ? cmdArgs + " " : "") + args[i];
                            else dlls.Add(args[i]);
                        }
                        ok = InjectorCore.Run(exe, dlls.ToArray(), cmdArgs, method, log);
                    }
                    else if (string.Equals(args[0], "-injectpid", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
                    {
                        // -injectpid <pid> <dll...> [-method ...]
                        int pid = int.Parse(args[1]);
                        var dlls = new System.Collections.Generic.List<string>();
                        int method = NativeMethods.INJECT_CRT;
                        for (int i = 2; i < args.Length; i++)
                        {
                            if (string.Equals(args[i], "-method", StringComparison.OrdinalIgnoreCase))
                            { if (i + 1 < args.Length) method = ParseMethod(args[++i]); continue; }
                            dlls.Add(args[i]);
                        }
                        ok = InjectorCore.InjectToProcess(pid, dlls.ToArray(), method, log);
                    }
                    else if (string.Equals(args[0], "-eject", StringComparison.OrdinalIgnoreCase) && args.Length >= 3)
                        ok = InjectorCore.EjectDll(int.Parse(args[1]), args[2], log);
                    else
                        Console.WriteLine("用法: DllInjector.exe -inject <exe> <dll...> [-args ...] [-method crt|ntc|apc] | -injectpid <pid> <dll...> [-method crt|ntc] | -eject <pid> <dll名>");

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

        /// <summary>解析 CLI 注入方式参数（crt / ntc / apc，默认 crt）</summary>
        private static int ParseMethod(string s)
        {
            if (string.Equals(s, "ntc", StringComparison.OrdinalIgnoreCase)) return NativeMethods.INJECT_NTC;
            if (string.Equals(s, "apc", StringComparison.OrdinalIgnoreCase)) return NativeMethods.INJECT_APC;
            return NativeMethods.INJECT_CRT;
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
