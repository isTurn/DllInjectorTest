// ============================================================================
//  TestTextTarget.c — 文本 Hook 的验证目标程序
//
//  用 GDI 输出若干段文本，供 TextHookDll 的 IAT Hook 捕获。
//  不弹窗口：建一个内存 DC + 位图即可驱动 GDI 文本输出，便于自动化验证。
//
//  文本一律使用**硬编码字节数组**，不依赖源码文件编码——
//  这样「抓到的文本是否正确」可以确定性判断（见下方每段文本的注释）。
//
//  ★ 编码选择（重要）：
//    TextHookDll 的 cp= 是**进程级**设置，一个进程只能有一种 *A 系列编码。
//    所以本程序用命令行参数选择输出哪一套 *A 编码，默认 sjis：
//
//      TextTarget_x64.exe            输出 Shift-JIS（配 cp=932）
//      TextTarget_x64.exe gbk        输出 GBK        （配 cp=936）
//
//    用错编码时 *A 系列必然乱码（例如 cp=932 去解 GBK 字节），这是设计使然。
//    *W 系列走宽字符，不受 cp= 影响，两种模式下都应正确。
//
//  编译（MSVC）：
//    cl /nologo /O2 /utf-8 TestTextTarget.c /link /OUT:TextTarget_x64.exe /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
//    或直接用 test\TextHookDll\build.bat
//
//    /utf-8 必需（本文件含 UTF-8 中文注释）；gdi32.lib / user32.lib 也必需
//    （调用了 GDI 文本 API，但没有 #pragma comment(lib)）。
// ============================================================================

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

// "こんにちは" 的 Shift-JIS 字节（cp=932）
static const char kSjisHello[] = "\x82\xb1\x82\xf1\x82\xc9\x82\xbf\x82\xcd";

// "テスト" 的 Shift-JIS 字节（cp=932）
static const char kSjisTest[]  = "\x83\x65\x83\x58\x83\x67";

// "你好，世界" 的 GBK 字节（cp=936）
static const char kGbkHello[]  = "\xc4\xe3\xba\xc3\xa3\xac\xca\xc0\xbd\xe7";

// 宽字符文本（走 *W 系列，无需编码转换）
static const wchar_t kWideText[] = L"\x30ef\x30a4\x30c9\x6587\x5b57"; // ワイド文字

int main(int argc, char** argv)
{
    // 选择 *A 系列的编码：默认 sjis，传 "gbk" 则用 GBK
    int useGbk = (argc > 1 && _stricmp(argv[1], "gbk") == 0);

    // 两套 *A 文本。GBK 模式下没有单独的 "テスト" 字节串，复用 GBK 样本即可。
    const char* ansiHello = useGbk ? kGbkHello : kSjisHello;
    const char* ansiTest  = useGbk ? kGbkHello : kSjisTest;

    // 建内存 DC：GetDC(NULL) 取屏幕 DC 作为兼容基准，再挂一张位图
    HDC     hScreen = GetDC(NULL);
    HDC     hMem    = CreateCompatibleDC(hScreen);
    HBITMAP hBmp    = CreateCompatibleBitmap(hScreen, 800, 600);
    HGDIOBJ hOld    = SelectObject(hMem, hBmp);

    printf("TextTarget started. PID=%lu\n", GetCurrentProcessId());
    printf("ANSI encoding: %s (expect cp=%s)\n",
           useGbk ? "GBK/936" : "Shift-JIS/932", useGbk ? "936" : "932");
    printf("用 GDI 输出文本，共 20 轮，每轮间隔 1 秒。\n");
    fflush(stdout);

    RECT rcA, rcB;
    rcA.left = 10; rcA.top = 130; rcA.right = 400; rcA.bottom = 160;
    rcB.left = 10; rcB.top = 160; rcB.right = 400; rcB.bottom = 190;

    for (int round = 1; round <= 20; round++)
    {
        // 1) TextOutA + ANSI  -> 期望捕获 "こんにちは"(sjis) / "你好，世界"(gbk)
        TextOutA(hMem, 10, 10, ansiHello, (int)strlen(ansiHello));

        // 2) ExtTextOutA + ANSI -> 同上（验证 ExtTextOutA 与 TextOutA 一致）
        ExtTextOutA(hMem, 10, 40, 0, NULL, ansiHello, (UINT)strlen(ansiHello), NULL);

        // 3) TextOutW               -> 期望捕获 "ワイド文字"（两种模式都应正确）
        TextOutW(hMem, 10, 70, kWideText, (int)wcslen(kWideText));

        // 4) ExtTextOutW            -> 期望捕获 "ExtTextOutW 测试"
        const wchar_t* wide2 = L"ExtTextOutW \u6d4b\u8bd5";
        ExtTextOutW(hMem, 10, 100, 0, NULL, wide2, (UINT)wcslen(wide2), NULL);

        // 5) DrawTextA + ANSI       -> 期望捕获 "テスト"(sjis) / "你好，世界"(gbk)
        DrawTextA(hMem, ansiTest, (int)strlen(ansiTest), &rcA, DT_LEFT);

        // 6) DrawTextW              -> 期望捕获 "DrawTextW sample"
        DrawTextW(hMem, L"DrawTextW sample", -1, &rcB, DT_LEFT);

        printf("[round %d] 已输出 6 段文本\n", round);
        fflush(stdout);

        Sleep(1000);
    }

    SelectObject(hMem, hOld);
    DeleteObject(hBmp);
    DeleteDC(hMem);
    ReleaseDC(NULL, hScreen);

    printf("TextTarget exiting.\n");
    return 0;
}
