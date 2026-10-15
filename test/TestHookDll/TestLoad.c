// TestLoad.c - in-process verifier for the TestHookDll sample DLL.
//
// What it checks (and why it exists):
//
//   1. The DLL loads at all.
//   2. All four exports resolve via GetProcAddress() using their UNDECORATED
//      names. This is the regression that TestHookDll.def guards against: on
//      x86, __stdcall (WINAPI) used to decorate the exports as _InstallHook@4,
//      so GetProcAddress(h, "InstallHook") returned NULL on 32-bit builds even
//      though the injector itself coped (PeHelper.GetExportRva matches
//      "_name@n").
//   3. The exports actually run and return the documented codes.
//   4. The DLL really writes hook_call_log.txt next to itself.
//
// It is built and run for BOTH bitnesses by build.bat, so an x86/x64 export
// mismatch can never slip through unnoticed again.
//
// ASCII-only on purpose: this file must compile regardless of the source code
// page, and it is built with the same /utf-8 switch as everything else.
//
// Build (see build.bat):
//   x64: cl /nologo /O2 /utf-8 TestLoad.c /link /OUT:TestLoad-x64.exe /SUBSYSTEM:CONSOLE
//   x86: cl /nologo /O2 /utf-8 TestLoad.c /link /OUT:TestLoad-x86.exe /SUBSYSTEM:CONSOLE
//
// Usage:
//   TestLoad-x64.exe <path-to-TestHookDll.dll>
// Exit code: 0 = all checks passed, non-zero = failure.

#include <windows.h>
#include <stdio.h>

typedef DWORD (WINAPI *PFN_ONE)(LPVOID);
typedef DWORD (WINAPI *PFN_MULTI)(LPVOID*);

static int g_failures = 0;

static void CheckExport(const char* name, void* p)
{
    printf("  [%-4s] GetProcAddress(\"%s\") = %p\n", p ? "OK" : "NULL", name, p);
    if (!p) g_failures++;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("usage: %s <path-to-TestHookDll.dll>\n", argv[0]);
        return 64;
    }
    const char* path = argv[1];

    printf("LoadLibraryA(\"%s\")\n", path);
    SetLastError(0);
    HMODULE h = LoadLibraryA(path);
    printf("  hModule = %p   GetLastError = %lu\n\n", (void*)h, (unsigned long)GetLastError());
    if (!h) {
        printf("RESULT: FAIL (LoadLibrary)\n");
        return 1;
    }

    PFN_ONE   Init          = (PFN_ONE)(void*)GetProcAddress(h, "Init");
    PFN_ONE   InstallHook   = (PFN_ONE)(void*)GetProcAddress(h, "InstallHook");
    PFN_ONE   InstallConfig = (PFN_ONE)(void*)GetProcAddress(h, "InstallConfig");
    PFN_MULTI InstallMulti  = (PFN_MULTI)(void*)GetProcAddress(h, "InstallMulti");

    CheckExport("Init",          (void*)Init);
    CheckExport("InstallHook",   (void*)InstallHook);
    CheckExport("InstallConfig", (void*)InstallConfig);
    CheckExport("InstallMulti",  (void*)InstallMulti);

    if (g_failures) {
        printf("\nRESULT: FAIL (%d export(s) missing under their undecorated name)\n", g_failures);
        printf("        Is TestHookDll.def passed to the linker? On x86 the exports\n");
        printf("        would otherwise be _Init@4 / _InstallHook@4 / ...\n");
        FreeLibrary(h);
        return 2;
    }
    printf("\n");

    // Documented return codes: Init -> 42, InstallHook -> 1,
    // InstallConfig -> number of key=value pairs, InstallMulti -> argument count.
    DWORD rInit = Init(NULL);
    printf("Init(NULL)                                       -> %lu\n", (unsigned long)rInit);
    if (rInit != 42) g_failures++;

    DWORD rHook = InstallHook((LPVOID)L"hello");
    printf("InstallHook(L\"hello\")                            -> %lu\n", (unsigned long)rHook);
    if (rHook != 1) g_failures++;

    DWORD rCfg = InstallConfig((LPVOID)L"server=1.2.3.4|port=8080|autostart=1");
    printf("InstallConfig(L\"server=1.2.3.4|port=8080|...\")    -> %lu\n", (unsigned long)rCfg);
    if (rCfg != 3) g_failures++;

    // InstallMulti receives a NULL-terminated array of UTF-16 string pointers,
    // exactly the layout the injector builds for "a||b||c".
    LPVOID args[4];
    args[0] = (LPVOID)L"\u5f20\u4e09";        // non-ASCII on purpose
    args[1] = (LPVOID)L"2024-01-01";
    args[2] = (LPVOID)L"admin";
    args[3] = NULL;
    DWORD rMulti = InstallMulti(args);
    printf("InstallMulti([3 args])                           -> %lu\n", (unsigned long)rMulti);
    if (rMulti != 3) g_failures++;

    FreeLibrary(h);

    if (g_failures) {
        printf("\nRESULT: FAIL (%d check(s) returned an unexpected value)\n", g_failures);
        return 3;
    }
    printf("\nRESULT: OK\n");
    return 0;
}
