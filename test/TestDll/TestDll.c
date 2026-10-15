// Test DLL: on DLL_PROCESS_ATTACH writes a marker file to prove DllMain runs in target process
#include <windows.h>
#include <stdio.h>
#include <string.h>

// marker filename prefix (distinguish DLL variants: TestDllA -> attachA, TestDllB -> attachB)
#ifndef MARKER_PREFIX
#define MARKER_PREFIX "attach"
#endif

// Resolve the directory that receives the marker file, into `out` (size `outSize`).
// Returns 1 on success, 0 when no writable candidate directory could be found.
//
// The directory used to be hard-coded to an absolute developer path, which made
// the whole test suite fail silently (no marker written, no error) as soon as the
// repository was moved or cloned elsewhere. It is now derived at run time:
//
//   1. compile-time MARKER_DIR override, if one was passed (/DMARKER_DIR=...)
//   2. this DLL's own directory   - normal LoadLibrary-based injection
//   3. the host EXE's directory   - manual mapping does not register the image in
//                                   the PEB module list, so (2) fails there; the
//                                   test target EXE lives next to the test DLLs,
//                                   so the marker still lands in test_output\
//   4. %TEMP%                     - last resort, always writable
static int ResolveMarkerDir(HMODULE self, char* out, size_t outSize)
{
#ifdef MARKER_DIR
    (void)self;
    return strcpy_s(out, outSize, MARKER_DIR) == 0;
#else
    char path[MAX_PATH];

    DWORD n = GetModuleFileNameA(self, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        n = GetModuleFileNameA(NULL, path, MAX_PATH);

    if (n > 0 && n < MAX_PATH)
    {
        char* slash = strrchr(path, '\\');
        if (slash)
        {
            *(slash + 1) = '\0';
            if (strcpy_s(out, outSize, path) == 0)
                return 1;
        }
    }

    DWORD t = GetTempPathA((DWORD)outSize, out);
    return t > 0 && t < (DWORD)outSize;
#endif
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);

        // GetModuleFileNameA is safe to call here: it does not take the loader
        // lock in a way that can deadlock during DLL_PROCESS_ATTACH.
        char dir[MAX_PATH];
        if (ResolveMarkerDir(hModule, dir, sizeof(dir)))
        {
            char path[MAX_PATH];
            sprintf_s(path, MAX_PATH, "%s%s_%lu.txt", dir, MARKER_PREFIX, GetCurrentProcessId());
            HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE)
            {
                char buf[256];
                int len = sprintf_s(buf, sizeof(buf),
                                    "DLL_PROCESS_ATTACH OK, PID=%lu, TID=%lu, module=0x%p, tick=%lu\n",
                                    GetCurrentProcessId(), GetCurrentThreadId(), hModule, GetTickCount());
                DWORD written = 0;
                WriteFile(h, buf, (DWORD)len, &written, NULL);
                CloseHandle(h);
            }
        }
    }
    return TRUE;
}
