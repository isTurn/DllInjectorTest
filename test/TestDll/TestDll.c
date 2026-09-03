// Test DLL: on DLL_PROCESS_ATTACH writes a marker file to prove DllMain runs in target process
#include <windows.h>
#include <stdio.h>

#ifndef MARKER_DIR
#define MARKER_DIR "D:\\Download\\ToDLL\\test_output\\"
#endif

// marker filename prefix (distinguish DLL variants: TestDllA -> attachA, TestDllB -> attachB)
#ifndef MARKER_PREFIX
#define MARKER_PREFIX "attach"
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        char path[MAX_PATH];
        sprintf_s(path, MAX_PATH, "%s%s_%lu.txt", MARKER_DIR, MARKER_PREFIX, GetCurrentProcessId());
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
    return TRUE;
}
