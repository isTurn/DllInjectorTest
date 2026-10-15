// Test target: echoes command line args to a marker file, prints PID, stays alive 120s
//
// The marker file is written next to this executable, derived at runtime from the
// module path -- there is deliberately no compile-time hardcoded directory, so the
// repository can be moved anywhere without breaking the test.
#include <windows.h>
#include <stdio.h>
#include <string.h>

// Build "<dir of this exe>\args_<pid>.txt"
static void BuildMarkerPath(char* out, size_t outSize)
{
    char exe[MAX_PATH];
    if (GetModuleFileNameA(NULL, exe, MAX_PATH) == 0) {
        sprintf_s(out, outSize, "args_%lu.txt", GetCurrentProcessId());
        return;
    }
    char* slash = strrchr(exe, '\\');
    if (slash) *(slash + 1) = 0; else exe[0] = 0;
    sprintf_s(out, outSize, "%sargs_%lu.txt", exe, GetCurrentProcessId());
}

int main(int argc, char* argv[])
{
    // write command line args to args_<pid>.txt to verify launch-argument pass-through
    char p[1024] = "";
    for (int i = 1; i < argc; i++)
    {
        if (i > 1) strcat_s(p, sizeof(p), " ");
        strcat_s(p, sizeof(p), argv[i]);
    }

    char path[MAX_PATH];
    BuildMarkerPath(path, MAX_PATH);

    HANDLE h = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE)
    {
        char buf[1100];
        int len = sprintf_s(buf, sizeof(buf), "argc=%d args=[%s] tick=%lu\n", argc, p, GetTickCount());
        DWORD written = 0;
        WriteFile(h, buf, (DWORD)len, &written, NULL);
        CloseHandle(h);
    }
    else
    {
        printf("Warning: could not write marker file: %s (error %lu)\n", path, GetLastError());
    }

    printf("Target started. PID=%lu, waiting 120s...\n", GetCurrentProcessId());
    fflush(stdout);
    for (int i = 0; i < 120; i++)
    {
        // alertable sleep so QueueUserAPC (user-mode APC) gets processed
        SleepEx(1000, TRUE);
    }
    printf("Target exiting.\n");
    return 0;
}
