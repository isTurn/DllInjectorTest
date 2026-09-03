// Test target: echoes command line args to a marker file, prints PID, stays alive 120s
#include <windows.h>
#include <stdio.h>

#ifndef MARKER_DIR
#define MARKER_DIR "D:\\Download\\ToDLL\\test_output\\"
#endif

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
    sprintf_s(path, MAX_PATH, "%sargs_%lu.txt", MARKER_DIR, GetCurrentProcessId());
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
