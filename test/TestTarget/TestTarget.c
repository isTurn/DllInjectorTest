// Test target: prints PID and stays alive 120s for injection verification
#include <windows.h>
#include <stdio.h>

int main(void)
{
    printf("Target started. PID=%lu, waiting 120s...\n", GetCurrentProcessId());
    fflush(stdout);
    for (int i = 0; i < 120; i++)
    {
        Sleep(1000);
    }
    printf("Target exiting.\n");
    return 0;
}
