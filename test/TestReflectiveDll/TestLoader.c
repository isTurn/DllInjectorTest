// TestLoader.c - in-process validation of a reflective DLL (x64/x86).
// Rebuilds the image in MEMORY layout (headers + sections at VirtualAddress),
// resolves ReflectiveLoader RVA dynamically, then calls it inside this process
// exactly like the injector starts a remote thread. Success = rfi_call_log.txt.
#include <windows.h>
#include <stdio.h>

// Resolve a named export to its RVA (from a memory-laid-out image in buf)
static DWORD FindExportRva(const unsigned char* buf, const char* want)
{
    DWORD peOff = *(const DWORD*)(buf + 0x3C);
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(void*)(buf + peOff);
    IMAGE_DATA_DIRECTORY* ed = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!ed->VirtualAddress || !ed->Size) return 0;
    IMAGE_EXPORT_DIRECTORY* ex = (IMAGE_EXPORT_DIRECTORY*)(buf + ed->VirtualAddress);
    DWORD* names = (DWORD*)(buf + ex->AddressOfNames);
    WORD* ords  = (WORD*)(buf + ex->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(buf + ex->AddressOfFunctions);
    for (DWORD i = 0; i < ex->NumberOfNames; i++)
    {
        const char* n = (const char*)(buf + names[i]);
        int j; for (j = 0; ; j++)
        {
            if (n[j] != want[j]) break;
            if (want[j] == 0) return funcs[ords[i]];
        }
    }
    return 0;
}

int main(int argc, char** argv)
{
    const char* path = argc > 1 ? argv[1] :
        "D:\\Download\\ToDLL\\test\\TestReflectiveDll\\TestReflectiveDll-x64.dll";
    FILE* f = fopen(path, "rb");
    if (!f) { printf("open fail: %s\n", path); return 1; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char* raw = (unsigned char*)malloc((size_t)sz);
    fread(raw, 1, (size_t)sz, f); fclose(f);

    DWORD peOff = *(const DWORD*)(raw + 0x3C);
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(void*)(raw + peOff);

    // Allocate the memory-layout image. x86 images use absolute addressing of
    // globals/consts (relative to their ImageBase), so the raw buffer MUST be
    // placed at the DLL's ImageBase; x64 uses RIP-relative so any address works.
    LPVOID want = (LPVOID)nt->OptionalHeader.ImageBase;
    unsigned char* buf = (unsigned char*)VirtualAlloc(want,
        nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!buf)
    {
        printf("ImageBase alloc at %p failed, retry any-address\n", want);
        buf = (unsigned char*)VirtualAlloc(NULL,
            nt->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }
    if (!buf) { printf("alloc fail\n"); return 1; }
    printf("mem-layout buf: %p (want %p) size=%08X\n", buf, want, nt->OptionalHeader.SizeOfImage);
    memcpy(buf, raw, nt->OptionalHeader.SizeOfHeaders);
    IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (sh[i].SizeOfRawData)
            memcpy(buf + sh[i].VirtualAddress,
                   raw + sh[i].PointerToRawData, sh[i].SizeOfRawData);
    printf("mem-layout buf: %p size=%08X\n", buf, nt->OptionalHeader.SizeOfImage);

    DWORD loaderRva = FindExportRva(buf, "ReflectiveLoader");
    if (!loaderRva) { printf("ReflectiveLoader export not found\n"); return 1; }
    printf("ReflectiveLoader RVA=0x%X\n", loaderRva);

#if defined(_WIN64)
    ULONG_PTR (*fn)(void) = (ULONG_PTR(*)(void))(buf + loaderRva);
    ULONG_PTR ret = 0;
    __try { ret = fn(); }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION_RECORD er = GetExceptionInformation()->ExceptionRecord;
        printf("EXCEPTION code=%08X at addr=%p\n", er->ExceptionCode, er->ExceptionAddress);
        ret = 0;
    }
    printf("ReflectiveLoader returned: %p (low32=%08X)\n", (void*)ret, (unsigned)ret & 0xFFFFFFFF);
#else
    ULONG_PTR (__cdecl *fn)(void) = (ULONG_PTR(__cdecl*)(void))(buf + loaderRva);
    ULONG_PTR ret = 0;
    __try { ret = fn(); }
    __except(EXCEPTION_EXECUTE_HANDLER)
    {
        PEXCEPTION_RECORD er = GetExceptionInformation()->ExceptionRecord;
        printf("EXCEPTION code=%08X at addr=%p\n", er->ExceptionCode, er->ExceptionAddress);
        ret = 0;
    }
    printf("ReflectiveLoader returned: %p (low32=%08X)\n", (void*)ret, (unsigned)ret & 0xFFFFFFFF);
#endif

    FILE* lg = fopen("C:\\Windows\\Temp\\rfi_call_log.txt", "rb");
    if (lg) { char line[256]; while (fgets(line, sizeof line, lg)) printf("LOG: %s", line); fclose(lg); }
    else printf("(no log file)\n");
    return 0;
}
