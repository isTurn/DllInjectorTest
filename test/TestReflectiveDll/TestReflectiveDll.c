// TestReflectiveDll.c
// A test "reflective DLL" with a complete, self-contained ReflectiveLoader.
//
// The injector copies this DLL's raw bytes into the target process and starts a
// remote thread at ReflectiveLoader. The loader performs the whole PE mapping
// in-process WITHOUT relying on its own IAT (which is not filled yet): it first
// resolves kernel32 exports via the PEB (GS/FS segment read, pure memory work),
// then maps headers/sections, applies relocations, fills the IAT and calls
// DllMain. After mapping it writes C:\Windows\Temp\rfi_call_log.txt as proof.

#include <windows.h>
#include <intrin.h>
#include <winternl.h>

// ------------------------------------------------------------------
// Resolved kernel32 function pointers (no compiler IAT usage before fill)
// ------------------------------------------------------------------
typedef ULONG_PTR (WINAPI *PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE   (WINAPI *PFN_LoadLibraryA)(LPCSTR);
typedef LPVOID    (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE    (WINAPI *PFN_CreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL      (WINAPI *PFN_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef int       (WINAPI *PFN_lstrlenA)(LPCSTR);
typedef BOOL      (WINAPI *PFN_CloseHandle)(HANDLE);

static PFN_CreateFileA g_CreateFileA;
static PFN_WriteFile   g_WriteFile;
static PFN_lstrlenA    g_lstrlenA;
static PFN_CloseHandle g_CloseHandle;

// ------------------------------------------------------------------
// Log (uses resolved pointers only)
// ------------------------------------------------------------------
static void RfiLog(const char* msg)
{
    if (!g_CreateFileA) return;
    HANDLE h = g_CreateFileA("C:\\Windows\\Temp\\rfi_call_log.txt", 4 /* FILE_APPEND_DATA */,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 4 /* OPEN_ALWAYS */, 0x80 /* NORMAL */, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wr;
    g_WriteFile(h, msg, (DWORD)g_lstrlenA(msg), &wr, NULL);
    g_WriteFile(h, "\r\n", 2, &wr, NULL);
    g_CloseHandle(h);
}

// ------------------------------------------------------------------
// Pure helpers (no imports)
// ------------------------------------------------------------------
// Byte-copy / zero-fill loops. MUST NOT use memcpy/memset here: the
// compiler would emit calls to the CRT __imp_memcpy/__imp_memset, which
// go through the DLL's own IAT - not filled while running in the raw
// buffer. These loops compile to plain rep movs / rep stos with no IAT.
static void RCopy(void* dst, const void* src, SIZE_T n)
{
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    while (n--) *d++ = *s++;
}
static void RZero(void* dst, SIZE_T n)
{
    BYTE* d = (BYTE*)dst;
    while (n--) *d++ = 0;
}

static int StrEqA(const char* a, const char* b)
{
    while (*a && *b && *a == *b) { a++; b++; }
    return (*a == 0 && *b == 0);
}

// case-insensitive compare of wchar name against "kernel32.dll"
static int IsKernel32(const wchar_t* w)
{
    const wchar_t* k = L"kernel32.dll";
    for (int i = 0; ; i++)
    {
        wchar_t a = w[i];
        wchar_t b = k[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (a != b) return 0;
        if (b == 0) return 1;
    }
}

// Resolve an export by name from a module base (no imports)
static ULONG_PTR GetExportAddr(ULONG_PTR modBase, const char* name)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)modBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(modBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY* edd = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!edd->VirtualAddress || !edd->Size) return 0;
    IMAGE_EXPORT_DIRECTORY* ed = (IMAGE_EXPORT_DIRECTORY*)(modBase + edd->VirtualAddress);
    if (!ed->NumberOfNames) return 0;
    DWORD* names = (DWORD*)(modBase + ed->AddressOfNames);
    WORD*  ords  = (WORD*)(modBase + ed->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(modBase + ed->AddressOfFunctions);
    for (DWORD i = 0; i < ed->NumberOfNames; i++)
    {
        const char* n = (const char*)(modBase + names[i]);
        if (StrEqA(n, name)) return modBase + funcs[ords[i]];
    }
    return 0;
}

// Resolve kernel32 base via PEB (GS:[0x60] on x64, FS:[0x30] on x86).
// Walk PEB_LDR_DATA->InMemoryOrderModuleList (offset 0x20 x64 / 0x1C x86).
// Per-entry offsets below are measured from the LIST_ENTRY field itself.
static ULONG_PTR K32Base(void)
{
#if defined(_WIN64)
    ULONG_PTR peb = __readgsqword(0x60);
    if (!peb) return 0;
    ULONG_PTR ldr = *(ULONG_PTR*)(peb + 0x18);      // PEB->Ldr
    ULONG_PTR headOff = 0x20;                        // InMemoryOrderModuleList
    ULONG_PTR dllOff = 0x20;                         // DllBase (from InMemoryOrderLinks)
    ULONG_PTR lenOff = 0x48;                         // BaseDllName.Length
    ULONG_PTR bufOff = 0x50;                         // BaseDllName.Buffer
#else
    ULONG_PTR peb = __readfsdword(0x30);
    if (!peb) return 0;
    ULONG_PTR ldr = *(ULONG_PTR*)(peb + 0x0C);       // PEB->Ldr
    ULONG_PTR headOff = 0x1C;                        // InMemoryOrderModuleList
    ULONG_PTR dllOff = 0x08;                         // DllBase (from InMemoryOrderLinks)
    ULONG_PTR lenOff = 0x1C;                         // BaseDllName.Length
    ULONG_PTR bufOff = 0x20;                         // BaseDllName.Buffer
#endif
    if (!ldr) return 0;
    ULONG_PTR head = ldr + headOff;
    ULONG_PTR e = *(ULONG_PTR*)head;                 // head.Flink
    while (e && e != head)
    {
        ULONG_PTR dllBase = *(ULONG_PTR*)(e + dllOff);
        USHORT len = *(USHORT*)(e + lenOff);
        const wchar_t* buf = (const wchar_t*)(*(ULONG_PTR*)(e + bufOff));
        if (dllBase && buf && len >= 24 && IsKernel32(buf))
            return dllBase;
        e = *(ULONG_PTR*)e;                          // Flink
    }
    return 0;
}

// ------------------------------------------------------------------
// Reflective mapping core. baseRaw = 64K-aligned block with raw DLL bytes.
// ------------------------------------------------------------------
LPVOID RfiMap(LPVOID baseRaw)
{
    // 0. Resolve kernel32 exports we need before touching the IAT
    ULONG_PTR k32 = K32Base();
    if (!k32) { return NULL; }
    PFN_VirtualAlloc   pVA   = (PFN_VirtualAlloc)GetExportAddr(k32, "VirtualAlloc");
    PFN_LoadLibraryA   pLL   = (PFN_LoadLibraryA)GetExportAddr(k32, "LoadLibraryA");
    PFN_GetProcAddress pGPA  = (PFN_GetProcAddress)GetExportAddr(k32, "GetProcAddress");
    g_CreateFileA  = (PFN_CreateFileA)GetExportAddr(k32, "CreateFileA");
    g_WriteFile    = (PFN_WriteFile)GetExportAddr(k32, "WriteFile");
    g_lstrlenA     = (PFN_lstrlenA)GetExportAddr(k32, "lstrlenA");
    g_CloseHandle  = (PFN_CloseHandle)GetExportAddr(k32, "CloseHandle");
    if (!pVA || !pLL || !pGPA || !g_CreateFileA || !g_WriteFile || !g_lstrlenA || !g_CloseHandle)
    { RfiLog("RfiMap: kernel32 export resolve failed"); return NULL; }

    // 1. Scan backward for MZ
    ULONG_PTR p = (ULONG_PTR)baseRaw & ~(ULONG_PTR)0xFFFF;
    IMAGE_DOS_HEADER* dos = NULL;
    while (p >= 0x10000)
    {
        if (*(WORD*)p == IMAGE_DOS_SIGNATURE)
        {
            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(p + ((IMAGE_DOS_HEADER*)p)->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) { dos = (IMAGE_DOS_HEADER*)p; break; }
        }
        p -= 0x10000;
    }
    if (!dos) { RfiLog("RfiMap: MZ not found"); return NULL; }

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((ULONG_PTR)dos + dos->e_lfanew);
    ULONG_PTR rawBase = (ULONG_PTR)dos;

    // 2. Allocate SizeOfImage of fresh RWX memory
    LPVOID newBase = pVA(NULL, nt->OptionalHeader.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!newBase) { RfiLog("RfiMap: VirtualAlloc failed"); return NULL; }
    ULONG_PTR dst = (ULONG_PTR)newBase;

    // 3. Copy headers
    RCopy((void*)dst, (void*)rawBase, nt->OptionalHeader.SizeOfHeaders);

    // 4. Copy each section (zero-fill BSS).
    // NOTE: baseRaw points at an image already laid out in MEMORY layout
    // (headers at +0, sections at their VirtualAddress), so section bytes are
    // read from rawBase + VirtualAddress, not from the file's raw offset.
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (sec[i].SizeOfRawData > 0)
            RCopy((void*)(dst + sec[i].VirtualAddress),
                   (void*)(rawBase + sec[i].VirtualAddress),
                   sec[i].SizeOfRawData);
        if (sec[i].Misc.VirtualSize > sec[i].SizeOfRawData)
            RZero((void*)(dst + sec[i].VirtualAddress + sec[i].SizeOfRawData),
                   sec[i].Misc.VirtualSize - sec[i].SizeOfRawData);
    }

    // 5. Relocations (apply base-address delta)
    LONG_PTR delta = (LONG_PTR)((ULONG_PTR)newBase - (ULONG_PTR)nt->OptionalHeader.ImageBase);
    if (delta != 0)
    {
        IMAGE_DATA_DIRECTORY* relocDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->VirtualAddress && relocDir->Size)
        {
            ULONG_PTR relocBase = dst + relocDir->VirtualAddress;
            ULONG_PTR end = relocBase + relocDir->Size;
            ULONG_PTR r = relocBase;
            while (r < end)
            {
                IMAGE_BASE_RELOCATION* blk = (IMAGE_BASE_RELOCATION*)r;
                if (!blk->SizeOfBlock) break;
                DWORD count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* entries = (WORD*)((ULONG_PTR)blk + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD k = 0; k < count; k++)
                {
                    WORD type = entries[k] >> 12;
                    WORD off = entries[k] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64)
                    {
                        ULONG_PTR* slot = (ULONG_PTR*)(dst + blk->VirtualAddress + off);
                        *slot = (ULONG_PTR)(*slot + delta);
                    }
                    else if (type == IMAGE_REL_BASED_HIGHLOW)
                    {
                        DWORD* slot = (DWORD*)(dst + blk->VirtualAddress + off);
                        *slot = (DWORD)((ULONG_PTR)*slot + delta);
                    }
                }
                r += blk->SizeOfBlock;
            }
        }
    }

    // 6. Fill IAT (import directory) using resolved kernel32 exports
    IMAGE_DATA_DIRECTORY* impDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir->VirtualAddress && impDir->Size)
    {
        IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(dst + impDir->VirtualAddress);
        while (imp->Name)
        {
            char* dllName = (char*)(dst + imp->Name);
            HMODULE hMod = pLL(dllName);
            if (hMod)
            {
                IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(dst +
                    (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
                IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)(dst + imp->FirstThunk);
                for (; thunk->u1.AddressOfData; thunk++, iat++)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal))
                        iat->u1.Function = (ULONG_PTR)pGPA(hMod,
                            (LPCSTR)(thunk->u1.Ordinal & 0xFFFF));
                    else
                    {
                        IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(dst + thunk->u1.AddressOfData);
                        iat->u1.Function = (ULONG_PTR)pGPA(hMod, (LPCSTR)ibn->Name);
                    }
                }
            }
            imp++;
        }
    }

    // 7. Call DllMain (DLL_PROCESS_ATTACH)
    if (nt->OptionalHeader.AddressOfEntryPoint)
    {
        BOOL (WINAPI *pDllMain)(HINSTANCE, DWORD, LPVOID) =
            (BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))(dst + nt->OptionalHeader.AddressOfEntryPoint);
        pDllMain((HINSTANCE)newBase, DLL_PROCESS_ATTACH, NULL);
    }

    RfiLog("RfiMap: mapped ok");
    return newBase;
}

// ------------------------------------------------------------------
// DllMain: called by RfiMap after mapping succeeds (IAT is filled now,
// so normal CRT-free API usage is fine).
// ------------------------------------------------------------------
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
        RfiLog("TestReflectiveDll DllMain attach OK");
    return TRUE;
}
