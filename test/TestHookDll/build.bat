@echo off
rem ============================================================================
rem  Build the "call an export after injection" sample DLL (TestHookDll).
rem
rem  Output (default: test_output\, NOT next to the sources):
rem    TestHookDll-x64.dll   64-bit
rem    TestHookDll-x86.dll   32-bit
rem    TestLoad-x64.exe      in-process validator, x64
rem    TestLoad-x86.exe      in-process validator, x86
rem
rem  Why test_output\ instead of the source directory: the two DLLs are
rem  committed to the repository (they are the probe DLLs CI uses for the
rem  published binary's smoke test), so writing them in place made every single
rem  build dirty the working tree with two binary diffs that carry no source
rem  change -- just a fresh PE timestamp. Regression runs then needed a
rem  "git checkout -- test/TestHookDll/*.dll" afterwards, and forgetting it
rem  meant accidentally committing rebuilt binaries.
rem
rem  To deliberately refresh the committed copies (only a maintainer shipping a
rem  new sample build needs this), pass --update-shipped:
rem
rem    test\TestHookDll\build.bat --update-shipped
rem
rem  It then builds and runs TestLoad.c for BOTH bitnesses, so the export names
rem  and the return codes are verified on the spot instead of being taken on
rem  trust. A mismatch fails the script.
rem
rem  Notes:
rem    - Paths are derived from this script's own location, so the repository
rem      can live anywhere.
rem    - /Brepro makes the output byte-identical across rebuilds with the same
rem      toolchain (it zeroes the PE timestamp and the PDB path). Without it,
rem      two consecutive builds of the same source differ, so "did the shipped
rem      binary actually change?" cannot be answered from a diff.
rem    - Visual Studio is located with vswhere.exe (any edition).
rem    - Messages are ASCII-only on purpose: cmd.exe reads .bat files using the
rem      console code page, so non-ASCII text would be garbled.
rem    - /utf-8 is REQUIRED on every cl line: the sources carry UTF-8 Chinese
rem      comments, but without this switch MSVC decodes them using the system
rem      code page (936/GBK on a Chinese Windows). A mis-decoded comment can
rem      swallow the following newline and produce bogus "undeclared
rem      identifier" errors, or fail outright with warning C4819.
rem    - TestHookDll.def is passed to the linker so the exports keep their
rem      undecorated names on x86 too. Without it, WINAPI (=__stdcall) would
rem      export them as _InstallHook@4 on x86 but as InstallHook on x64, so
rem      GetProcAddress(h, "InstallHook") would return NULL on x86.
rem    - BOTH bitnesses are always built and verified. Keep them in sync.
rem ============================================================================

setlocal
set "SRC=%~dp0"
set "OUT=%~dp0..\..\test_output"

rem Where the two DLLs land. Default is the scratch output directory; the
rem committed copies under the source tree are only rewritten on request.
set "DLLOUT=%OUT%\"
if /i "%~1"=="--update-shipped" set "DLLOUT=%SRC%"

rem cl writes .obj / .exp / .lib into the CURRENT directory (not next to the
rem source). Without this cd, invoking the script from the repo root scatters
rem MSVC intermediates into the repo root.
cd /d "%SRC%"

rem ---- Locate Visual Studio (any edition) via vswhere ----------------------
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found - Visual Studio does not appear to be installed.
    echo         Install "Visual Studio Build Tools" with the C++ workload:
    echo         https://visualstudio.microsoft.com/downloads/
    exit /b 1
)

set "VSPATH="
for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo [ERROR] No Visual Studio installation with the C++ build tools was found.
    echo         Install the "Desktop development with C++" workload.
    exit /b 1
)

set "VC=%VSPATH%\VC\Auxiliary\Build"
if not exist "%VC%\vcvars64.bat" (
    echo [ERROR] vcvars64.bat not found under: %VC%
    exit /b 1
)
echo [INFO] Visual Studio: %VSPATH%
echo [INFO] source        : %SRC%
echo [INFO] verifier out  : %OUT%
echo [INFO] dll out       : %DLLOUT%
echo.

if not exist "%OUT%" md "%OUT%"

rem ---- incremental gate ----------------------------------------------------
rem  Skip the whole script (compile AND verification) when none of the inputs
rem  changed since the last successful run. The fingerprint is the SHA1 of every
rem  input below, in order; see test\_uptodate.bat for why content hashing is
rem  used rather than timestamps.
rem
rem  The script itself is in the list: the compile/link flags live in it, so
rem  changing /O2 to /O1 must trigger a rebuild even though no .c file moved.
rem
rem  Two guards keep the skip honest:
rem    - "have" checks the products still exist. The fingerprint only covers
rem      inputs, so deleting test_output must not leave a stamp claiming that
rem      products which are no longer there are current.
rem    - "commit" is only reached after the checks below pass, so a failed build
rem      never leaves a stamp behind.
rem
rem  --update-shipped must always rebuild: its whole purpose is regenerating the
rem  committed binaries, and skipping would silently leave them stale.
set "FORCE_REBUILD="
if /i "%~1"=="--force" set "FORCE_REBUILD=1"
if /i "%~1"=="--update-shipped" set "FORCE_REBUILD=1"

call "%~dp0..\_uptodate.bat" have "%DLLOUT%TestHookDll-x64.dll" "%DLLOUT%TestHookDll-x86.dll" "%OUT%\TestLoad-x64.exe" "%OUT%\TestLoad-x86.exe"
if errorlevel 1 goto :build

call "%~dp0..\_uptodate.bat" check test-hook-dll "%SRC%TestHookDll.c" "%SRC%TestHookDll.def" "%SRC%TestLoad.c" "%~f0" "%~dp0..\_uptodate.bat"
if errorlevel 1 goto :build

echo [SKIP] %~nx0: inputs unchanged and products present - nothing to do.
echo         Pass --force to rebuild anyway.
echo BUILD_DONE
endlocal
exit /b 0

:build

rem Stale log would make the verification below unprovable. The DLL writes it
rem next to itself, which is now the scratch output directory.
if exist "%DLLOUT%hook_call_log.txt" del /q "%DLLOUT%hook_call_log.txt"

rem ---- x64 -----------------------------------------------------------------
call "%VC%\vcvars64.bat" >nul

cl /nologo /W3 /Brepro /LD /O2 /utf-8 "%SRC%TestHookDll.c" /link /Brepro /DEF:"%SRC%TestHookDll.def" /OUT:"%DLLOUT%TestHookDll-x64.dll"
if errorlevel 1 goto :fail

cl /nologo /W3 /Brepro /O2 /utf-8 "%SRC%TestLoad.c" /link /Brepro /OUT:"%OUT%\TestLoad-x64.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

echo.
echo ---- verify x64 -------------------------------------------------------
"%OUT%\TestLoad-x64.exe" "%DLLOUT%TestHookDll-x64.dll"
if errorlevel 1 goto :fail

rem ---- x86 -----------------------------------------------------------------
call "%VC%\vcvars32.bat" >nul

cl /nologo /W3 /Brepro /LD /O2 /utf-8 "%SRC%TestHookDll.c" /link /Brepro /DEF:"%SRC%TestHookDll.def" /OUT:"%DLLOUT%TestHookDll-x86.dll"
if errorlevel 1 goto :fail

cl /nologo /W3 /Brepro /O2 /utf-8 "%SRC%TestLoad.c" /link /Brepro /OUT:"%OUT%\TestLoad-x86.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

echo.
echo ---- verify x86 -------------------------------------------------------
"%OUT%\TestLoad-x86.exe" "%DLLOUT%TestHookDll-x86.dll"
if errorlevel 1 goto :fail

rem ---- clean intermediates left next to the source -------------------------
del /q "%SRC%*.obj" "%SRC%*.exp" "%SRC%*.lib" "%SRC%*.ilk" "%SRC%*.pdb" 2>nul

echo.
echo ============================================================
echo   BUILD OK - both bitnesses built and verified
echo.
echo   Output: %DLLOUT%
echo.
echo   Inspect the exports by hand if you want:
echo     dumpbin /exports "%DLLOUT%TestHookDll-x64.dll"
echo     dumpbin /exports "%DLLOUT%TestHookDll-x86.dll"
echo   Expected on both: InstallHook / Init / InstallConfig / InstallMulti
echo   (an x86 build without the .def would show _InstallHook@4 etc.)
echo.
echo   The calls above also wrote %DLLOUT%hook_call_log.txt
echo   End-to-end injection (needs the injector built first):
rem Do NOT join these two lines with a trailing caret: cmd would splice the
rem literal word "echo" into the output. Two separate echo lines instead.
echo     DllInjector-x64.exe -inject your_target.exe "%DLLOUT%TestHookDll-x64.dll"
rem Inside double quotes cmd does NOT consume a caret, so "a^|b" would print the
rem caret literally. A plain | inside quotes is safe and prints as intended.
echo         -export InstallConfig -exportarg "server=1.2.3.4|port=8080"
echo.
echo   To refresh the copies committed under test\TestHookDll\, rerun with
echo     test\TestHookDll\build.bat --update-shipped
echo ============================================================

rem Only now, after every check above passed, is the new fingerprint promoted.
call "%~dp0..\_uptodate.bat" commit test-hook-dll
endlocal
exit /b 0

:fail
echo.
echo BUILD_FAIL
endlocal
exit /b 1
