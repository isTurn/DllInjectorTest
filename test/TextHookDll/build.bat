@echo off
rem ============================================================================
rem  Build the text-hook material, then verify it end-to-end.
rem
rem  Output: ..\..\test_output\
rem    TextHookDll-x64.dll / TextHookDll-x86.dll   the hook DLL (both bitnesses)
rem    TextHookDll.profiles.ini                    engine profile template
rem    TextHookClient.exe                          named-pipe consumer (x64)
rem    TextTarget_x64.exe / TextTarget_x86.exe     GDI text target for testing
rem    TestTextHook-x64.exe / -x86.exe             in-process end-to-end verifier
rem
rem  BOTH bitnesses are always built AND verified. Keep them in sync.
rem
rem  Notes:
rem    - Paths are derived from this script's own location, so the repository
rem      can live anywhere.
rem    - Visual Studio is located with vswhere.exe (any edition).
rem    - Messages are ASCII-only on purpose: cmd.exe reads .bat files using the
rem      console code page, so non-ASCII text would be garbled.
rem    - /utf-8 is REQUIRED on every cl line: the sources carry UTF-8 Chinese
rem      comments, but without this switch MSVC decodes them using the system
rem      code page (936/GBK on a Chinese Windows). A mis-decoded comment can
rem      swallow the following newline and produce bogus "undeclared
rem      identifier" errors, or fail outright with warning C4819.
rem    - TestTextTarget and TestTextHook call GDI/user32 but have no
rem      #pragma comment(lib), so gdi32.lib / user32.lib must be named
rem      explicitly on the link line.
rem    - TextHookDll.def is passed to the linker so the exports keep their
rem      undecorated names on x86 too. Without it, WINAPI (=__stdcall) would
rem      export them as _InstallConfig@4 on x86 but as InstallConfig on x64,
rem      so GetProcAddress(h, "InstallConfig") would return NULL on x86.
rem      TestTextHook checks exactly that, for both bitnesses.
rem ============================================================================

setlocal
set "SRC=%~dp0"
set "OUT=%~dp0..\..\test_output"
set "TARGET=%~dp0..\TestTextTarget"

rem cl writes .obj / .exp / .lib into the CURRENT directory (not next to the
rem source), and the linker resolves some paths relative to it too. Without
rem this cd, invoking the script from the repo root scatters MSVC
rem intermediates into the repo root and can make the link step fail.
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
echo [INFO] output        : %OUT%
echo.

if not exist "%OUT%" md "%OUT%"

rem Ship the profile template next to the DLL: the DLL auto-loads it from
rem its own directory.
copy /y "%SRC%TextHookDll.profiles.ini" "%OUT%\TextHookDll.profiles.ini" >nul

rem ---- x64 -----------------------------------------------------------------
echo [1/2] building x64 ...
call "%VC%\vcvars64.bat" >nul

cl /nologo /LD /O2 /utf-8 "%SRC%TextHookDll.c" /link /DEF:"%SRC%TextHookDll.def" /OUT:"%OUT%\TextHookDll-x64.dll"
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%SRC%TextHookClient.c" /link /OUT:"%OUT%\TextHookClient.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%TARGET%\TestTextTarget.c" /link /OUT:"%OUT%\TextTarget_x64.exe" /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%SRC%TestTextHook.c" /link /OUT:"%OUT%\TestTextHook-x64.exe" /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
if errorlevel 1 goto :fail

rem ---- x86 -----------------------------------------------------------------
echo [2/2] building x86 ...
call "%VC%\vcvars32.bat" >nul

cl /nologo /LD /O2 /utf-8 "%SRC%TextHookDll.c" /link /DEF:"%SRC%TextHookDll.def" /OUT:"%OUT%\TextHookDll-x86.dll"
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%TARGET%\TestTextTarget.c" /link /OUT:"%OUT%\TextTarget_x86.exe" /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%SRC%TestTextHook.c" /link /OUT:"%OUT%\TestTextHook-x86.exe" /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
if errorlevel 1 goto :fail

rem ---- clean intermediates left next to the sources ------------------------
del /q "%SRC%*.obj" "%SRC%*.exp" "%SRC%*.lib" 2>nul
del /q "%TARGET%\*.obj" "%TARGET%\*.exp" "%TARGET%\*.lib" 2>nul

rem ---- verify: run the in-process end-to-end test for BOTH bitnesses -------
rem  Exit codes: 0 = all checks passed, 2 = some check failed, 1 = usage/load error.
echo.
echo ============================================================
echo   running end-to-end verification
echo ============================================================
echo.

echo [x64] TestTextHook
"%OUT%\TestTextHook-x64.exe" "%OUT%\TextHookDll-x64.dll" "%OUT%\TextHookDll.profiles.ini"
if errorlevel 1 goto :testfail

echo.
echo [x86] TestTextHook
"%OUT%\TestTextHook-x86.exe" "%OUT%\TextHookDll-x86.dll" "%OUT%\TextHookDll.profiles.ini"
if errorlevel 1 goto :testfail

echo.
echo ============================================================
echo   BUILD OK + VERIFY OK (x64 and x86)
echo.
rem  NOTE: no "^" line continuations in the echo block below. A caret at the
rem  end of an echo line escapes the newline, so the *next* line's literal
rem  text -- including the word "echo" -- gets appended to the output. The
rem  long command is therefore split into separate echo lines instead.
echo   Manual run against a real game (optional, both processes):
echo.
echo     1) test_output\TextHookClient.exe
echo.
echo     2) DllInjector-x64.exe -inject test_output\TextTarget_x64.exe
echo            test_output\TextHookDll-x64.dll -export InstallConfig
echo            -exportarg "engine=generic-gdi|cp=932|log=1"
echo.
echo   NOTE: cp= is process-wide, and one process can only carry ONE *A
echo         encoding. The test target therefore defaults to Shift-JIS;
echo         for a GBK run start it as "TextTarget_x64.exe gbk" and pass
echo         cp=936. Mismatching them makes the *A text garbled by design.
echo.
echo   Engine profiles: edit test_output\TextHookDll.profiles.ini
echo         (loaded from the DLL's own directory; no rebuild needed).
echo         The startup banner in texthook_log.txt reports which file was
echo         read and which profiles were loaded.
echo ============================================================
endlocal
exit /b 0

:testfail
echo.
echo ============================================================
echo   VERIFY_FAIL - see the FAIL lines above
echo ============================================================
endlocal
exit /b 1

:fail
echo BUILD_FAIL
endlocal
exit /b 1
