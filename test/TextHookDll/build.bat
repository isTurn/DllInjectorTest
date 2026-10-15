@echo off
rem ============================================================================
rem  Build the text-hook material (hook DLL + pipe client + test target).
rem
rem  Output: ..\..\test_output\
rem    TextHookDll-x64.dll / TextHookDll-x86.dll   the hook DLL (both bitnesses)
rem    TextHookClient.exe                          named-pipe consumer (x64)
rem    TextTarget_x64.exe / TextTarget_x86.exe     GDI text target for testing
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
rem    - TestTextTarget calls GDI/user32 but has no #pragma comment(lib), so
rem      gdi32.lib / user32.lib must be named explicitly on the link line.
rem    - TextHookDll.def is passed to the linker so the exports keep their
rem      undecorated names on x86 too. Without it, WINAPI (=__stdcall) would
rem      export them as _InstallConfig@4 on x86 but as InstallConfig on x64,
rem      so GetProcAddress(h, "InstallConfig") would return NULL on x86.
rem ============================================================================

setlocal
set "SRC=%~dp0"
set "OUT=%~dp0..\..\test_output"
set "TARGET=%~dp0..\TestTextTarget"

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

rem ---- x64 -----------------------------------------------------------------
call "%VC%\vcvars64.bat" >nul

cl /nologo /LD /O2 /utf-8 "%SRC%TextHookDll.c" /link /DEF:"%SRC%TextHookDll.def" /OUT:"%OUT%\TextHookDll-x64.dll"
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%SRC%TextHookClient.c" /link /OUT:"%OUT%\TextHookClient.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%TARGET%\TestTextTarget.c" /link /OUT:"%OUT%\TextTarget_x64.exe" /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
if errorlevel 1 goto :fail

rem ---- x86 -----------------------------------------------------------------
call "%VC%\vcvars32.bat" >nul

cl /nologo /LD /O2 /utf-8 "%SRC%TextHookDll.c" /link /DEF:"%SRC%TextHookDll.def" /OUT:"%OUT%\TextHookDll-x86.dll"
if errorlevel 1 goto :fail

cl /nologo /O2 /utf-8 "%TARGET%\TestTextTarget.c" /link /OUT:"%OUT%\TextTarget_x86.exe" /SUBSYSTEM:CONSOLE gdi32.lib user32.lib
if errorlevel 1 goto :fail

rem ---- clean intermediates left next to the sources ------------------------
del /q "%SRC%*.obj" "%SRC%*.exp" "%SRC%*.lib" 2>nul
del /q "%TARGET%\*.obj" "%TARGET%\*.exp" "%TARGET%\*.lib" 2>nul

echo.
echo ============================================================
echo   BUILD OK
echo.
echo   Verify end-to-end (run each in its own console):
echo.
echo     1^) test_output\TextHookClient.exe
echo.
echo     2^) DllInjector-x64.exe -inject test_output\TextTarget_x64.exe ^
echo            test_output\TextHookDll-x64.dll -export InstallConfig ^
echo            -exportarg "engine=generic-gdi|cp=932|log=1"
echo.
echo   NOTE: cp= is process-wide, and one process can only carry ONE *A
echo         encoding. The test target therefore defaults to Shift-JIS;
echo         for a GBK run start it as "TextTarget_x64.exe gbk" and pass
echo         cp=936. Mismatching them makes the *A text garbled by design.
echo.
echo   Expected: the client prints captured text, and
echo             test_output\texthook_log.txt gets a copy.
echo ============================================================
endlocal
exit /b 0

:fail
echo BUILD_FAIL
endlocal
exit /b 1
