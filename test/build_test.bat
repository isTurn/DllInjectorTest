@echo off
rem ============================================================================
rem  Build the test material (test DLLs + test target) with MSVC.
rem
rem  Output: ..\test_output\
rem    TestDllA_x64.dll / TestDllB_x64.dll   TestDllA_x86.dll / TestDllB_x86.dll
rem    Target_x64.exe   / Target_x86.exe
rem
rem  Notes:
rem    - Paths are derived from this script's own location, so the repository
rem      can live anywhere.
rem    - The Visual Studio installation is located with vswhere.exe, so any
rem      edition (Community / Professional / Enterprise) and any install path
rem      works, as long as the C++ build tools are installed.
rem    - Messages are ASCII-only on purpose: cmd.exe reads .bat files using the
rem      console code page, so non-ASCII text would be garbled.
rem ============================================================================

setlocal
set "SRC=%~dp0"
set "OUT=%~dp0..\test_output"

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
echo [INFO] output        : %OUT%
echo.

if not exist "%OUT%" md "%OUT%"

rem ---- x64 -----------------------------------------------------------------
call "%VC%\vcvars64.bat" >nul
cl /nologo /utf-8 /LD /O2 /DMARKER_PREFIX=\"attachA\" "%SRC%TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllA_x64.dll"
if errorlevel 1 goto :fail
cl /nologo /utf-8 /LD /O2 /DMARKER_PREFIX=\"attachB\" "%SRC%TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllB_x64.dll"
if errorlevel 1 goto :fail
cl /nologo /utf-8 /O2 "%SRC%TestTarget\TestTarget.c" /link /OUT:"%OUT%\Target_x64.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

rem ---- x86 -----------------------------------------------------------------
call "%VC%\vcvars32.bat" >nul
cl /nologo /utf-8 /LD /O2 /DMARKER_PREFIX=\"attachA\" "%SRC%TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllA_x86.dll"
if errorlevel 1 goto :fail
cl /nologo /utf-8 /LD /O2 /DMARKER_PREFIX=\"attachB\" "%SRC%TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllB_x86.dll"
if errorlevel 1 goto :fail
cl /nologo /utf-8 /O2 "%SRC%TestTarget\TestTarget.c" /link /OUT:"%OUT%\Target_x86.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

rem ---- clean intermediates left next to the sources ------------------------
del /q "%SRC%TestDll\*.obj" "%SRC%TestDll\*.exp" "%SRC%TestDll\*.lib" 2>nul
del /q "%SRC%TestTarget\*.obj" "%SRC%TestTarget\*.exp" "%SRC%TestTarget\*.lib" 2>nul

echo BUILD_DONE
endlocal
exit /b 0

:fail
echo BUILD_FAIL
endlocal
exit /b 1
