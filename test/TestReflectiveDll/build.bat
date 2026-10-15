@echo off
rem ============================================================================
rem  Build the reflective DLL test material (self-contained ReflectiveLoader).
rem
rem  Output (next to the sources):
rem    TestReflectiveDll-x64.dll
rem    TestReflectiveDll-x86.dll
rem    TestLoader-x64.exe          (in-process validator for the x64 DLL)
rem    TestLoader-x86.exe          (in-process validator for the x86 DLL)
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
set "OUT=%SRC%"

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
echo.

rem ---- x64 -----------------------------------------------------------------
call "%VC%\vcvars64.bat" >nul
ml64 /nologo /c "%SRC%ReflectiveLoader_x64.asm" || goto :fail
cl /nologo /utf-8 /LD /O2 "%SRC%TestReflectiveDll.c" "%SRC%ReflectiveLoader_x64.obj" /link /OUT:"%OUT%TestReflectiveDll-x64.dll" /DEF:"%SRC%Reflective.def"
if errorlevel 1 goto :fail
cl /nologo /utf-8 /O2 "%SRC%TestLoader.c" /link /OUT:"%OUT%TestLoader-x64.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

rem ---- x86 -----------------------------------------------------------------
call "%VC%\vcvars32.bat" >nul
ml /nologo /c "%SRC%ReflectiveLoader_x86.asm" || goto :fail
cl /nologo /utf-8 /LD /O2 "%SRC%TestReflectiveDll.c" "%SRC%ReflectiveLoader_x86.obj" /link /OUT:"%OUT%TestReflectiveDll-x86.dll" /DEF:"%SRC%Reflective.def"
if errorlevel 1 goto :fail
cl /nologo /utf-8 /O2 "%SRC%TestLoader.c" /link /OUT:"%OUT%TestLoader-x86.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

rem ---- clean intermediates -------------------------------------------------
del /q "%SRC%*.obj" "%SRC%*.exp" "%SRC%*.lib" 2>nul

echo BUILD_DONE
echo.
echo  Validate in-process (writes C:\Windows\Temp\rfi_call_log.txt on success):
echo    %OUT%TestLoader-x64.exe
echo    %OUT%TestLoader-x86.exe
endlocal
exit /b 0

:fail
echo BUILD_FAIL
endlocal
exit /b 1
