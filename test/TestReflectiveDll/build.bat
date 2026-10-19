@echo off
rem ============================================================================
rem  Build the reflective DLL test material (self-contained ReflectiveLoader).
rem
rem  Output (default: test_output\, NOT next to the sources):
rem    TestReflectiveDll-x64.dll
rem    TestReflectiveDll-x86.dll
rem    TestLoader-x64.exe          (in-process validator for the x64 DLL)
rem    TestLoader-x86.exe          (in-process validator for the x86 DLL)
rem
rem  Why test_output\ instead of the source directory: the two DLLs are
rem  committed to the repository, so writing them in place made every build
rem  dirty the working tree with binary diffs that carry no source change --
rem  just a fresh PE timestamp. Regression runs then needed a
rem  "git checkout -- test/TestReflectiveDll/*.dll" afterwards.
rem
rem  TestLoader resolves its default DLL path from its own directory, so keeping
rem  both in test_output\ preserves that sibling relationship.
rem
rem  To deliberately refresh the committed DLLs (only a maintainer shipping a
rem  new sample build needs this), pass --update-shipped:
rem
rem    test\TestReflectiveDll\build.bat --update-shipped
rem
rem  Notes:
rem    - Paths are derived from this script's own location, so the repository
rem      can live anywhere.
rem    - /Brepro makes the output byte-identical across rebuilds with the same
rem      toolchain (it zeroes the PE timestamp and the PDB path). Without it,
rem      two consecutive builds of the same source differ, so "did the shipped
rem      binary actually change?" cannot be answered from a diff.
rem    - The Visual Studio installation is located with vswhere.exe, so any
rem      edition (Community / Professional / Enterprise) and any install path
rem      works, as long as the C++ build tools are installed.
rem    - Messages are ASCII-only on purpose: cmd.exe reads .bat files using the
rem      console code page, so non-ASCII text would be garbled.
rem ============================================================================

setlocal
set "SRC=%~dp0"
set "OUT=%~dp0..\..\test_output"

rem Where the DLLs land. Default is the scratch output directory; the committed
rem copies under the source tree are only rewritten on request.
set "DLLOUT=%OUT%\"
if /i "%~1"=="--update-shipped" set "DLLOUT=%SRC%"

rem cl / ml write .obj next to the SOURCE file, not next to the script, but
rem the linker resolves the /link /OUT: paths and the .obj argument relative to
rem the CURRENT directory. Without this cd, invoking the script from anywhere
rem else (the repo root, or CI) makes ml64 drop the .obj in that other
rem directory while the link step looks for it here -> LNK1181.
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
echo [INFO] output        : %DLLOUT%
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

call "%~dp0..\_uptodate.bat" have "%DLLOUT%TestReflectiveDll-x64.dll" "%DLLOUT%TestReflectiveDll-x86.dll" "%OUT%\TestLoader-x64.exe" "%OUT%\TestLoader-x86.exe"
if errorlevel 1 goto :build

call "%~dp0..\_uptodate.bat" check test-reflective-dll "%SRC%TestReflectiveDll.c" "%SRC%Reflective.def" "%SRC%TestLoader.c" "%SRC%ReflectiveLoader_x64.asm" "%SRC%ReflectiveLoader_x86.asm" "%~f0" "%~dp0..\_uptodate.bat"
if errorlevel 1 goto :build

echo [SKIP] %~nx0: inputs unchanged and products present - nothing to do.
echo         Pass --force to rebuild anyway.
echo BUILD_DONE
endlocal
exit /b 0

:build

rem ---- x64 -----------------------------------------------------------------
call "%VC%\vcvars64.bat" >nul
ml64 /nologo /c "%SRC%ReflectiveLoader_x64.asm" || goto :fail
cl /nologo /Brepro /utf-8 /LD /O2 "%SRC%TestReflectiveDll.c" "%SRC%ReflectiveLoader_x64.obj" /link /Brepro /OUT:"%DLLOUT%TestReflectiveDll-x64.dll" /DEF:"%SRC%Reflective.def"
if errorlevel 1 goto :fail
cl /nologo /Brepro /utf-8 /O2 "%SRC%TestLoader.c" /link /Brepro /OUT:"%OUT%\TestLoader-x64.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

rem ---- x86 -----------------------------------------------------------------
call "%VC%\vcvars32.bat" >nul
ml /nologo /c "%SRC%ReflectiveLoader_x86.asm" || goto :fail
cl /nologo /Brepro /utf-8 /LD /O2 "%SRC%TestReflectiveDll.c" "%SRC%ReflectiveLoader_x86.obj" /link /Brepro /OUT:"%DLLOUT%TestReflectiveDll-x86.dll" /DEF:"%SRC%Reflective.def"
if errorlevel 1 goto :fail
cl /nologo /Brepro /utf-8 /O2 "%SRC%TestLoader.c" /link /Brepro /OUT:"%OUT%\TestLoader-x86.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

rem ---- clean intermediates -------------------------------------------------
del /q "%SRC%*.obj" "%SRC%*.exp" "%SRC%*.lib" 2>nul

echo BUILD_DONE
echo.
echo  Output: %DLLOUT%
echo  Validate in-process (writes C:\Windows\Temp\rfi_call_log.txt on success):
echo    "%OUT%\TestLoader-x64.exe"
echo    "%OUT%\TestLoader-x86.exe"
echo.
echo  To refresh the copies committed under test\TestReflectiveDll\, rerun with
echo    test\TestReflectiveDll\build.bat --update-shipped

rem Only now, after every check above passed, is the new fingerprint promoted.
call "%~dp0..\_uptodate.bat" commit test-reflective-dll
endlocal
exit /b 0

:fail
echo BUILD_FAIL
endlocal
exit /b 1
