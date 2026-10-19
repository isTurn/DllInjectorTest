@echo off
rem ============================================================================
rem  Build the Manual Map / Unmap shellcode and regenerate the C# byte arrays.
rem
rem  Pipeline (see the "manual map" section of README.md for the design):
rem    1. ml64 / ml assembles ManualMap_x64.asm / ManualMap_x86.asm
rem                            UnmapDll_x64.asm  / UnmapDll_x86.asm   -> .obj
rem    2. gen_shellcode.py extracts the .text machine code from each .obj
rem       and writes it as a C# byte[] literal:
rem         shellcode_x64.cs  ->  ManualMapX64   (in DllInjector\Program.cs)
rem         shellcode_x86.cs  ->  ManualMapX86
rem         unmap_x64.cs      ->  UnmapDllX64
rem         unmap_x86.cs      ->  UnmapDllX86
rem    3. The generated arrays are patched straight into DllInjector\Program.cs
rem       (gen_shellcode.py --apply) -- no manual copy-paste step.
rem
rem  Usage: build_shellcode.bat            (rebuild all four, patch Program.cs)
rem         build_shellcode.bat ManualMap_x64 UnmapDll_x86   (selected only)
rem         build_shellcode.bat --check    (verify only: no rebuild, no writes)
rem
rem  Notes:
rem    - Paths are derived from this script's own location.
rem    - Visual Studio is located with vswhere.exe (any edition).
rem    - Messages are ASCII-only on purpose: cmd.exe reads .bat files using the
rem      console code page, so non-ASCII text would be garbled.
rem ============================================================================

setlocal
set "SRC=%~dp0"
cd /d "%SRC%"

rem ---- --check: pure comparison, needs neither VS nor Python --------------
if /i "%~1"=="--check" (
    where python >nul 2>nul || (
        echo [ERROR] Python 3 not found - --check needs gen_shellcode.py.
        exit /b 1
    )
    python gen_shellcode.py --check
    if errorlevel 1 exit /b 1
    endlocal
    exit /b 0
)

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

rem ---- Locate Python (gen_shellcode.py) ------------------------------------
rem Prefer the "python" executable on PATH; fall back to the Windows "py"
rem launcher (installed by the official Python installer even when the
rem "Add python.exe to PATH" option was left unchecked).
set "PY="
where python >nul 2>nul
if not errorlevel 1 set "PY=python"
if not defined PY (
    where py >nul 2>nul
    if not errorlevel 1 set "PY=py -3"
)
if not defined PY (
    rem Parens inside a ( ... ) block must be escaped: cmd closes the block at
    rem the first unescaped ")", so a bare ")" in an echo would truncate it and
    rem leave a stray ")." for the parser. This bites even when the condition is
    rem false - cmd parses the whole block before deciding whether to run it.
    echo [ERROR] Python 3 not found ^(neither "python" nor the "py" launcher^).
    echo         gen_shellcode.py needs Python 3: https://www.python.org/downloads/
    echo         Tip: tick "Add python.exe to PATH" during installation.
    exit /b 1
)
echo [INFO] python       : %PY%

echo [INFO] Visual Studio: %VSPATH%
echo [INFO] work dir     : %SRC%
echo.

rem ---- 1. assemble ---------------------------------------------------------
call "%VC%\vcvars64.bat" >nul
ml64 /nologo /c ManualMap_x64.asm || goto :fail
ml64 /nologo /c UnmapDll_x64.asm  || goto :fail

call "%VC%\vcvars32.bat" >nul
ml /nologo /c ManualMap_x86.asm || goto :fail
ml /nologo /c UnmapDll_x86.asm  || goto :fail

echo.
echo [INFO] Assembly OK. Extracting shellcode bytes...
echo.

rem ---- 2. extract + patch Program.cs ---------------------------------------
rem --apply rewrites the four byte[] initialisers in DllInjector\Program.cs
rem directly. If an array cannot be located the script exits non-zero, so a
rem renamed/moved array fails loudly instead of silently leaving stale bytes.
python gen_shellcode.py --apply %*
if errorlevel 1 goto :fail

echo.
echo ============================================================
echo   Generated .cs files: shellcode_x64.cs / shellcode_x86.cs
echo                        unmap_x64.cs     / unmap_x86.cs
echo.
echo   DllInjector\Program.cs has been patched automatically.
echo   Keep the reported byte counts in sync with README/CHANGELOG.
echo ============================================================
endlocal
exit /b 0

:fail
echo BUILD_FAIL
endlocal
exit /b 1
