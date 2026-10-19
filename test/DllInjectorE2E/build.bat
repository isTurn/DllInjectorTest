@echo off
rem ---------------------------------------------------------------------------
rem  DllInjector end-to-end tests (C# side).
rem
rem  Unlike DllInjectorTests (which only exercises pure logic), this one really
rem  creates processes, injects DLLs, calls exports and ejects again. It covers
rem  all five injection methods, so a broken code path can no longer hide behind
rem  a green "logic tests" run.
rem
rem  Prerequisites (all produced by the native build scripts):
rem    test_output\Target_<bits>.exe
rem    test_output\TestHookDll-<bits>.dll
rem    test_output\TestReflectiveDll-<bits>.dll
rem  Run test\build_test.bat, test\TestHookDll\build.bat and
rem  test\TestReflectiveDll\build.bat first.
rem
rem  Usage:
rem    build.bat          - build and run as x64 (the default)
rem    build.bat --x86    - build and run as x86
rem  The test host must match the bitness of the target process, so the
rem  architecture is a build-time choice, not a runtime one.
rem
rem  Exit code: 0 = all passed, 1 = build failed / prerequisites missing /
rem  an assertion failed. (CI uses the exit code directly.)
rem
rem  NOTE: keep this file ASCII-only. cmd.exe renders it in the OEM code page,
rem  so UTF-8 text here would show up as mojibake.
rem ---------------------------------------------------------------------------
setlocal

set "SRC=%~dp0"
rem Trailing backslash on purpose: it is concatenated with bare file names
rem below, and %~dp0..\.. expands to a path that ends WITHOUT one.
set "OUT=%~dp0..\..\test_output\"
set "PREREQ_HINT=Run test\build_test.bat, test\TestHookDll\build.bat and test\TestReflectiveDll\build.bat first."
set "PLAT=x64"
set "BITS=x64"

rem Args are matched with /i so "--X86" also works. Anything else is ignored
rem on purpose: a typo must not silently fall back to the x64 run.
if /i "%~1"=="--x86" (
    set "PLAT=x86"
    set "BITS=x86"
)

rem dotnet resolves relative paths (and the project's Link/Include globs)
rem against the current directory, so run from here regardless of where the
rem caller stands.
cd /d "%SRC%"

echo [INFO] bitness: %BITS%

rem Fail fast with an actionable message instead of letting the test print a
rem dozen confusing failures after the first missing file.
if not exist "%OUT%Target_%BITS%.exe" (
    echo MISSING_PREREQ: %OUT%Target_%BITS%.exe not found.
    echo %PREREQ_HINT%
    exit /b 1
)
if not exist "%OUT%TestHookDll-%BITS%.dll" (
    echo MISSING_PREREQ: %OUT%TestHookDll-%BITS%.dll not found.
    echo %PREREQ_HINT%
    exit /b 1
)
if not exist "%OUT%TestReflectiveDll-%BITS%.dll" (
    echo MISSING_PREREQ: %OUT%TestReflectiveDll-%BITS%.dll not found.
    echo %PREREQ_HINT%
    exit /b 1
)

rem The output directory is per-bitness on purpose. dotnet's incremental build
rem keys off the source files, not off -p:PlatformTarget, so building x64 and
rem then x86 into the SAME bin\ dir silently reuses the x64 assembly: the run
rem then tests 64-bit binaries while claiming to test 32-bit ones. Separate
rem output (plus -t:Rebuild) makes that impossible.
set "OUTDIR=%SRC%bin\%PLAT%\"

echo [INFO] building DllInjectorE2E (%PLAT%) ...
dotnet build "%SRC%DllInjectorE2E.csproj" -c Debug -v q --nologo -t:Rebuild -p:PlatformTarget=%PLAT% -p:OutputPath="%OUTDIR%"
if errorlevel 1 (
    echo BUILD_FAIL
    exit /b 1
)

echo.
echo [INFO] running DllInjectorE2E ...
"%OUTDIR%DllInjectorE2E.exe"
if errorlevel 1 (
    echo E2E_FAIL
    exit /b 1
)

echo.
echo BUILD OK + E2E OK
exit /b 0
