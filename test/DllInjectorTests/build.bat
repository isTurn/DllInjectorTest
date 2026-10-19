@echo off
rem ---------------------------------------------------------------------------
rem  DllInjector logic regression tests (C# side).
rem
rem  Unlike the other build.bat files under test\, this one does NOT need
rem  Visual Studio: the code under test is managed, there is no C compile step.
rem  .NET 8 SDK is enough.
rem
rem  Exit code: 0 = all passed, 1 = build failed or an assertion failed.
rem  (CI uses the exit code directly.)
rem
rem  NOTE: keep this file ASCII-only. cmd.exe renders it in the OEM code page,
rem  so UTF-8 text here would show up as mojibake.
rem ---------------------------------------------------------------------------
setlocal

set "SRC=%~dp0"

rem dotnet resolves relative paths (and the project's Link/Include globs)
rem against the current directory, so run from here regardless of where the
rem caller stands.
cd /d "%SRC%"

echo [INFO] building DllInjectorTests ...
dotnet build "%SRC%DllInjectorTests.csproj" -c Debug -v q --nologo
if errorlevel 1 (
    echo BUILD_FAIL
    exit /b 1
)

echo.
echo [INFO] running DllInjectorTests ...
"%SRC%bin\Debug\net8.0-windows\DllInjectorTests.exe"
if errorlevel 1 (
    echo TEST_FAIL
    exit /b 1
)

echo.
echo BUILD OK + TEST OK
exit /b 0
