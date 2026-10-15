@echo off
rem ============================================================================
rem  DLL Injector - one-click build script (x64 + x86)
rem
rem  Requirements: .NET 8 SDK  (https://dotnet.microsoft.com/download)
rem
rem  Output:
rem    out\x64\DllInjector.exe   64-bit injector
rem    out\x86\DllInjector.exe   32-bit injector
rem    dist\DllInjector-x64.exe  release-named copy of the x64 build
rem    dist\DllInjector-x86.exe  release-named copy of the x86 build
rem
rem  Notes:
rem    - The publish parameters below are kept in sync with
rem      .github/workflows/build.yml so local and CI builds are identical.
rem    - Messages are ASCII-only on purpose: a .bat file is read by cmd.exe
rem      using the console code page, so non-ASCII text would be garbled.
rem ============================================================================

setlocal
set "ROOT=%~dp0"
set "PROJ=%ROOT%DllInjector\DllInjector.csproj"
set "CONFIG=Release"
set "PUBARGS=-c %CONFIG% --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true"

rem ---- Restore the environment variables NuGet depends on -------------------
rem NuGet 6.x derives its user-level and machine-wide configuration paths from
rem the APPDATA and ProgramFiles environment variables (see
rem NuGet.Common.NuGetEnvironment.GetFolderPath). In a hardened, sandboxed or
rem otherwise stripped shell those variables are missing, and then EVERY
rem restore fails with a message that gives no hint about the real cause:
rem
rem   NuGet.targets(745,5): error : Value cannot be null. (Parameter 'path1')
rem
rem The exception comes from XPlatMachineWideSetting's static constructor, which
rem calls Path.Combine(null, ...) before the project is even looked at. Nothing
rem in the project or in NuGet.Config can avoid it, so re-create the variables
rem defensively when they are absent.
if not defined APPDATA         set "APPDATA=%USERPROFILE%\AppData\Roaming"
if not defined ProgramFiles    set "ProgramFiles=%SystemDrive%\Program Files"
if not defined ProgramW6432    set "ProgramW6432=%SystemDrive%\Program Files"
if not defined ALLUSERSPROFILE set "ALLUSERSPROFILE=%SystemDrive%\ProgramData"

echo ============================================================
echo   DLL Injector - Build
echo ============================================================
echo.

if not exist "%PROJ%" (
    echo [ERROR] Project file not found:
    echo         %PROJ%
    exit /b 1
)

where dotnet >nul 2>nul
if errorlevel 1 (
    echo [ERROR] dotnet SDK not found in PATH.
    echo         Install .NET 8 SDK: https://dotnet.microsoft.com/download
    exit /b 1
)

for /f "delims=" %%v in ('dotnet --version 2^>nul') do set "DOTNET_VER=%%v"
echo [INFO] dotnet SDK : %DOTNET_VER%
echo [INFO] project    : %PROJ%
echo.

set "FAILED=0"

echo [1/4] Cleaning previous output...
if exist "%ROOT%out\x64" rd /s /q "%ROOT%out\x64"
if exist "%ROOT%out\x86" rd /s /q "%ROOT%out\x86"

echo [2/4] Publishing x64 ^(win-x64^)...
dotnet publish "%PROJ%" -r win-x64 %PUBARGS% -o "%ROOT%out\x64"
if errorlevel 1 (
    echo [ERROR] x64 publish failed.
    set "FAILED=1"
    goto :summary
)

echo [3/4] Publishing x86 ^(win-x86^)...
dotnet publish "%PROJ%" -r win-x86 %PUBARGS% -o "%ROOT%out\x86"
if errorlevel 1 (
    echo [ERROR] x86 publish failed.
    set "FAILED=1"
    goto :summary
)

echo [4/4] Creating release-named copies in dist\...
if not exist "%ROOT%dist" md "%ROOT%dist"
copy /y "%ROOT%out\x64\DllInjector.exe" "%ROOT%dist\DllInjector-x64.exe" >nul
if errorlevel 1 ( set "FAILED=1" & goto :summary )
copy /y "%ROOT%out\x86\DllInjector.exe" "%ROOT%dist\DllInjector-x86.exe" >nul
if errorlevel 1 ( set "FAILED=1" & goto :summary )

:summary
echo.
echo ============================================================
if "%FAILED%"=="1" goto :failed
echo   BUILD OK
echo.
echo   out\x64\DllInjector.exe   ^(64-bit^)
echo   out\x86\DllInjector.exe   ^(32-bit^)
echo   dist\DllInjector-x64.exe
echo   dist\DllInjector-x86.exe
echo ============================================================
endlocal
exit /b 0

:failed
echo   BUILD FAILED - see the messages above.
echo ============================================================
endlocal
exit /b 1
