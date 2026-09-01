@echo off
REM Build DllInjector x64 + x86 (self-contained single-file EXEs)
REM Requires .NET 8 SDK: https://dotnet.microsoft.com
setlocal
cd /d %~dp0

echo === Publishing x64 ===
dotnet publish DllInjector\DllInjector.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o out\x64
if errorlevel 1 goto :err

echo === Publishing x86 ===
dotnet publish DllInjector\DllInjector.csproj -c Release -r win-x86 --self-contained true -p:PublishSingleFile=true -o out\x86
if errorlevel 1 goto :err

echo.
echo Done. Output: out\x64\DllInjector.exe (64-bit) and out\x86\DllInjector.exe (32-bit)
goto :eof

:err
echo Build failed.
exit /b 1
endlocal
