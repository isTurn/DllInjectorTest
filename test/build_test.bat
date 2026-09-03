@echo off
set VC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build
set SRC=D:\Download\ToDLL\test
set OUT=D:\Download\ToDLL\test_output

call "%VC%\vcvars64.bat" >nul
cl /nologo /LD /O2 /DMARKER_PREFIX=\"attachA\" "%SRC%\TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllA_x64.dll"
if errorlevel 1 goto :fail
cl /nologo /LD /O2 /DMARKER_PREFIX=\"attachB\" "%SRC%\TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllB_x64.dll"
if errorlevel 1 goto :fail
cl /nologo /O2 "%SRC%\TestTarget\TestTarget.c" /link /OUT:"%OUT%\Target_x64.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

call "%VC%\vcvars32.bat" >nul
cl /nologo /LD /O2 /DMARKER_PREFIX=\"attachA\" "%SRC%\TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllA_x86.dll"
if errorlevel 1 goto :fail
cl /nologo /LD /O2 /DMARKER_PREFIX=\"attachB\" "%SRC%\TestDll\TestDll.c" /link /OUT:"%OUT%\TestDllB_x86.dll"
if errorlevel 1 goto :fail
cl /nologo /O2 "%SRC%\TestTarget\TestTarget.c" /link /OUT:"%OUT%\Target_x86.exe" /SUBSYSTEM:CONSOLE
if errorlevel 1 goto :fail

echo BUILD_DONE
exit /b 0
:fail
echo BUILD_FAIL
exit /b 1
