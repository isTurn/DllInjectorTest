@echo off
set VC=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build
set SRC=D:\Download\ToDLL\test\TestReflectiveDll
set OUT=%SRC%

call "%VC%\vcvars64.bat" >nul
ml64 /nologo /c "%SRC%\ReflectiveLoader_x64.asm" || goto :fail
cl /nologo /LD /O2 "%SRC%\TestReflectiveDll.c" "%SRC%\ReflectiveLoader_x64.obj" /link /OUT:"%OUT%\TestReflectiveDll-x64.dll" /DEF:"%SRC%\Reflective.def"
if errorlevel 1 goto :fail

call "%VC%\vcvars32.bat" >nul
ml /nologo /c "%SRC%\ReflectiveLoader_x86.asm" || goto :fail
cl /nologo /LD /O2 "%SRC%\TestReflectiveDll.c" "%SRC%\ReflectiveLoader_x86.obj" /link /OUT:"%OUT%\TestReflectiveDll-x86.dll" /DEF:"%SRC%\Reflective.def"
if errorlevel 1 goto :fail

del /q "%SRC%\*.obj" "%SRC%\*.exp" "%SRC%\*.lib" 2>nul
echo BUILD_DONE
exit /b 0
:fail
echo BUILD_FAIL
exit /b 1
