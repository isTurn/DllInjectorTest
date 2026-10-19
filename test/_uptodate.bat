@echo off
rem ============================================================================
rem  Incremental-build helper shared by the test build scripts.
rem
rem  WHY THIS EXISTS
rem    A full regression run used to rebuild every piece of test material from
rem    scratch, including material another script had just produced. Re-running
rem    an unchanged script now costs a hash of its sources instead of a compile.
rem
rem  WHAT IT DOES NOT DO
rem    It does not look at timestamps or mtimes. "dir /o-d" cannot be used for
rem    this: given absolute paths that span directories it drops entries and does
rem    not sort them (measured - 4 inputs, 3 outputs, wrong order), and a
rem    timestamp on its own cannot tell you whether the *compiler flags* changed.
rem    So the stamp is a content fingerprint: the SHA1 of every input, in order.
rem    Edit an input, or add one to the list, and the fingerprint changes.
rem
rem  USAGE
rem    call "%~dp0_uptodate.bat" check  <name> <file> [<file>...]
rem        errorlevel 0 = everything up to date, caller may skip the work
rem        errorlevel 1 = rebuild needed (fingerprint differs, or an input is
rem                       missing / unreadable, or FORCE_REBUILD is set)
rem        On 1, the new fingerprint is parked in <name>.fp.new and only
rem        becomes current once the caller reports success via "commit".
rem        That ordering matters: a build that fails must not leave a stamp
rem        claiming the (missing) products are current.
rem
rem    call "%~dp0_uptodate.bat" commit <name>
rem        Promotes <name>.fp.new to <name>.fp.
rem
rem    Set FORCE_REBUILD=1 in the environment to bypass the check entirely
rem    (the build scripts forward their --force switch to it).
rem
rem  Messages are ASCII-only: cmd.exe reads .bat files with the console code
rem  page, so non-ASCII text would be garbled.
rem ============================================================================

setlocal enabledelayedexpansion

if /i "%~1"=="check"  goto :check
if /i "%~1"=="commit" goto :commit
if /i "%~1"=="have"   goto :have

echo [ERROR] _uptodate.bat: unknown mode "%~1"
endlocal & exit /b 2

rem ----------------------------------------------------------------- have ----
rem  errorlevel 0 = every named file exists, 1 = at least one is missing.
rem  The fingerprint only covers *inputs*; without this check, deleting
rem  test_output would leave a stamp claiming products that no longer exist
rem  are current.
:have
shift
:haveloop
if "%~1"=="" (
    endlocal & exit /b 0
)
if not exist "%~1" (
    endlocal & exit /b 1
)
shift
goto :haveloop

rem ---------------------------------------------------------------- check ----
:check
set "UNAME=%~2"
if "%UNAME%"=="" (
    echo [ERROR] _uptodate.bat check: missing stamp name
    endlocal & exit /b 2
)

set "STAMPDIR=%~dp0..\test_output\.stamps"
set "STAMP=%STAMPDIR%\%UNAME%.fp"

if defined FORCE_REBUILD (
    echo [REBUILD] %UNAME%: FORCE_REBUILD is set
    endlocal & exit /b 1
)

if not exist "%STAMPDIR%" md "%STAMPDIR%" >nul 2>&1

rem Concatenate one SHA1 per input. No second hash pass: the concatenation is
rem already a unique key per input list, and it keeps this to one certutil call
rem per file instead of two.
set "ACC="
set "N=0"
shift
shift
:checkloop
if "%~1"=="" goto :checkcompare
set "UH="
call :hash "%~1" UH
if not defined UH (
    echo [REBUILD] %UNAME%: cannot hash "%~1"
    endlocal & exit /b 1
)
set "ACC=!ACC!%UH%"
set /a N+=1
shift
goto :checkloop

:checkcompare
if "%N%"=="0" (
    echo [ERROR] _uptodate.bat check: no input files given for %UNAME%
    endlocal & exit /b 2
)

set "OLD="
if exist "%STAMP%" set /p OLD=<"%STAMP%"

if "!ACC!"=="!OLD!" (
    endlocal & exit /b 0
)

rem Park the new value; "commit" promotes it after the build succeeds.
<nul set /p "=!ACC!">"%STAMP%.new"
endlocal & exit /b 1

rem --------------------------------------------------------------- commit ----
:commit
set "UNAME=%~2"
if "%UNAME%"=="" (
    echo [ERROR] _uptodate.bat commit: missing stamp name
    endlocal & exit /b 2
)
set "STAMPDIR=%~dp0..\test_output\.stamps"
if exist "%STAMPDIR%\%UNAME%.fp.new" (
    move /y "%STAMPDIR%\%UNAME%.fp.new" "%STAMPDIR%\%UNAME%.fp" >nul
)
endlocal & exit /b 0

rem ----------------------------------------------------------- :hash --------
rem  Sets %2 to the SHA1 of the file named by %1, or leaves it undefined when
rem  the file is missing. certutil prints a localised error message to stdout in
rem  that case, so the result is validated instead of trusted: it must be exactly
rem  40 hex characters. Without that check a failed hash would be stored as a
rem  timestamp and the next run would think everything was current.
:hash
set "%~2="
set "FPH="
for /f "skip=1 delims=" %%H in ('certutil -hashfile "%~1" SHA1 2^>nul') do (
    if not defined FPH set "FPH=%%H"
)
if not defined FPH goto :eof
echo !FPH!| "%SystemRoot%\System32\findstr.exe" /r /x /i /c:"[0-9a-f][0-9a-f]*" >nul || goto :eof
if not "!FPH:~39,1!"=="" if "!FPH:~40,1!"=="" set "%~2=!FPH!"
goto :eof
