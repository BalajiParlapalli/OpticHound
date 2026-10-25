@echo off
setlocal EnableDelayedExpansion

:: 1. Check portable pyruntime
if exist "%~dp0..\pyruntime\python.exe" (
    "%~dp0..\pyruntime\python.exe" "%~dp0optichound.py" %*
    exit /b !ERRORLEVEL!
)

:: 2. Check standard Python launcher 'py'
where py >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    py -3 "%~dp0optichound.py" %*
    exit /b !ERRORLEVEL!
)

:: 3. Check official python.org default user installs (%LOCALAPPDATA%\Programs\Python\Python3*)
for /d %%d in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if exist "%%d\python.exe" (
        "%%d\python.exe" "%~dp0optichound.py" %*
        exit /b !ERRORLEVEL!
    )
)

:: 4. Check Windows Pythoncore installs (%LOCALAPPDATA%\Python\pythoncore-*)
for /d %%d in ("%LOCALAPPDATA%\Python\pythoncore-*") do (
    if exist "%%d\python.exe" (
        "%%d\python.exe" "%~dp0optichound.py" %*
        exit /b !ERRORLEVEL!
    )
)

:: 5. Check System Program Files installs
for /d %%d in ("%ProgramFiles%\Python3*" "C:\Python3*") do (
    if exist "%%d\python.exe" (
        "%%d\python.exe" "%~dp0optichound.py" %*
        exit /b !ERRORLEVEL!
    )
)

if exist "%LOCALAPPDATA%\Python\bin\python.exe" (
    "%LOCALAPPDATA%\Python\bin\python.exe" "%~dp0optichound.py" %*
    exit /b !ERRORLEVEL!
)

:: 6. Fallback to python in PATH
where python >nul 2>&1
if !ERRORLEVEL! EQU 0 (
    python "%~dp0optichound.py" %*
    exit /b !ERRORLEVEL!
)

echo [ERROR] Python 3 was not detected on this machine.
echo Please install Python 3 from https://www.python.org/downloads/
exit /b 1
