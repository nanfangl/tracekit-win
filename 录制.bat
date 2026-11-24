@echo off
chcp 65001 >nul
setlocal
set "HERE=%~dp0"
set "PYEXE="

where python >nul 2>nul && set "PYEXE=python"
if not defined PYEXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYEXE if exist "%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe" set "PYEXE=%USERPROFILE%\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\python.exe"

if not defined PYEXE (
  echo [x] 没找到 python，请安装 Python 3.9+ 或把 python.exe 加进 PATH
  pause
  exit /b 1
)
if "%~1"=="" (
  echo 用法:
  echo   录制.bat "C:\目标软件\app.exe"
  echo   录制.bat "C:\目标软件\app.exe" --watch-dir "C:\目标软件\data" --shot-interval 30
  echo   录制.bat "C:\目标软件\app.exe" --no-input --no-ui
  pause
  exit /b 1
)

cd /d "%HERE%"
echo [i] 解释器: %PYEXE%
echo [i] 目标:   %~1
echo.
"%PYEXE%" -m tracekit run --name "%~n1" %2 %3 %4 %5 %6 %7 %8 %9 -- "%~1"
echo.
echo [i] 结果在 %HERE%runs\ 下（report.md / timeline.html / events.sqlite）
pause
