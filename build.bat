@echo off
REM ===========================================================================
REM  KeyMouseLock build script
REM  Uses the built-in csc.exe (.NET Framework 4.x). No SDK required.
REM  Produces a single KeyMouseLock.exe.
REM ===========================================================================
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "OUT=%ROOT%KeyMouseLock.exe"
set "SRC=%ROOT%LockScreen.cs"

set "CSC="
if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if not defined CSC (
  echo [ERROR] csc.exe not found. Please ensure .NET Framework 4.x is installed.
  exit /b 1
)

echo Compiler: !CSC!
echo Building...

"!CSC!" /nologo /target:winexe /optimize+ /out:"%OUT%" /reference:System.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll "%SRC%"

if errorlevel 1 (
  echo.
  echo [FAILED] Compilation did not succeed.
  exit /b 1
)

echo.
echo [DONE] Generated KeyMouseLock.exe
echo Tip: keep config.json next to the exe.
endlocal
