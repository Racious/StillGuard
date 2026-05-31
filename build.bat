@echo off
REM ===========================================================================
REM  StillGuard build script
REM  Uses the built-in csc.exe (.NET Framework 4.x). No SDK required.
REM  Produces a single StillGuard.exe.
REM ===========================================================================
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
set "OUT=%ROOT%StillGuard.exe"
set "SRC=%ROOT%LockScreen.cs"

set "CSC="
if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if not defined CSC (
  echo [ERROR] csc.exe not found. Please ensure .NET Framework 4.x is installed.
  exit /b 1
)

REM If icon.ico exists in this folder, embed it as the exe file icon
set "ICONARG="
if exist "%ROOT%icon.ico" set ICONARG=/win32icon:"%ROOT%icon.ico"
if defined ICONARG echo Using icon: %ROOT%icon.ico

echo Compiler: !CSC!
echo Building...

"!CSC!" /nologo /target:winexe /optimize+ /out:"%OUT%" !ICONARG! /reference:System.dll /reference:System.Drawing.dll /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll /reference:System.Security.dll "%SRC%"

if errorlevel 1 (
  echo.
  echo [FAILED] Compilation did not succeed.
  exit /b 1
)

echo.
echo [DONE] Generated StillGuard.exe
echo Tip: keep config.json next to the exe.
endlocal
