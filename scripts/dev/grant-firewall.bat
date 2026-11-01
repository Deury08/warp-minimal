@echo off
setlocal enabledelayedexpansion
REM Firewall permissions for warp-minimal (self-elevates, then exits)

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Elevating to Administrator...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

REM Cover every warp-minimal executable in this folder
set EXE=%~dp0warp-minimal-test.exe
set EXE2=%~dp0warptest2.exe
set EXE3=%~dp0warp-minimal.exe

REM Clean any previous rules so re-running is safe
netsh advfirewall firewall delete rule name="warp-minimal UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="warp-minimal TCP" >nul 2>&1

REM WARP WireGuard tunnel traffic (UDP to Cloudflare :2408 and replies)
for %%P in ("%EXE%" "%EXE2%" "%EXE3%") do (
  if exist "%%~P" (
    netsh advfirewall firewall add rule name="warp-minimal UDP" dir=out action=allow program="%%~P" protocol=UDP >nul
    if !errorLevel! neq 0 goto :fail
    netsh advfirewall firewall add rule name="warp-minimal UDP" dir=in action=allow program="%%~P" protocol=UDP >nul
    if !errorLevel! neq 0 goto :fail
  )
)

REM Local proxy listener on TCP 8789 (config.json listen port)
netsh advfirewall firewall add rule name="warp-minimal TCP" dir=in action=allow program="%EXE%" protocol=TCP localport=8789 >nul
if %errorLevel% neq 0 goto :fail

echo.
echo Firewall rules created for: %EXE%
echo   - UDP Outbound (WARP tunnel to Cloudflare :2408)
echo   - UDP Inbound (WARP tunnel replies)
echo   - TCP Inbound on 8789 (local proxy listener)
echo.
pause
exit /b 0

:fail
echo ERROR: failed to create one of the firewall rules. Run as Administrator.
pause
exit /b 1

:noexe
echo ERROR: no warp-minimal executable found in %~dp0
pause
exit /b 1
