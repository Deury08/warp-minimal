@echo off
REM Test the WARP tunnel with the Windows firewall temporarily OFF.
REM Saves the firewall state, disables it, runs the tunnel probe,
REM reports, and re-enables the firewall automatically.

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo [1/4] Saving current firewall state...
netsh advfirewall show allprofiles state | findstr /i "State Estado ON OFF" > "%~dp0firewall-state-before.txt"
type "%~dp0firewall-state-before.txt"

echo [2/4] Disabling ALL firewall profiles (temporary)...
netsh advfirewall set allprofiles state off
if %errorLevel% neq 0 goto :fail

echo [3/4] Starting WARP tunnel and probing handshake (50 seconds)...
start /b "" "%~dp0warptest2.exe"
timeout /t 50 /nobreak >nul

echo [4/4] Re-enabling the firewall...
netsh advfirewall set allprofiles state on

echo WARP results (look for handshake response):
type "%~dp0warptest2.out"
echo.
echo Done. Firewall is back ON. Press any key...
pause
exit /b 0

:fail
echo ERROR: could not disable firewall. Nothing was changed beyond state reading.
pause
exit /b 1
