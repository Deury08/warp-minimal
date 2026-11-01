@echo off
REM Re-enable the Windows firewall immediately (restore after any test).

net session >nul 2>&1
if %errorLevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

netsh advfirewall set allprofiles state on
echo Firewall re-enabled on all profiles. Press any key...
pause
