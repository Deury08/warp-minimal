# Firewall permissions for warp-minimal (run as Administrator)
# Allows the WARP WireGuard UDP traffic and the local listener both ways.

$ErrorActionPreference = "Stop"

# Elevate automatically if not running as admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath)
    exit
}

$exe = Join-Path $PSScriptRoot "warp-minimal-test.exe"
if (-not (Test-Path $exe)) { $exe = Join-Path $PSScriptRoot "warp-minimal.exe" }
if (-not (Test-Path $exe)) {
    Write-Host "No warp-minimal executable found in $PSScriptRoot" -ForegroundColor Red
    pause
    exit 1
}

$name = "warp-minimal UDP"

# Remove old rules so re-running is safe
Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule

New-NetFirewallRule -DisplayName $name `
    -Description "Allow Cloudflare WARP WireGuard traffic for warp-minimal" `
    -Direction Outbound -Action Allow -Program $exe -Protocol UDP | Out-Null

New-NetFirewallRule -DisplayName $name `
    -Description "Allow Cloudflare WARP WireGuard traffic for warp-minimal" `
    -Direction Inbound -Action Allow -Program $exe -Protocol UDP | Out-Null

# The local HTTP/HTTPS proxy listener (config.json listen port) is TCP, so
# Windows does not prompt for it, but we allow it explicitly to be safe.
New-NetFirewallRule -DisplayName "$name TCP" `
    -Description "Allow warp-minimal local proxy listener" `
    -Direction Inbound -Action Allow -Program $exe -Protocol TCP -LocalPort 8789 | Out-Null

Write-Host ""
Write-Host "Firewall rules created for: $exe" -ForegroundColor Green
Write-Host "  - UDP Outbound (WARP tunnel to Cloudflare :2408)"
Write-Host "  - UDP Inbound (WARP tunnel replies)"
Write-Host "  - TCP Inbound on 8789 (local proxy listener)"
Write-Host ""
Write-Host "Done. Press any key to close..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
