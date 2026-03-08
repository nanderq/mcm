param(
    [string]$Username = "admin",
    [string]$Password = "change-me-now",
    [string]$CookieSecure = "false",
    [switch]$SkipStart
)

$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot

$env:MCM_AUTH_USERNAME = $Username
$env:MCM_AUTH_PASSWORD_HASH = (uv run hash-password $Password).Trim()
$env:MCM_SESSION_SECRET = (uv run python -c "import secrets; print(secrets.token_urlsafe(32))").Trim()
$env:MCM_COOKIE_SECURE = $CookieSecure

Write-Host "Configured auth environment variables for this shell:"
Write-Host "  MCM_AUTH_USERNAME=$env:MCM_AUTH_USERNAME"
Write-Host "  MCM_COOKIE_SECURE=$env:MCM_COOKIE_SECURE"
Write-Host "  MCM_SESSION_SECRET=<generated>"
Write-Host "  MCM_AUTH_PASSWORD_HASH=<generated>"

if ($SkipStart) {
    return
}

Push-Location $projectRoot
try {
    uv run start
}
finally {
    Pop-Location
}
