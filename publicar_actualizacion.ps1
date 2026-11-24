# Publica una actualización de Chat WiFi en GitHub Releases.
#
# Uso normal (solo genera dist\latest.json):
#   .\publicar_actualizacion.ps1
#
# Publicar automáticamente con un token de GitHub:
#   $env:GITHUB_TOKEN = "ghp_..."
#   .\publicar_actualizacion.ps1 -Notes "Corrige reconexión Online"
#
# El token necesita permiso "Contents: Read and write" sobre el repositorio.

param(
    [string]$Version = "",
    [string]$Repo = "Juedorigamer/ChatWifi",
    [string]$Notes = "",
    [switch]$NoUpload
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $Version) {
    $line = Select-String -Path (Join-Path $root "chat.py") -Pattern '^APP_VERSION = "([^"]+)"' |
        Select-Object -First 1
    if (-not $line) { throw "No se pudo leer APP_VERSION de chat.py" }
    $Version = $line.Matches[0].Groups[1].Value
}

$installer = Join-Path $root "dist\ChatWiFi_Setup_$Version.exe"
if (-not (Test-Path $installer)) {
    throw "No existe el instalador: $installer"
}

$tag = "v$Version"
$assetName = "ChatWiFi_Setup_$Version.exe"
$url = "https://github.com/$Repo/releases/download/$tag/$assetName"
$sha = (Get-FileHash $installer -Algorithm SHA256).Hash.ToLower()

if (-not $Notes) {
    $Notes = "Chat WiFi $Version"
}

$manifest = [ordered]@{
    version   = $Version
    url       = $url
    sha256    = $sha
    notes     = $Notes
    published = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
}
$manifestPath = Join-Path $root "dist\latest.json"
$json = $manifest | ConvertTo-Json -Depth 5
[IO.File]::WriteAllText($manifestPath, $json, (New-Object Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "Version:    $Version"
Write-Host "Instalador: $installer"
Write-Host "SHA-256:    $sha"
Write-Host "Manifiesto: $manifestPath"
Write-Host ""

if ($NoUpload -or -not $env:GITHUB_TOKEN) {
    Write-Host "Falta GITHUB_TOKEN: no se subio nada." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Opcion manual:"
    Write-Host "1. Abre https://github.com/$Repo/releases/new"
    Write-Host "2. Tag: $tag"
    Write-Host "3. Sube estos dos archivos:"
    Write-Host "   - $installer"
    Write-Host "   - $manifestPath"
    Write-Host "4. Publica la release (no borrador, no prerelease)."
    Write-Host ""
    Write-Host "Opcion automatica:"
    Write-Host '  $env:GITHUB_TOKEN = "ghp_..."'
    Write-Host "  .\publicar_actualizacion.ps1"
    exit 0
}

$headers = @{
    "Authorization"        = "Bearer $env:GITHUB_TOKEN"
    "Accept"               = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "ChatWiFi-Updater"
}

$bodyText = @{
    tag_name         = $tag
    name             = "Chat WiFi $Version"
    body             = $Notes
    draft            = $false
    prerelease       = $false
} | ConvertTo-Json
$bodyBytes = [Text.Encoding]::UTF8.GetBytes($bodyText)

Write-Host "Creando release $tag..."
$release = Invoke-RestMethod -Method Post `
    -Uri "https://api.github.com/repos/$Repo/releases" `
    -Headers $headers -ContentType "application/json; charset=utf-8" -Body $bodyBytes

$uploadUrl = $release.upload_url -replace '\{.*$', ''

Write-Host "Subiendo instalador..."
Invoke-RestMethod -Method Post `
    -Uri "${uploadUrl}?name=$([uri]::EscapeDataString($assetName))" `
    -Headers $headers -ContentType "application/octet-stream" `
    -InFile $installer | Out-Null

Write-Host "Subiendo latest.json..."
Invoke-RestMethod -Method Post `
    -Uri "${uploadUrl}?name=latest.json" `
    -Headers $headers -ContentType "application/json" `
    -InFile $manifestPath | Out-Null

Write-Host ""
Write-Host "Release publicada: https://github.com/$Repo/releases/tag/$tag" -ForegroundColor Green
Write-Host "Manifiesto: https://github.com/$Repo/releases/latest/download/latest.json"
