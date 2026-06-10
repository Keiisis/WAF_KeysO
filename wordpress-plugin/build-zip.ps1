# Build du plugin WordPress installable (keyso-waf.zip)
# Usage : pwsh wordpress-plugin/build-zip.ps1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $root 'keyso-waf'
$out  = Join-Path $root 'keyso-waf.zip'

if (Test-Path $out) { Remove-Item $out -Force }
Compress-Archive -Path $src -DestinationPath $out -CompressionLevel Optimal
Write-Host "✅ Plugin packagé : $out"
