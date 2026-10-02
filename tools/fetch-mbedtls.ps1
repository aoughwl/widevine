# Fetch and build the mbedTLS static crypto library (libmbedcrypto.a) that the
# CDM links against. One-time setup; the tree lands under third-party/mbedtls
# (gitignored). Needs git + a MinGW gcc/make toolchain (MSYS2 UCRT64 works).
param(
  [string]$Tag = "mbedtls-3.6.2"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$dir = Join-Path $root "third-party\mbedtls"

if (-not (Test-Path (Join-Path $dir ".git"))) {
  Write-Host "Cloning mbedTLS $Tag ..."
  git clone --branch $Tag --depth 1 https://github.com/Mbed-TLS/mbedtls.git $dir
  Push-Location $dir
  try { git submodule update --init } finally { Pop-Location }
}

Push-Location (Join-Path $dir "library")
try {
  Write-Host "Building libmbedcrypto.a ..."
  # mingw32-make ships with MSYS2 UCRT64; adjust if your make is named 'make'.
  & mingw32-make libmbedcrypto.a CC=gcc
  if ($LASTEXITCODE -ne 0) { throw "mbedTLS build failed (exit $LASTEXITCODE)" }
} finally { Pop-Location }

$lib = Join-Path $dir "library\libmbedcrypto.a"
if (Test-Path $lib) { Write-Host "OK: $lib" } else { throw "libmbedcrypto.a not produced" }
