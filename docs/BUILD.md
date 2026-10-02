# Building

## Prerequisites

- **[nimony]** toolchain (expected at `%USERPROFILE%\nimony\bin\nimony.exe`).
- A **MinGW-w64 gcc/g++** toolchain. MSYS2 UCRT64 (gcc 15.x) is what this was
  developed with; `gcc`, `g++`, `mingw32-make`, `nm`, `objdump` must be on PATH.
  The nimony toolchain and mbedTLS must be built with the *same* gcc so the
  static link is ABI-compatible.
- **git** (to fetch mbedTLS).

> Build from **PowerShell**, not Git Bash — gcc fails silently under Git Bash
> on Windows.

## One-time: build the crypto library

```powershell
tools\fetch-mbedtls.ps1
```

This clones mbedTLS 3.6.2 into `third-party\mbedtls` (gitignored) and builds
`library\libmbedcrypto.a`. The CDM links this statically.

## Provide a device identity

Place your pywidevine `.wvd` at the repository root as `embedded.wvd`. It is
gitignored and is baked into the DLL at build time (the CDM cannot read files
at runtime). Without it the DLL still builds and loads, but every license
request fails — see [ALGORITHMS.md](ALGORITHMS.md) §1 for the format.

## Build

```powershell
tools\build.ps1                      # uses .\embedded.wvd if present
tools\build.ps1 -Wvd C:\path\dev.wvd # or point at one elsewhere
```

Output: `dist\widevinecdm.dll`.

## What the build does

`build.ps1` bakes the `.wvd` bytes into `src\embedded_device.nim`, then runs

```powershell
cd src
nimony c --app:lib --nimcache:..\build -f widevine.nim
```

`widevine.nim` pulls the C++ shim (`cpp\shim.cpp`) and the crypto wrapper
(`cpp\wvcrypto.c`) into the link via `{.compile.}` pragmas, and links
`libmbedcrypto.a` + `bcrypt` via `{.passL.}`. The shim is compiled
`-fno-exceptions -fno-rtti` and provides freestanding `operator new/delete`;
with `-static` the result has **no** `libstdc++`/`libgcc` runtime DLL
dependency — only system DLLs (`kernel32`, `advapi32`, `bcrypt`) plus the
Windows UCRT. Verify with:

```powershell
objdump -p dist\widevinecdm.dll | Select-String "DLL Name:"
```

## Smoke test

`build\smoke.c` loads the DLL and calls `GetCdmVersion` /
`InitializeCdmModule_4`:

```powershell
gcc build\smoke.c -o build\smoke.exe ; .\build\smoke.exe
```

[nimony]: https://github.com/nim-lang/nimony
