# widevine (nimony)

A free, open-source reimplementation of Google's Widevine Content Decryption
Module (CDM) — the piece of a browser that obtains content keys for protected
media and decrypts that media. It is a drop-in replacement for Google's
proprietary `widevinecdm.dll` / `libwidevinecdm.so` / `libwidevinecdm.dylib`
and implements the same [shared-library CDM API][cdm-api] used by Chromium and
Firefox.

This project is a from-scratch port, written in **[nimony]** (a Nim-family
language), of the architecture pioneered by Thomas Hebb's Rust project
[**openwv**][openwv]. The protocol, algorithms, and ABI match openwv; the
implementation is independent.

> **Not affiliated with or endorsed by Google or Widevine.** For
> interoperability and research. You are responsible for complying with the
> terms of any service you use it with.

## It needs a device identity you must supply

Like openwv, this CDM ships with **no** device identity and does nothing
without one. A device identity (a [`.wvd` file][pywidevine]) holds a Widevine
client's metadata and the RSA private key that authenticates it to license
servers. You must obtain an appropriate `.wvd` yourself. Because browsers
sandbox the CDM and forbid it from reading files at runtime, the identity —
like all configuration — is baked in **at build time**: there are no official
binaries, the only supported way to use this is to build it yourself.

Place your file at the repository root as `embedded.wvd` before building. It is
`.gitignore`d and must never be committed.

## Architecture

The CDM ABI is C++ (a vtable subclass of `cdm::ContentDecryptionModule_10/_11`)
and the crypto is heavy, so the port is layered:

```
browser  ─(C++ vtable)─▶  cpp/shim.cpp  ─(flat C ABI)─▶  nimony logic  ─(flat C ABI)─▶  cpp/wvcrypto.c ─▶ mbedTLS
            CreateCdmInstance,            wv_* exports        src/*.nim          wvc_* imports      libmbedcrypto.a
            Host_NN callbacks         (state, protocol,     protobuf, parsing,
                                        session machine)     KDF, decrypt flow
```

- **`cpp/shim.cpp`** — the only C++. Implements the exported entry points
  (`InitializeCdmModule_4`, `CreateCdmInstance`, …), subclasses the CDM
  interface, and exposes the host callbacks (`Host_10/11`) as plain C functions
  the nimony layer calls. See [docs/DESIGN.md](docs/DESIGN.md).
- **`src/*.nim`** — all logic: config, `.wvd` parsing, PSSH/CENC init-data
  parsing, the Widevine protobuf codec, the session state machine, license
  request/response, session-key derivation, and the decrypt dispatch. Compiled
  to C by nimony, then linked in.
- **`cpp/wvcrypto.c`** — a thin flat-C wrapper over mbedTLS giving the nimony
  layer exactly the primitives it needs (AES-CTR/CBC, AES-CMAC, HMAC-SHA256,
  SHA-1/256, RSA-PSS-SHA1 sign/verify, RSA-OAEP-SHA1 enc/dec, PKCS#1 DER
  import, CSPRNG).

References gathered during the port live in [`docs/`](docs): the CDM ABI, the
Widevine protocol algorithms, and the protobuf schema.

## Building

See [docs/BUILD.md](docs/BUILD.md). In short:

1. Install the [nimony] toolchain, a C/C++ compiler (MinGW-w64 gcc/g++ on
   Windows), and CMake.
2. `tools/fetch-mbedtls` to vendor and build `libmbedcrypto.a`.
3. Put your `embedded.wvd` at the repo root.
4. `tools/build` → produces `widevinecdm.dll` (or `.so`/`.dylib`).

Installation into Firefox / Chrome / Kodi follows openwv's instructions
exactly; see [docs/INSTALL.md](docs/INSTALL.md).

## License

LGPL-3.0-only, matching openwv (whose structure this port follows). See
`LICENSE`.

[cdm-api]: https://chromium.googlesource.com/chromium/cdm/
[openwv]: https://github.com/tchebb/openwv
[pywidevine]: https://github.com/devine-dl/pywidevine
[nimony]: https://github.com/nim-lang/nimony
