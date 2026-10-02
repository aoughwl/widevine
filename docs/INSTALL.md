# Installing

"The library" below means your built `dist\widevinecdm.dll` (or
`libwidevinecdm.so` / `.dylib` on other platforms). Installation is identical
to [openwv](https://github.com/tchebb/openwv#installation); summarized here.

## Firefox
1. `about:support` → note your **Profile Directory**.
2. `about:config` → set `media.gmp-widevinecdm.autoupdate` to `false` (create
   it if needed) and `media.gmp-widevinecdm.version` to `openwv`.
3. In the profile, go to `gmp-widevinecdm/`.
4. Create a subdirectory `openwv/`, and put the library plus
   `manifest-firefox.json` (renamed to `manifest.json`) inside it. You **must**
   use this `manifest.json` (not Google's) — it advertises no decode support,
   or Firefox won't play video.

A manual add-on update check reverts Firefox to Google's CDM; if that happens,
set `media.gmp-widevinecdm.version` back to `openwv`.

## Chrome / Chromium
1. `chrome://version/` → note the **parent** of your Profile Path (the "User
   Data Directory").
2. Go to `WidevineCdm/` there; delete any existing subdirectories.
3. Create a numeric subdirectory greater than Google's version, e.g. `9999/`,
   and put `manifest-chromium.json` (renamed to `manifest.json`) in it.
4. Beside it create `_platform_specific/win_x64/` (or the right OS/arch) and put
   the library there.
5. On Linux only, launch and quit the browser once before playing protected
   media (a Chromium registration quirk).

## Kodi (InputStream Adaptive)
Build with `encryptPolicy = eciNever` in `src/config.nim` (InputStream Adaptive
can't handle service-certificate request messages), then set its "Decrypter
path" to the directory containing the library.
