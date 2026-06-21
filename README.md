# Patchgram for Windows

A Windows port of the macOS Patchgram runtime hook for **Telegram Desktop x64** (built/tested against
6.9.3, Qt 5.15.19). A DLL is loaded into `Telegram.exe`, resolves functions by AOB / string-anchor,
installs inline hooks (MinHook), and rewrites MTProto TL in-process. Same wire format as the macOS engine,
so the TL layer ports directly; only hooking, the Win x64 ABI, and injection are Windows-specific.

**Read [`NOTES.md`](NOTES.md)** — the master doc (architecture, RE findings, every patch, status).

## Layout
- `dll/` — the injected DLL (`Patchgram.dll`):
  - `patchgram.cpp` — resolver, MinHook hooks, host-allocator bridge, byte-patch applier, the in-memory
    `UserData` field writes (custom phone, level rating, channel, bot-verify, …).
  - `engine_tl.c` / `.h` + `tl_schema.c.inc` — TL decoder + rewrite walker (ported from macOS).
  - `engine_patches.c` / `.h` — config (`PatchgramRuntime.json`) + all the response/request rewriters.
  - `patchgram_offsets.h` — RE-confirmed Qt5/x64 offsets. `build.bat` — MSVC x64 build.
- `launcher/` — `launcher.c` + `build.bat` → `pg_launcher.exe`. Installed **as `Telegram.exe`** (the real
  client is renamed `Telegram_real.exe`); it starts the real client suspended, injects `Patchgram.dll`,
  resumes, and forwards args. This makes every launch of Telegram (shortcut, double-click, tg:// link)
  patched without running the GUI — Telegram hardens its DLL search path so plain DLL sideloading won't load.
- `gui_flutter/` — the Flutter patcher (macOS-styled). Edits `PatchgramRuntime.json` and, on Apply, installs
  the launcher + DLL into the Telegram folder and (re)starts it. See `gui_flutter/README.md`.
- `tools/` — reverse-engineering / decompilation tooling: `retool.py` (PE/.pdata/xref), `disasm.py`
  (capstone), `xrefindex.py` (call-graph index), `dump_exc.py` (minidump exception), `find_ctor.py` /
  `dump_tl_layout.py` / `resolve_ctor.py` (TL schema), `ida/` (IDA/Binary Ninja scripts), plus the findings
  docs `signatures.md` + `offsets.md`. Needs the Windows `Telegram.exe` (not committed) + a venv
  (`pefile` + `capstone`).

## Build
Sources only — no build artifacts are committed. To build the full patcher:
1. `dll/` — vendor MinHook into `dll/minhook/` (github.com/TsudaKageyu/minhook), then run `dll\build.bat`
   → `dll/Patchgram.dll`.
2. `launcher/` — run `launcher\build.bat` → `launcher/pg_launcher.exe`.
3. `gui_flutter/` — copy `Patchgram.dll` and `pg_launcher.exe` into `gui_flutter/assets/`, then
   `flutter build windows --release`. The release folder (`build/windows/x64/runner/Release/`) is the
   distributable: `Patchgram.exe` + the Flutter runtime + `data/` (the DLL + launcher ride inside as assets).

## Status
All shipped patches work + are startup-stable on 6.9.3: always-offline, don't-share-phone, 999 accounts,
hide self phone, custom account settings (custom Stars/TON/level-rating, visual badge, bot verification,
local premium, account freeze, custom phone, custom userID, local channel, fragment phone, custom list
usernames + per-username collectible info), message settings (typing/read/drafts/fact-check/no-forwards/TTL),
callback-on-hover, sensitive blur, more recent stickers, open-links-without-warning, disable spoilers,
disable Premium/Stars/TON/Gifts (Premium-UI tier), disable premium effects, hide stories, disable ads,
spoof profile gifts, spoof unique gifts, fake transfer, show hidden gifts, the MTProto logger, and the
persistent launcher. Not committed: the 208 MB `Telegram.exe` (RE input), build outputs, the venv, vendored
MinHook, and the bundled `assets/Patchgram.dll` + `assets/pg_launcher.exe` (build products).
