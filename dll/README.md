# Patchgram.dll (Windows) — build

Target: x64 DLL injected into `Telegram.exe` (Telegram Desktop 6.9.3). Current state = a working MTProto
**logger with full TL decode**: the two hooks resolve, the Qt5 buffers are read, and `engine_tl.c`
(the macOS TL decoder + `tl_schema.c.inc`, ported verbatim) turns every request/response into readable TL
(`name#id { field=value, … }`). Validated live (69 req + 41 resp, 0 unknown ctors). Next: port the macOS
engine's in-place **rewriters** into the two callbacks (`patchgram.cpp`) to enable the real patches.

## Files
- `patchgram.cpp` — DLL glue (C++): runtime hook resolver, MinHook install, the two hook callbacks, Qt5
  buffer decode, config load (`PatchgramRuntime.json`). Calls `patchgram_tl_decode` + `pg_apply_*`.
- `engine_tl.c` / `engine_tl.h` — portable MTProto TL decoder (C), ported from the macOS engine. Read-only.
- `engine_patches.c` / `engine_patches.h` — config (`pg_config_load`) + the runtime rewriters
  (`pg_apply_response` / `pg_apply_request`), ported + Qt5-adapted. First rewriter: `strip_noforwards`.
- `tl_schema.c.inc` — generated TL schema (2464 ctors), bundled from the macOS repo, `#include`d by engine_tl.c.
- `patchgram_offsets.h` — all RE-confirmed Qt5/x64 offsets + `pg_qvec_data` / `pg_qvec_unshared` helpers.

## Config (`PatchgramRuntime.json`, next to `Telegram.exe`)
Same keys as the macOS engine; missing file → defaults (logger on, rewriters off). Recognised so far:
- `mtprotoLoggerEnabled` (default true) — decode + log every request/response.
- `messageSettingsEnabled` + `messageNoForwardsCopyEnabled` — copy/save-protect strip (`strip_noforwards`).
- `accountFreezeEnabled` — inject freeze dates + appeal URL into help.appConfig (`account_freeze`); the
  client then shows the account as frozen locally (clears on a restart without the patch).
- `giftSpoofEnabled` (+ `giftSpoofSenderId`, `giftSpoofSenderPeerType`, `giftSpoofDate`, `giftSpoofGiftId`,
  `giftSpoofStickerId`, `giftSpoofStars`, `giftSpoofAvailable`, `giftSpoofTotal`, `giftSpoofLimited`,
  `giftSpoofGiftNum`, `giftSpoofWasRefunded`) — rewrite the scalar fields of every gift in a
  `payments.savedStarGifts` response in place (base subset of Spoof-profile-gifts; "everyone" target,
  no caption/badge rebuild yet). Uses the `rw`-walker in `engine_tl.c`.

- `giftShowHiddenEnabled` + `giftHiddenPayload` (`"giftId:emojiId,giftId:emojiId,…"`) — inject extra
  starGift entries into the `payments.starGifts` catalog (`inject_hidden_gifts`; clones the first gift's
  slimmed sticker doc, swaps its id to your emoji id). Uses the `rw`-walker capture branches + `pg_qvec_grow`.

- `alwaysOfflineEnabled` — force `account.updateStatus` offline → boolTrue (in-place request rewrite). **Live-validated.**
- `blockTypingEnabled` — drop `messages.setTyping` requests (hook returns without forwarding).
- `blockReadMessagesEnabled` — drop read-history/contents/discussion requests.
- `noPhoneOnAddEnabled` — strip `add_phone_privacy_exception` (flags.0) from `contacts.addContact`.
  (These four are pure-TL, no IDA. Drops are a clean block — the request never enters the send queue.)

More keys are added as rewriters are ported.

## Dependencies
- **MinHook** (x64 inline hooking). Either:
  - vcpkg: `vcpkg install minhook:x64-windows-static` and link `minhook.lib`, or
  - vendor: clone https://github.com/TsudaKageyu/minhook into `dll/minhook/` and add its `src/*.c` +
    `include/` to the build. Header used: `#include "MinHook.h"`.

## Build (one command)
Run `dll\build.bat` from any shell — it locates VS via `vswhere`, calls `vcvars64`, compiles `engine_tl.c`
(as C, `/TC`) and `patchgram.cpp` + the vendored MinHook sources into `Patchgram.dll` (objects go to
`dll\build\`). MinHook must be vendored at `dll/minhook/` — `git clone https://github.com/TsudaKageyu/minhook dll/minhook`.
The result is a 0x8664 DLL importing only KERNEL32 (static `/MT`). **Note:** can't overwrite `Patchgram.dll`
while it's injected into a running Telegram — close Telegram (or build to a new name) first.

> Note: this build links Qt5-shaped struct access — the Windows Telegram 6.9.3 build is **Qt 5.15.19**
> (8-byte COW `QVector`), see `../re/offsets.md`. The macOS Qt6 offsets are NOT reused.

## Build (manual, MSVC x64 Native Tools Command Prompt)
```
cl /LD /O2 /MT /std:c++17 /EHsc ^
   /I include\path\to\minhook\include ^
   patchgram.cpp ^
   path\to\minhook.lib ^
   /link /OUT:Patchgram.dll
```
(or drop the files into a Visual Studio "Dynamic-Link Library" x64 project; `/MT` = static CRT so the DLL
has no extra runtime deps.)

## Run
- Inject with `..\loader\` (see its README), or rename `Patchgram.dll` per a proxy-DLL approach.
- On success `PatchgramHook.log` appears next to `Telegram.exe` with `RESOLVE … via anchor` + request/
  response lines. If you see `RVA fallback`, the anchor strings changed — re-derive (re/retool.py).

## Porting the engine — status + next
The macOS engine `Sources/PatchgramCore/Resources/engine.c.template` is ~10k lines of mostly-portable C.
- ✅ **TL decoder + schema** → `engine_tl.c` + `tl_schema.c.inc` (read-only walker; `rw` context dropped).
- ✅ **Hook install** → MinHook (`patchgram.cpp`); **injection** → `loader/`; **buffer access** → Qt5 (`pg_qvec_data`).
- ⬜ **Rewriters** (`patchgram_apply_*_response` / `patchgram_*_request_*`): reuse this schema + walker but
  reintroduce the `PatchgramTLRewrite` context AND adapt every buffer read/write to Qt5. The macOS
  versions read/write `words`/`count` via Qt6 inline `{ptr@0x8, size@0x10}`; on Windows reads go through
  `pg_qvec_data`, and **resizes** (hidden-gift inject, gift spoof rebuild) need Qt5 COW detach/realloc —
  NOT a simple inline `size` write. Start with the in-place, non-resizing rewriters.
- ❌ AppKit overlay / profile rain → drop (macOS-only).
Config: reuse `PatchgramRuntime.json` (same keys the macOS engine reads) placed next to `Telegram.exe`;
parse it at load and set the same globals (the rewriters gate on those globals, e.g. `g_gift_spoof_enabled`).

Config: reuse `PatchgramRuntime.json` (same keys the macOS engine reads) placed next to `Telegram.exe`;
parse it at load and set the same globals.
