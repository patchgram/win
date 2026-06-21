# Patchgram for Windows — porting notes

Goal: port the macOS Patchgram runtime hook (`Patchgram.dylib`) to a Windows DLL injected into
`Telegram.exe`, reusing the same AOB-signature + inline-hook + in-dylib TL-rewrite approach so we
**don't chase offsets every update** — we re-derive a signature only when a function's code actually
changes. This file is the living doc: read it top-to-bottom to continue the work.

Status legend: ✅ done · 🟡 in progress / partial · ⬜ todo

> **2026-06-20 update — RE verification complete.** Both hooks + **all §3 offsets are now VERIFIED**
> against the real `Telegram.exe` 6.9.3 (disasm via `re/disasm.py` + tdesktop v6.9.3 source). Headline:
> **the Windows build links Qt 5.15.19, not Qt6** — so `mtpBuffer`/`QVector`/`QString` is a single 8-byte
> COW pointer, not Qt6's 24-byte `{d,ptr,size}`. Every macOS `QVECTOR_*` offset is wrong on Windows; the
> received-queue + request offsets are all smaller. Confirmed values are in `re/offsets.md` and locked into
> `dll/patchgram_offsets.h` (+ a `pg_qvec_data()` Qt5 decoder). The logger in `dll/patchgram.cpp` now reads
> buffers the Qt5 way. Remaining: build the DLL on Windows, then port the engine TL core.

---

## 0. Target binary (the RE input)

- Path: `patchgram-windows/Telegram/Telegram.exe` (gitignored — 208 MB, do not commit).
- **Telegram Desktop 6.9.3** — *exactly the same source version as the macOS build the dylib targets.*
  → functions + struct layouts are the same source, just compiled MSVC/x64 instead of clang/arm64.
- PE32+ **x86-64**, **Qt statically linked into the exe** (single monolithic binary, like macOS). Only
  `modules/x64/d3d/d3dcompiler_47.dll` is external (D3D shader compiler — irrelevant).
- ImageBase `0x140000000`. Sections (VA / vsize / fileoff):
  - `.text`   `0x140001000` / `0x59a6e7c` (~94 MB code) / file `0x600`   ← scan window for signatures
  - `.rdata`  `0x1459a9000` / `0x2dcca08` / file `0x59a8000`             ← strings / vtables / rodata
  - `.data`   `0x148776000` / `0x4d243ec` / file `0x8774c00`
  - `.pdata`  `0x14d49b000` / `0x3c0360`  / file `0xc189800`            ← **x64 unwind table = every fn's [begin,end) RVA**
  - `.reloc`  `0x14d874000` …

`.pdata` is the key shortcut: on x64 every non-leaf function has a `RUNTIME_FUNCTION{BeginRVA, EndRVA,
UnwindRVA}` (3 DWORDs). `re/enum_funcs.py` parses it → ~all function bounds without a multi-hour IDA pass.

---

## 1. Architecture: what ports vs what's new

The macOS engine (`Sources/PatchgramCore/Resources/engine.c.template`, ~9k lines) already uses the exact
technique we want on Windows:
- **AOB signature + mask** scan of the code section to locate a function entry (`patchgram_find_signature`).
- **Inline hook + trampoline** (copy prologue, write an absolute branch, keep the original) to intercept it.
- **In-engine TL decoder/rewriter** (`tl_schema.c.inc`, layer 227) — pure C, **MTProto wire format is identical
  on every platform**, so this ports verbatim.

### Ports with little/no change (the high-value 50%+)
- **The entire TL engine** (decoder, rewriter, schema, all the gift/message/etc. response rewriting). Pure C.
- **Qt memory layouts** we rely on — both are 64-bit, Qt6 → same:
  - `QVector`/`QList<mtpPrime>` = `{ Data* d; T* ptr; qsizetype size; }` → d@0x0, ptr@0x8, size@0x10.
  - `QString` = same `{d, ptr, size}` → 0x0/0x8/0x10.
- **The whole MTProto-patch family hangs on just TWO hooks** (see §2). Re-derive those 2 signatures for x64
  and the whole class lights up: spoof gifts (regular/unique/value/fake-transfer), show hidden, message
  settings + subpatches, fragment phone, custom usernames, account freeze, fact check, MTProto logger.

### Needs Windows-specific work
- ⬜ **AOB signatures re-derived for x64** (different instruction encoding). Only the hook anchors + each
  byte-patch. tdesktop being open source speeds this up (compile a ref build / cross-ref source).
- ⬜ **Inline-hook glue + ABI**: Windows x64 calling convention is RCX/RDX/R8/R9 (+ shadow space, 16-byte
  stack alignment) vs arm64 X0–X7. Use **MinHook** (battle-tested x64 inline hooker) instead of the hand-
  rolled arm64 trampoline. Our hook callbacks become `__fastcall`/default-x64 with the right arg order.
- ⬜ **Injection**: DLL injection (loader: `CreateRemoteThread`+`LoadLibrary`, or a proxy/`version.dll`
  next to Telegram.exe) instead of `DYLD_INSERT_LIBRARIES`. See `loader/`.
- 🟡 **Struct offsets**: same source → likely the SAME, but MSVC vs clang field packing must be confirmed
  per struct (see §3). Verify before trusting.
- ⬜ **Per byte-patch AOBs** (999 accounts, premium, monetization, recent stickers, sensitive blur, …).
- ⬜ **Patcher GUI**: SwiftUI is Apple-only. Windows side = a prebuilt DLL that reads config from a JSON
  file at runtime (the engine already reads `PatchgramRuntime.json`) + a small loader/CLI (or later a
  proper GUI). No per-apply compiler needed on the user's machine.
- ❌ **Profile rain overlay** = AppKit/QuartzCore, macOS-only. Drop on Windows, or later reimplement on
  Direct2D/Qt. It's one cosmetic patch.

---

## 2. The two hooks (the leverage)

From the macOS engine (`engine.c.template`):
- `MTP::details::SessionPrivate::tryToReceive` — ABI `void tryToReceive(SessionPrivate* this)`.
  Windows x64: `this` in **RCX**. Walks the received-response queue → we rewrite incoming responses here.
- `MTP::details::Session::sendPrepared` — ABI `void sendPrepared(Session* this, SerializedRequest request,
  int64 msCanWait)`. Windows x64: **RCX=this, RDX=request, R8=msCanWait**. We inspect/modify outgoing
  requests here (track gift requests, strip flags, invalidate transfer slug, log).
  - `request` is a pointer to a `SerializedRequest` whose first 8 bytes is a pointer to the request data
    buffer (macOS does `memcpy(&request_data, request_ref, 8)`), then QVector at request_data+{0x8 ptr,
    0x10 size}, and `request_id` at request_data + `0x30`.

Source files in tdesktop 6.9.3:
- `Telegram/SourceFiles/mtproto/session_private.cpp` → `SessionPrivate::tryToReceive()`
- `Telegram/SourceFiles/mtproto/session.cpp` → `Session::sendPrepared()`

Finding them in the x64 binary (the 4–5h part) — strategy, easiest first:
1. **String anchors**: look for unique log/literal strings used inside (or right next to) these functions,
   find their `.rdata` address, then find the `lea rXX, [rip+disp]` in `.text` that references them, and
   walk up to the enclosing function via `.pdata`. `re/find_str_xref.py` helps.
2. **`.pdata` + structural match**: enumerate functions, disassemble, match by what they call / constants.
3. Last resort: full IDA/Hex-Rays pass (idalib MCP) — heavy on a 94 MB `.text`; do it selectively on
   candidate addresses, not a blind full auto-analysis (that crashed on the 216 MB macOS binary).

When found, record for each: function RVA, entry bytes (≥16), and an AOB signature (fixed opcode bytes +
0x00 wildcards over rip-relative displacements / call targets). Put them in `re/signatures.md`.

---

## 3. Struct / layout constants to verify on x64

macOS values vs the **now-verified Windows (Qt5) values** (full evidence in `re/offsets.md`):
| constant | macOS (Qt6) | **Windows (Qt5) ✅** | meaning |
| --- | --- | --- | --- |
| QVECTOR layout | d/ptr/size @ 0x0/0x8/0x10 (24B) | **single `d` ptr (8B)**; size@`d+4`, data@`d+*(d+0x10)` | Qt5 COW QVector — **differs** |
| QSTRING layout | d/ptr/size @ 0x0/0x8/0x10 | **single `d` ptr (8B)** (same Qt5 QArrayData) | Qt5 COW QString — **differs** |
| SESSION_PRIVATE_DATA_OFFSET | 0x28 | **0x28** | Session → `_data` (unchanged) |
| SESSION_DATA_RECEIVED_BEGIN/END | 0x120 / 0x128 | **0xc0 / 0xc8** | `std::vector<Response>` first/last |
| RESPONSE_SIZE | 0x28 | **0x18** | `sizeof(Response)` (Qt5 reply is 8B) |
| RESPONSE_REQUEST_ID_OFFSET | 0x20 | **0x10** | requestId within a Response |
| REQUEST_DATA_REQUEST_ID_OFFSET | 0x30 | **0x20** | RequestData::requestId |
| SERIALIZED_REQUEST_BODY_POSITION | 8 (words) | **8** | TL body ctor word index (wire fmt, unchanged) |
| USER_PHONE_OFFSET | 0x288 | _(verify when porting self-phone patches)_ | UserData.phone QString |

The headline: macOS QVECTOR/QSTRING are **NOT** safe to reuse — Windows is Qt5 (8-byte COW), so size/data
must be read through `d`. The SessionData/Response/Request offsets are all smaller than macOS for the same
reason. All locked into `dll/patchgram_offsets.h`; reproduce with `re/disasm.py mem 0x<rva>`.

---

## 4. Plan / order of work

1. ✅ Workspace + this doc + RE tooling (`re/retool.py`, parses .pdata = 327,752 funcs).
2. ✅ RE: **both hooks located + cross-validated** via string-xref (`re/signatures.md`):
   - `Session::sendPrepared` = RVA `0x2192cb0`, `Session::tryToReceive` = RVA `0x2193a50`.
3. ✅ Verify the §3 offsets on x64 (`re/offsets.md`) — **DONE**; all offsets confirmed by disasm +
   v6.9.3 source. Found the Qt5-vs-Qt6 QVector divergence; locked into `dll/patchgram_offsets.h`.
4. ✅ DLL: `dll/patchgram.cpp` = runtime resolver (anchor string → rip-lea → `RtlLookupFunctionEntry`) +
   MinHook + the 2 hooks wired as an **MTProto logger** (validation), using the Qt5-correct offsets.
   **Builds cleanly** (MSVC 14.41 x64, MinHook vendored, `dll/build.bat`) → `Patchgram.dll`, a 0x8664
   DLL importing only KERNEL32 (static `/MT`). TL rewriters not ported yet.
5. ✅ Loader/injector (`loader/inject.cpp`) — complete + **builds** (`loader/build.bat` → `patchgram-loader.exe`).
   **Attach-if-running fix:** Telegram Desktop is single-instance, so launching a 2nd (injected) copy makes
   it hand off to the existing window and exit → nothing patched. The loader now, in launch mode, **attaches
   to a running instance** instead (this was the cause of "always-offline / block-typing / block-read don't
   work" — the patch logic was correct; the injected process was being discarded). Verified: clean launch
   fires `ALWAYS OFFLINE forced…`; with Telegram running the loader logs `injected (attached running pid …)`.
6. ✅ Config: `PatchgramRuntime.json` (same keys as macOS engine) read at DLL load (`pg_config_load`), plus a
   **live-reload watcher** thread (`configWatcher` in patchgram.cpp): polls the file by CONTENT every 1s
   (mtime polling is unreliable — NTFS defers directory timestamps) and reloads on change. So a GUI Save
   takes effect on the running Telegram with no restart — this (with the loader attach fix) is why
   "always-offline / typing / read didn't work": re-injecting never re-ran DllMain, so config never updated.
   Verified live: edit the JSON → `# config reloaded (PatchgramRuntime.json changed)` + the new flags.
7. 🟡 Port the engine TL core (`engine.c.template`) into the hooks.
   - ✅ **Read-only decoder** — `dll/engine_tl.c` + `dll/tl_schema.c.inc` (2464-ctor schema, ported verbatim,
     `rw` dropped) → `patchgram_tl_decode()`; both hooks log **fully-decoded TL** (live: 69 req + 41 resp, 0 unknown).
   - ✅ **Config system** — `dll/engine_patches.c` reads `PatchgramRuntime.json` (same keys as macOS) next to
     the exe → enable-flags (defaults: logger on, rewriters off). Validated: `# config loaded: logger=1 …`.
   - ✅ **Rewriter framework + rewriters** — `pg_apply_response`/`pg_apply_request` dispatchers; ported:
     · `strip_noforwards` (Copy/save-protect: clears message#7600b9d3 flag.26 / channel#1c32b11c flag.27
       in place, Qt5 COW-guarded via `pg_qvec_unshared`). Armed (fires only on protected content).
     · `account_freeze` (inject freeze_since/until/appeal into help.appConfig). **Live-validated:**
       `ACCOUNT FREEZE injected … -> 4026 words (cap=8186)` — proves the **Qt5 resize-within-capacity**
       path: read `d->alloc` (`pg_qvec_capacity`), append within slack, bump count, full re-parse via
       `patchgram_tl_validate` (new NULL-sink decode mode), publish `d->size` (`pg_qvec_set_size`).
     No regression to the logger (still 0 unknown ctors).
   - ✅ **`rw`-walker (in-place subset)** — threaded `struct PatchgramTLRewrite *rw` through
     `patchgram_tl_decode_{ctor,value}` (all new logic `if(rw)`-guarded; `rw==NULL` decode path is
     byte-identical — regression-checked live: 0 unknown ctors with the walker present). Ported
     `patchgram_gift_rewrite_field` (base scalar branches) + `patchgram_tl_rewrite_saved_star_gifts`.
     Wired `pg_gift_spoof` (date/gift_id/stars/sender/sticker/supply/gift_num/refunded over every
     `payments.savedStarGifts`, "everyone" mode), config keys `giftSpoof*`. **Builds + off-by-default +
     regression-safe; live-firing pending** a profile-with-gifts (GUI) — the only way to exercise it.
   - ✅ **Qt5 resize-BEYOND-capacity writeback** — `pg_qvec_grow` (append within a bigger buffer) +
     `pg_qvec_replace` (build-fresh-and-swap), engine_patches.c. **LEAK-BASED, zero cross-CRT frees:** the
     new `d` is marked Qt5 STATIC (`ref = -1`) so Telegram never frees it, and we never free Telegram's old
     `d`. Telegram statically links its CRT (imports 0 CRT DLLs) so neither side may free the other's heap
     blocks — this design sidesteps that entirely (mirrors the macOS engine, which also leaks). Cost: a
     small per-rewrite leak (rewrites are infrequent). ⚠️ **An earlier free-based version crashed the
     session** (freeing a Telegram buffer / Telegram freeing ours) — do NOT reintroduce frees; and only
     ever relocate a HIGH-LEVEL RPC result, never a service message (the first crash relocated a
     `new_session_created`). Validated: init self-test `# SELFTEST grow: PASS (size=4 cap=16 data_ok=1)`
     **and live** — relocating a real 318-word `config#cc1a241e` buffer left Telegram running normally
     (41 responses decoded after, 0 unknown). Wired into `account_freeze` (grows when slack is short).
   - ✅ **Show hidden gifts** (`inject_hidden_gifts`) — clones the first catalog gift's slimmed sticker
     Document, swaps its id to a chosen custom-emoji id, splices N starGift entries (50 Stars) at the front
     of a `payments.starGifts` response (memmove + `pg_qvec_grow` beyond capacity, re-validated). Needed
     the **read-only capture branches** in the walker (`find_first_doc`, `find_gifts_end`, Document
     `thumbs` span) — added, all `if(rw)`-guarded, regression-clean (0 unknown). Config: `giftShowHiddenEnabled`
     + `giftHiddenPayload="giftId:emojiId,..."`. Built + off-by-default; GUI-fire pending (gift-send menu).
   - ✅ **Request-side patches (no IDA — pure TL in `sendPrepared`, `pg_apply_request`)**: `alwaysOffline`
     (force `account.updateStatus` offline→boolTrue, in-place — **live-validated: fires + session survives**),
     `noPhoneOnAdd` (strip `contacts.addContact` flags.0, in-place), `blockTyping` (drop `messages.setTyping`),
     `blockRead` (drop readHistory/channels.readHistory/readMessageContents/readDiscussion). Drops = the hook
     returns without calling the original, so the request never enters toSendMap (clean, no resend). Config:
     `alwaysOfflineEnabled` / `blockTypingEnabled` / `blockReadMessagesEnabled` / `noPhoneOnAddEnabled`.
     blockTyping/blockRead/noPhone fire only on GUI activity (typing/reading/adding a contact).
   - ⬜ **Remaining** — these are the large, GUI/RE-gated tier (the response- + request-rewriter tiers are done):
     · **Request-tracking + memory-patch-driven rewriters**: fact-check, fragment-phone, custom-username,
       fake-transfer, unique-gift rebuild. Each needs a request-tracking ring AND a memory patch to *force*
       the request (e.g. force `messages.getFactCheck` per post) — so they depend on the byte-patch subsystem.
     · **Byte-patch AOB subsystem** — ✅ **applier engine built + validated**: `pg_mem_patch` (masked AOB
       scan of .text + `VirtualProtect` write + `FlushInstructionCache`) with a private-buffer self-test
       (`# MEMPATCH selftest: find_ok=1 write_ok=1`). ⬜ **Per-patch AOB derivation is the remaining work**
       and needs IDA/idalib: the target functions (999 accounts, recent-stickers limit, monetization,
       sensitive blur, media spoilers, premium effects, hide stories, disable ads, block typing/read, …)
       are anchor-less in the stripped 208 MB binary — verified for recent-stickers: the `cmp #20` in
       `StickersListWidget::collectRecentStickers` can't be reached from the `"unlimited-recent-stickers"`
       option id (tdesktop's `base::options::toggle::value()` reads a central registry, not the toggle
       object). macOS used IDA-derived vmaddrs. So: locate each fn in IDA → derive its x64 AOB → register
       it in the engine. Behavioural verification of each needs the GUI.
8. ✅ Windows patcher GUI — two front-ends, both edit `PatchgramRuntime.json` + drive the loader:
   - `gui/` — `PatchgramGui.exe`, lightweight WinForms (built-in .NET `csc.exe`, no SDK; `gui/build.bat`).
     Verified live: builds, launches, window renders.
   - `gui_flutter/` — **Flutter rewrite styled to match the macOS (SwiftUI) app**: dark theme, top bar
     (Logs/Rescan/Choose App), sidebar stats, sections→detail master/detail, patch cards with
     Available/`dylib`·`binary`/Enabled badges + toggles, search, Filters popover (Type+Sort), collapsible
     subpatches, and Gift-spoof / hidden-gifts Settings modals. Catalog mirrors the 5 macOS sections;
     `available:true` patches map to the DLL config keys, the byte-patch ones show "Needs RE" (toggle
     disabled). **Built + verified live** with Flutter 3.44.2 (`gui_flutter/build.bat` → `flutter build
     windows --release` → `build\windows\x64\runner\Release\patchgram_gui.exe`); on launch it read the
     real exe size + loaded the existing PatchgramRuntime.json. Screenshots: `gui_flutter/screenshot-*.png`.
     (NB build.bat must `call flutter …` — flutter is a .bat, so without CALL control never returns.)
     **Polish pass (matches the macOS app):** section + logo icons are the macOS SVGs (`assets/section-*.svg`,
     `PatchgramLogo.svg`, via flutter_svg); `dylib` badge renders as **`dll`**; gear + About buttons wired
     (Settings + About dialogs); **Logs** opens the Telegram.exe folder; **Selected app** shows the icon +
     ProductName/ProductVersion read from Telegram.exe (e.g. "Telegram Desktop 6.9.3"); Account freeze is a
     subpatch of Custom account settings only (not standalone); Misc = "DLL injection" + logger (rain overlay
     dropped); Show hidden gifts is a plain toggle (baked-in default gifts, like macOS); catalog order/grouping
     mirrors macOS (Custom account settings + Message settings groups). The Patchgram logo renders WHITE
     (it's a white-fill SVG; the blue tint was a bug). **About** = white logo + title + subtitle + GitHub
     (github.com/patchgram/win) & Telegram (t.me/patchgram) link buttons with their logos (url_launcher), no
     description/Selected lines. **Program icon** generated from `assets/app_icon.png` (the macOS
     PatchgramAppIcon) via flutter_launcher_icons. Screenshots: `gui_flutter/screenshot-{sections,accounts,about}.png`.

**First Windows milestone: ✅ ACHIEVED (2026-06-20).** Built `dll/` + `loader/`, injected into a live
Telegram 6.9.3 (attach mode: `loader\patchgram-loader.exe <abs>\dll\Patchgram.dll`), and `PatchgramHook.log`
(next to the exe) confirmed the whole chain on real MTProto traffic:
- `RESOLVE Session::tryToReceive via anchor -> …3A50` and `…sendPrepared … -> …2CB0` — anchor→xref→unwind
  resolver hit the exact verified RVAs (module-relative 0x2193A50 / 0x2192CB0).
- Decoded ctors are all real + correlated by requestId, proving the Qt5 buffer decode + every offset:
  `-> REQUEST reqId=148 updates.getChannelDifference` ↔ `<- RESPONSE reqId=148 updates.channelDifference`;
  `-> REQUEST reqId=149 messages.getPeerDialogs` ↔ `<- RESPONSE reqId=149 messages.peerDialogs`;
  `<- RESPONSE reqId=0` `updates#74ae4240` / `updateShort#78d4dec1`.
This validates: resolver, both hook ABIs, Response stride 0x18 + requestId@0x10, RequestData requestId@0x20,
body ctor @ word 8, and the **Qt5 QVector decode** (size@d+4, data@d+d->offset). Everything after is
porting the (portable) TL rewriters from `engine.c.template` into the two hook callbacks.

## 5. How to build / test on Windows (once the DLL exists)
- Build the DLL with MSVC (x64) — see `dll/README.md`. Pull MinHook (vendored or via vcpkg).
- Inject with `loader/` (run the loader, or drop the proxy DLL next to Telegram.exe).
- Engine writes its log next to the exe (mirror the macOS `PatchgramHook.log`) — check it for
  `RESOLVE … via signature` lines to confirm the hooks landed.
- AV note: DLL injection trips antivirus heuristics; expect SmartScreen/Defender friction.

## 6. Gotchas
- MSVC x64: callbacks need shadow space + 16-byte stack alignment (MinHook handles the trampoline ABI).
- `.text` is ~94 MB → signature scans must be reasonably fast (4-byte... no, x64 is byte-aligned; scan
  on a 1-byte stride but prefilter on the first 4 fixed bytes like the macOS resolver does).
- Functions on x64 are NOT 4-byte aligned (unlike arm64) → can't stride by 4; use `.pdata` begins as the
  candidate set, or a byte-stride scan with a strong first-bytes prefilter.
</content>
