# Patchgram (Windows) — Patch Authoring Guide

Audience: an AI agent (or engineer) who wants to add a **new patch** to the Windows Patchgram DLL, using
only this repo + public sources. It explains the architecture, the **Windows-specific** differences from
the macOS build, how to find what you need in `Telegram.exe`, how to write each kind of patch, and how to
build/test it.

- This repo: <https://github.com/patchgram/win>
- macOS original (the reference design; the portable TL engine + schema come from here):
  <https://github.com/patchgram/osx> — its `docs/patch-authoring.md` covers the shared TL concepts in more
  depth. **Read it first for the TL/rewriter model**, then this for the Windows ABI/layout.
- Target: **Telegram Desktop 6.9.3**, x86-64. Download: <https://telegram.org/dl/desktop/win64>
- Telegram Desktop source (**same source version as macOS** → same functions/structs, different compiler):
  tag `v6.9.3` → <https://github.com/telegramdesktop/tdesktop/tree/v6.9.3>
- MTProto/TL schema, **layer 227**: bundled as `dll/tl_schema.c.inc` (generated from the macOS repo);
  upstream [`scheme.tl`](https://github.com/telegramdesktop/tdesktop/tree/v6.9.3/Telegram/SourceFiles/mtproto/scheme)
  / <https://core.telegram.org/schema>.
- Gift catalog (ids, models, symbols, backdrops, emoji ids): **@GiftChanges** — <https://api.changes.tg>.
- Living RE/status doc for this port: [`../NOTES.md`](../NOTES.md). Verified offsets/signatures:
  [`../tools/offsets.md`](../tools/offsets.md), [`../tools/signatures.md`](../tools/signatures.md).

---

## 1. What's the same, what's different vs macOS

**Same (ports verbatim):** the TL wire format, the schema (`tl_schema.c.inc`), the decoder/rewriter
(`engine_tl.c`), and the *whole patch idea* — hook the same two MTProto functions and rewrite the buffers.
The entire MTProto-patch family hangs on the same **two hooks**.

**Different (Windows work):**

| Area | macOS | **Windows** |
| --- | --- | --- |
| Qt version | **Qt6** — `QVector` = 24-byte `{d@0, ptr@8, size@0x10}` | **Qt 5.15.19** — `QVector`/`mtpBuffer` = a **single 8-byte COW `d` pointer**. size, capacity, data are reached *through* `d` (a Qt5 `QArrayData` header: `ref@0`, `size@4`, `alloc@8` (31-bit), `offset@0x10`; `data() = d + offset`). **Every macOS QVECTOR offset is wrong here.** Use the helpers `pg_qvec_data` / `pg_qvec_unshared` / `pg_qvec_capacity` / `pg_qvec_set_size` in [`dll/patchgram_offsets.h`](../dll/patchgram_offsets.h). |
| Calling convention | arm64 X0–X7 | **x64: RCX, RDX, R8, R9** (+ 32-byte shadow space, 16-byte stack align). Hook callbacks are `__fastcall`. |
| Inline hooking | hand-rolled trampoline | **MinHook** (<https://github.com/TsudaKageyu/minhook>), vendored at `dll/minhook/`. |
| Injection | `DYLD_INSERT_LIBRARIES` wrapper | **DLL injection launcher** ([`launcher/launcher.c`](../launcher/launcher.c)): renames `Telegram.exe`→`Telegram_real.exe`, starts it `CREATE_SUSPENDED`, `LoadLibrary`-injects `Patchgram.dll`, resumes. |
| Patcher UI | SwiftUI | **Flutter** (`gui_flutter/`) — writes `PatchgramRuntime.json` next to `Telegram.exe`; the DLL reads it. |
| Overlay (profile rain) | AppKit | dropped (would need Direct2D/Qt). |

Verified function RVAs (module-relative; resolver uses signatures, these are the fallback — see
[`dll/patchgram_offsets.h`](../dll/patchgram_offsets.h)):

- `Session::tryToReceive` — `PG_RVA_TRY_TO_RECEIVE 0x2193a50` → hook `hkTryToReceive(void* self /*RCX*/)`.
- `Session::sendPrepared` — `PG_RVA_SEND_PREPARED 0x2192cb0` → hook
  `hkSendPrepared(void* self /*RCX*/, void* request /*RDX*/, int64 msCanWait /*R8*/)`.

ImageBase `0x140000000`. `.text` is the signature scan window; `.pdata` is the x64 unwind table
(`RUNTIME_FUNCTION{begin,end,unwind}` per function) = an instant index of every function's bounds.

---

## 2. Tools you need

| Tool | Why |
| --- | --- |
| **Visual Studio Build Tools (MSVC `cl`, x64)** | Compile the DLL + launcher. `dll/build.bat` finds VS via `vswhere`, calls `vcvars64`, compiles `engine_tl.c` (as C) + `patchgram.cpp` + MinHook into `Patchgram.dll`. `launcher/build.bat` builds the injector. |
| **MinHook** | x64 inline hooks. Vendor it: `git clone https://github.com/TsudaKageyu/minhook dll/minhook`. |
| **A throwaway `Telegram/` (Telegram.exe 6.9.3 + modules)** | RE + test target. Gitignored — never commit. |
| **IDA Pro** (x64) | Decompile/disasm, confirm sites, derive AOBs. tdesktop source speeds this up. |
| **python3 + pefile + capstone** (`pip install pefile capstone`) | The RE toolkit in `tools/`: `retool.py` (.pdata/xref/bytes/sig), `disasm.py`, `find_ctor.py`, `resolve_ctor.py`, `xrefindex.py`, `dump_exc.py`, `dump_tl_layout.py`. Venv recommended. |
| **Flutter SDK** (only to touch the GUI) | `gui_flutter/` patcher. Not needed to author DLL patches. |

---

## 3. The two hooks + buffer access (the leverage)

The DLL resolves both hooks at load (version-resilient): find a unique log/literal **string** in `.rdata`
→ find the `lea reg,[rip+disp32]` that references it (`retool.py` xref; encoding `48|4C 8D /r` modrm
`rm=101` + disp32) → walk up to the enclosing function via `RtlLookupFunctionEntry`/`.pdata` → MinHook it.
If the anchor strings change, it falls back to the RVAs above (`PatchgramHook.log` prints `RESOLVE … via
anchor` or `RVA fallback`).

Inside the hooks (`dll/patchgram.cpp`):
- `hkTryToReceive` walks `SessionData`'s received `std::vector<Response>` (offsets
  `PG_SESSION_PRIVATE_DATA_OFFSET 0x28` → `RECEIVED_BEGIN 0xc0`/`END 0xc8`, `RESPONSE_SIZE 0x18`, reply at
  `RESPONSE_REPLY_OFFSET 0x0`) and calls `pg_apply_response(resp)` per item.
- `hkSendPrepared` reads the `SerializedRequest` (request data ptr at `RDX`, buffer at offset `0x0`,
  `requestId` at `0x20`, TL body at word index `PG_SERIALIZED_REQUEST_BODY_POSITION = 8`) and calls
  `pg_apply_request(req)`; returning **without** forwarding to the original = a clean request drop.

**Read a buffer the Qt5 way** (never the Qt6 way):
```c
int32_t wc; uint32_t* words = pg_qvec_data(container, &wc);   // container = &reply / request-data+0x0
bool ownEdit = pg_qvec_unshared(container);                   // ref==1 → safe in place
int32_t cap  = pg_qvec_capacity(container);                   // Qt5 alloc (31-bit)
pg_qvec_set_size(container, new_wc);                          // publish new size (writes d+4)
```
A freshly received reply / freshly built request is `ref==1`. Refuse to edit a shared (`ref!=1`) buffer.
Grows must fit `alloc`, or `realloc` the `QArrayData` only when `ref==1` (see `pg_autoload_append_emoji`).
Validate the rewrite re-decodes to exactly its length; revert on failure. **Never destabilise the client.**

---

## 4. How to author a **dll** (runtime) patch

1. **Identify the TL object**: enable the logger (default on), reproduce, read `PatchgramHook.log` — every
   request/response is fully-decoded TL (`engine_tl.c` + `tl_schema.c.inc`). Find the constructor + field.
2. **Confirm the schema** in `tl_schema.c.inc` / tdesktop `scheme.tl` (layer 227).
3. **Pick the side** and mirror an existing rewriter in [`dll/engine_patches.c`](../dll/engine_patches.c):
   - response rewrite/rebuild → `pg_gift_spoof` / `pg_gift_unique_rebuild`
   - response inject → `pg_inject_hidden_gifts`
   - capture a doc by id → `pg_unique_capture`
   - response field force / inject → `pg_account_freeze`, `pg_strip_noforwards`, `pg_fact_check`
   - request drop / field force → branches in `pg_apply_request` (`pg_apply_request` near the bottom of the
     file: always-offline, no-phone, block-typing/read, disable-ads, emoji autoload).
4. **Write the handler** using `pg_qvec_*` for all buffer access and the TL walker for fields. Gate on a
   global flag and `pg_logf(...)` (capped). Add its call to `pg_apply_response` or `pg_apply_request`.
5. **Config**: parse your key in `pg_config_load` (reads `PatchgramRuntime.json`) into the global. Reuse the
   **same key names as the macOS engine** where a macOS equivalent exists, so configs/UI stay aligned.
6. **GUI** (optional): add the toggle/fields in `gui_flutter/lib` so the patcher writes the key.
7. **Build + test** (§6).

Some host-side hooks (not pure TL) also live in `patchgram.cpp`: `setFlags` hook (peer badge, bot verify,
level rating, local premium, attached channel), `QLocale::toString` hook (custom balance/userID), self-phone
hook. Add new host hooks there with MinHook, gated and reverted on toggle-off.

---

## 5. How to author a **binary** (AOB byte-patch)

For local checks/limits not on the wire (999 accounts, recent stickers, sensitive blur, spoilers,
open-links, premium effects, hide-stories client half, TTL). All are **reversible `PgBytePatch`** structs in
[`dll/patchgram.cpp`](../dll/patchgram.cpp).

1. **Find the function** in tdesktop `v6.9.3` source, then in `Telegram.exe` with IDA (or `tools/retool.py`
   + `disasm.py`). Decompile to confirm the exact instruction.
2. **Decide the minimal, same-length edit** for **x64** (e.g. flip `jcc`→`jmp 0xEB`, `and reg,1`→`and reg,0`,
   prologue→`xor eax,eax; ret`, `mov imm32`). Match the macOS arm64 intent, re-encoded for x64.
3. **Derive the AOB**: `PG_<NAME>_PAT` bytes + `PG_<NAME>_MASK` (`0xFF` fixed / `0x00` wildcard over
   rip-relative disps & call rels), the `patched` bytes, the in-pattern offset, and `expectedOccurrences`.
   Verify uniqueness in `.text` (`retool.py`). Examples to copy: `g_recentPatch`, `g_blurPatch`,
   `g_spoilPhotoPatch`, `g_acc1Patch`..`g_acc4Patch`, `g_links1Patch`, `g_storiesUserPatch`.
4. **Register it**: add the `PgBytePatch g_<name>Patch = {…}` and call `pg_byte_patch_apply(&g_<name>Patch,
   <enabled>)` in the toggle-apply path (search `pg_byte_patch_apply`). The applier finds + overwrites each
   occurrence and reverts on disable.
5. **Build + test** (§6).

---

## 6. Build + test

```bat
:: from any shell — vendors MinHook first
git clone https://github.com/TsudaKageyu/minhook dll/minhook
dll\build.bat            :: -> Patchgram.dll (x64, /MT static CRT, imports only KERNEL32)
launcher\build.bat       :: -> the injector/launcher
```
- Can't overwrite `Patchgram.dll` while it's injected into a running Telegram — close Telegram (or build to
  a new name) first.
- Run: inject via `launcher/`, or place the launcher per its README. On success `PatchgramHook.log` appears
  next to `Telegram.exe` with `RESOLVE … via anchor` + decoded request/response lines. `RVA fallback` means
  the anchor strings changed → re-derive signatures (`tools/retool.py`, update `tools/signatures.md`).
- Config: `PatchgramRuntime.json` next to `Telegram.exe` (same keys the macOS engine reads); missing file →
  defaults (logger on, rewriters off).

---

## 7. RE recipes (Windows)

- **`.pdata` enumeration**: parse `RUNTIME_FUNCTION` (3 DWORD RVAs) for ~all function bounds cheaply
  (`tools/retool.py`, `dump_exc.py`) — avoids a multi-hour IDA pass.
- **String-anchor → function**: unique string in `.rdata` → `lea reg,[rip+disp32]` xref in `.text`
  (`48|4C 8D /r`, modrm `rm=101`) → `RtlLookupFunctionEntry`/`.pdata` to the function start. `retool.py`
  does string/xref/bytes/signature; `find_ctor.py`/`resolve_ctor.py` locate TL constructor handling.
- **Cross-validate** any function two ways (anchor + structural) before trusting it; record RVA, ≥16 entry
  bytes, and an AOB signature in `tools/signatures.md`; struct offsets in `tools/offsets.md`.
- **Offsets**: the source is identical to macOS, but MSVC vs clang packing differs and **Qt is Qt5**, so
  verify each offset against the binary before use (see the verified set in `tools/offsets.md`).

---

## 8. Golden rules

1. **Local only** — never mutate server data.
2. **Qt5, not Qt6** — always go through `pg_qvec_*`; the macOS inline `{ptr@8,size@0x10}` offsets are wrong.
3. **Validate + revert on failure**; refuse shared (`ref!=1`) buffers; a patch must never crash the client.
4. **x64 ABI** — RCX/RDX/R8/R9 + shadow space; hooks are `__fastcall`; byte-patches are x64 encodings.
5. **Pin RE facts to `v6.9.3`**; re-derive signatures on a new Telegram version instead of hardcoding RVAs.

## 9. File map

| Path | What |
| --- | --- |
| `dll/engine_patches.c` | All runtime rewriters (`pg_apply_response` / `pg_apply_request` + per-patch fns). |
| `dll/patchgram.cpp` | Hook resolver, MinHook install, the two hook callbacks, host-side hooks, **`PgBytePatch` AOB engine** + all byte-patches, Qt5 decode, config load. |
| `dll/engine_tl.c` / `engine_tl.h` / `tl_schema.c.inc` | Portable TL decoder + schema (layer 227). |
| `dll/patchgram_offsets.h` | Verified Qt5/x64 offsets + `pg_qvec_*` helpers + fallback RVAs. |
| `launcher/launcher.c` + `build.bat` | DLL-injection launcher. |
| `gui_flutter/` | Flutter patcher GUI (writes `PatchgramRuntime.json`). |
| `tools/` | RE toolkit (`retool.py`, `disasm.py`, `find_ctor.py`, …) + `signatures.md`, `offsets.md`. |
| `NOTES.md` | Living port status + RE master doc. |
| `patchlist.md` / `patchlist_ru.md` / `README.md` | Human patch list + per-patch code links. |
