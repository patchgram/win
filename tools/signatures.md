# RE findings — Telegram.exe 6.9.3 (x64), ImageBase 0x140000000

Method: parse `.pdata` (327,752 functions) for bounds, find a unique log-string in `.rdata`, find the
`lea reg,[rip+disp]` in `.text` that references it, take the enclosing `.pdata` function. All via
`re/retool.py` (no full IDA pass needed). RVAs are file/module-relative (add ImageBase for VA).

## The two MTProto hooks ✅ located + cross-validated

### MTP::details::Session::sendPrepared(this, SerializedRequest request, crl::time msCanWait)
- **RVA `0x2192cb0`** (VA `0x142192cb0`), func bounds `[0x2192cb0, 0x21931e7]`.
- ABI (Win x64): RCX=this(Session*), RDX=request(&SerializedRequest), R8=msCanWait(int64).
- Anchors (both resolve to this fn → high confidence):
  - "MTP Info: adding request to toSendMap, msCanWait %1" @ .rdata RVA `0x7770190`
  - "MTP Info: added, requestId %1" @ .rdata RVA `0x7770098`
- Entry bytes (32): `48 89 5c 24 20 55 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 d9 48 81 ec c0 00 00 00 48 8b 05 ed`
  - `mov [rsp+20],rbx; push rbp/rsi/rdi/r12-r15; lea rbp,[rsp-0x27]; sub rsp,0xc0; mov rax,[rip+..]`
  - volatile: the `48 81 ec c0..` frame size (0xc0) and the `48 8b 05 <disp>` rip-disp → wildcard those.

### MTP::details::Session::tryToReceive(this)
- **RVA `0x2193a50`** (VA `0x142193a50`), func bounds `[0x2193a50, 0x2193e7e]`.
- ABI (Win x64): RCX=this(Session*). (macOS engine labels it "SessionPrivate::tryToReceive" — same fn:
  it drains `_data->haveReceivedMessages()`; our hook runs BEFORE the original, which `base::take`s them.)
- Anchor: "Session Error: can't receive in a killed session" @ .rdata RVA `0x776ff28` (unique).
- Entry bytes (32): `48 89 4c 24 08 53 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 68 48 8b f9 80 79 48 00 0f 84 b1 00`
  - `mov [rsp+8],rcx; push rbx/rbp/rsi/rdi/r12-r15; sub rsp,0x68; mov rdi,rcx; cmp byte [rcx+0x48],0; je ..`
  - so `_killed` is at **Session+0x48**. volatile: the `0f 84 <rel32>` je target → wildcard.

## Recommended runtime resolver (version-resilient, better than a prologue AOB)
The push-prologues above are NOT unique in a 94 MB .text. Instead resolve at runtime by the unique
**log string + xref**, then get the function start from Windows' own unwind data:
1. Scan the module's `.rdata` for the anchor C-string → its VA.
2. Scan `.text` for `REX.W 8D /r` rip-lea (`48|4C 8D [05|0D|15|1D|25|2D|35|3D] disp32`) whose
   `target = lea_va + 7 + disp32 == string_va`.
3. `RtlLookupFunctionEntry(xref_va, &imgbase, nullptr)` → `RUNTIME_FUNCTION{BeginAddress}` = fn start.
4. Hook the fn start (MinHook).
Fallback for the exact 6.9.3 build: hook `module_base + RVA` directly (RVAs above).

This survives updates as long as the log string + a rip-lea to it exist (very stable). Re-derive only if
Telegram changes/removes the log line.

## Offsets — ✅ ALL VERIFIED on x64 (see `offsets.md` for full evidence)
Disassembled both functions (`re/disasm.py`) + cross-referenced v6.9.3 source. Key results:
- `Session`: `_data` @ `this+0x28` (same as macOS), `_killed` @ `this+0x48`, `_instance` @ `this+0x10`.
- received `std::vector<Response>` in `SessionData`: first/last @ **`_data+0xc0/0xc8`** (macOS 0x120/0x128).
- `Response` (`{mtpBuffer reply; uint64 outerMsgId; int32 requestId}`): **stride 0x18**, `requestId` @
  **`resp+0x10`** (macOS 0x28 / 0x20). `RequestData::requestId` @ **`+0x20`** (macOS 0x30).
- **⚠️ The Windows build is Qt 5.15.19, not Qt6.** `mtpBuffer`/`QVector`/`QString` is a **single 8-byte
  COW pointer** `d`, not Qt6's 24-byte `{d,ptr,size}`. size@`d+4`, data@`d + *(int64*)(d+0x10)`. This is
  why every struct above is smaller than its macOS counterpart, and it changes the whole TL engine port.

## How to reproduce / continue
```
re/.venv/bin/python re/retool.py enum
re/.venv/bin/python re/retool.py strings "<anchor>"
re/.venv/bin/python re/retool.py xref 0x<stringRVA>
re/.venv/bin/python re/retool.py func 0x<xrefRVA>
re/.venv/bin/python re/retool.py bytes 0x<funcRVA> 48
```
Next anchors to chase for the byte-patch class (each needs its own string/const anchor or IDA):
recent-stickers limit, 999 accounts, premium flags, monetization, etc. (see the macOS rule list).

## Custom Stars / Custom TON — `CreditsAmountFromTL(MTPStarsAmount&)` ✅ located + ABI solved

- **Single function** handles BOTH stars and ton on Windows (one body, internal branch on TL ctor id).
  macOS had two separate arm64 patch entries; on x64 they collapse to ONE entry point.
- **RVA `0x115c470`** (VA `0x14115c470`), bounds `[0x115c470, 0x115c5a3]`, **size 307 bytes**, 21 callers.
  (`0x115c5b0` is the inverse `StarsAmountToTL` — NOT a target.)
- **x64 ABI = sret (hidden pointer), NOT RAX:RDX.** `CreditsAmount` is 16 bytes
  (`int64 _ton:2 | _whole:62` in word0; `int64 _nano` in word1 — see core/credits_amount.h).
  - **RCX = &return slot** (caller's `CreditsAmount` local), **RDX = &MTPStarsAmount**.
  - Function writes `[rcx+0]=(whole<<2)|tonflag`, `[rcx+8]=nano`, returns `rax=rcx`.
  - Verified at caller 0x55dd80: `lea rcx,[rbp+0x1b0]; lea rdx,[rsi+0x18]; call 0x115c470`.
  - Stars path: `shl rcx,2; mov [rbx],rcx` (ton bits=0). Ton path: `... or rax,1; mov [rbx],rax`.
    This packing is IDENTICAL to the macOS arm64 `(value<<2)|ton` scheme — only the ABI (sret) differs.
- **VALUE-DEPENDENT PATCH (23 bytes, overwrites entry @ 0x115c470):**
  for configured V, imm = `((V & ((1<<62)-1)) << 2) | tonflag`  (tonflag 0=stars, 1=ton):
  ```
  31 c0                         xor   eax,eax
  48 89 41 08                   mov   [rcx+8],rax        ; nano = 0
  48 b8 <imm64 LE>              mov   rax, imm64         ; (V<<2)|tonflag  <-- V encoded here (offset +8..+15)
  48 89 01                      mov   [rcx],rax          ; word0
  48 89 c8                      mov   rax,rcx            ; return sret ptr
  c3                            ret
  ```
  V=999 stars → imm 0xf9c: `31 c0 48 89 41 08 48 b8 9c 0f 00 00 00 00 00 00 48 89 01 48 89 c8 c3`
  V=999 ton   → imm 0xf9d: `31 c0 48 89 41 08 48 b8 9d 0f 00 00 00 00 00 00 48 89 01 48 89 c8 c3`
  23 « 307 → fits trivially; pad remainder with 0xCC or leave (entry is only reached via call → ret returns).
  Patch is a leaf (no new frame) so original .pdata unwind is irrelevant.
- **UNIQUE AOB (entry @ 0x115c470), 24 bytes, 1 match in .text:**
  `40 53 48 83 ec 40 8b 42 08 48 8b d9 3d e0 e3 ae 74 74 37 3d a3 b4 b6 bb`
  = push rbx; sub rsp,0x40; mov eax,[rdx+8]; mov rbx,rcx; cmp eax,0x74aee3e0(ton); je; cmp eax,0xbbb6b4a3(stars)
  (16-byte prefix already unique; 12-byte prefix collides w/ a sibling TL-match at 0x10785d0 — use ≥16B.)
- ⚠️ Stars & Ton are MUTUALLY EXCLUSIVE here: one entry, so enabling both is contradictory. Pick one
  tonflag/value to install. Forcing stars makes ton inputs also return the stars value, and vice-versa.

## ⚠️ Monetization patches (disable_monetization) — x64 portability assessment

macOS `binary.config.disable_monetization` arm64 patches do NOT port cleanly to x64.
Root cause: Clang (macOS) emits clean leaf accessors (ldr+ubfx / parallel `and #mask`), so a
1–2-occurrence AOB neutralizes premium reads. MSVC (Win) **inlines** the same `isPremium()` /
flag-spread everywhere, producing dozens of register-allocation variants. No unique safe AOB.

Measured on .text:
- premium read `[reg+0x1a8] & 0x4000`: 42 `mov`-form sites (+`bt rax,0xe` ×27, +`movzx`/`shr` forms);
  35 distinct 3-insn byte windows; best-case window repeats only 5×. NO clean 2-occurrence leaf.
- `peerColorCollectible` ctor compare `cmp eax,0xb9c0639a`: 13 sites (not unique).
Conclusion: force-premium-false / collectible-empty cannot be shipped as safe byte-patches on x64.
The `premiumPossibleValue` producer (0x1f98eb0, reads [user+0x60] then [+0x1a8]&0x4000) is the
"Local premium" site — DO NOT touch for monetization. getAppConfig poison (61e3f854→7f7f1234):
NOT ported — would break appConfig and the whole client.

## Custom account settings FOUNDATION — `UserData::setFlags` / `ChannelData::setFlags` ✅ located

The macOS engine HOOKS `UserData::setFlags(peer, uint32 flags)` and writes custom values after the
original runs (engine.c.template `patchgram_user_set_flags` @2987). Windows equivalents found by
decompiling `PeerData::setStoriesHidden` (FN 0x13cb4e0, panic string
"...setStoriesHidden for non-user/non-channel." @ data_peer.cpp:1647) which dispatches to BOTH setters.

### `UserData::setFlags(UserData* this, UserDataFlags which)` — **RVA 0x14028e0** (VA 0x1414028e0)
- bounds [0x14028e0, 0x1402c10], size 0x330. **ABI: RCX = this(UserData*), EDX = new 32-bit flags.**
- Confirmed shape (the `Data::Flags<>::set` diff+store+notify):
  ```
  mov  ebx, edx              ; new flags (32-bit)
  mov  r15, rcx              ; this
  xor  edi, [rcx+0x1a8]      ; changed = new ^ old        (flags word @ this+0x1a8, DWORD)
  ... (Deleted/Forum teardown side-effects keyed on `changed`) ...
  mov  ecx, [r15+0x1a8]      ; old
  and  eax, 0x2000 / btr ebx,0xd / or ebx,eax   ; Self bit is sticky (preserved from old)
  xor  eax, ecx ; je skip    ; if (new==old) no notify
  mov  [r15+0x1a8], ebx      ; *** STORE new flags ***
  lea  rcx, [r15+0x1b0]      ; &_changes (rpl::event_stream right after flags)
  call 0x1404d5280           ; _changes.fire({value=new, diff=changed})   ← NOTIFY
  ```
- 21 callers (TL user parser, addFlags/removeFlags, setStoriesHidden, setNoForwardsFlags @0x1402cb0…).
  setNoForwardsFlags independently proves ABI: `mov edx,[rcx+0x1a8]; and edx,0x9fffffff; or edx,..; call 0x14028e0`.
- **UNIQUE AOB (22 bytes, 1 match in .text):**
  `40 53 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 28 8b da 4c 8b f9`
  = push rbx/rbp/rsi/rdi/r12-r15; sub rsp,0x28; mov ebx,edx; mov r15,rcx.
  (17B push-prologue prefix alone = 19 matches; the `8b da 4c 8b f9` tail is the discriminator.)

### `ChannelData::setFlags(ChannelData* this, ChannelDataFlags which)` — **RVA 0x1200000** (VA 0x141200000)
- bounds [0x1200000, 0x12009e0]. **ABI: RCX = this(ChannelData*), RDX = new 64-bit flags.**
  Channel flags @ [this+0x1a8] are a **QWORD** (ChannelDataFlags=uint64), vs UserData's DWORD.
  Same store/notify: `xor rax,[r13+0x1a8]; mov [r13+0x1a8],rbx; lea rcx,[r13+0x1b0]; call 0x1404d5280`.
- 24 callers. **UNIQUE AOB (36 bytes, 1 match):**
  `48 89 4c 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 58 48 8b da 4c 8b e9 45 33 e4 45 8b fc`

### Flag bit positions in [peer+0x1a8] — cross-validated against .text (UserDataFlag enum, data_user.h)
Empirical `test [reg+0x1a8],imm` counts confirm the enum (anchors Self=0x2000 ×199, Premium=0x4000 ×79):
- **Verified = bit3 = 0x8** (×2 reads), **Scam = bit4 = 0x10** (×3), **Fake = bit5 = 0x20** (enum; flanked by
  confirmed Verified/Scam — isFake reads load-then-mask so no disp-adjacent imm, but position is certain).
- Also confirmed: MutualContact=0x2, Deleted=0x4, Support=0x400, Forum=0x8000000, StoriesHidden=0x40000.

## Fragment collectible-phone GATE — `Info::Profile::IsCollectiblePhone` ✅ LOCATED (2026-06-21)

The macOS Fragment-phone display hooks `Info::Profile::IsCollectiblePhone(user)→bool` to return true for self
so the profile phone row renders as a Fragment collectible (link → `fragment.getCollectibleInfo`). The Windows
DLL previously only hooked `PhoneOrHiddenValue` @0x1d7ac30 — that BUILDS the phone text but does NOT gate the
collectible branch. The actual gate is now found.

### `Info::Profile::IsCollectiblePhone(not_null<UserData*> user)` — **RVA 0x1d40050** (VA 0x141d40050)
- bounds [0x1d40050, 0x1d402c0], size 624. **ABI: RCX = user(UserData*). Returns bool in AL** (`movzx eax,bl; ret`).
- **What it checks (source-confirmed, info_profile_phone_menu.cpp:118):** NOT a UserData flag bit. It:
  1. `user->session().appConfig().get<std::vector<QString>>("fragment_prefixes", {"888"})` — nav chain
     `[rcx+0x10]→[+0]→[+0x10]→[+0x78]` (user→session→appConfig); fatal int3 if appConfig null (@0x1d40299).
  2. reads `user->phone()` = the QString `d` at **user+0x218** (`add rbx,0x218; mov rax,[rbx]`; same offset
     PhoneOrHiddenValue uses at 0x1d7ad17 `lea r8,[rbx+0x218]`).
  3. `ranges::any_of(prefixes, [&](p){ return phone.startsWith(p); })` — loop @0x1d401d0 calling Qt5
     QString::startsWith @0x5310da0 (reads `[d+4]`=size, `(char*)d+[d+0x10]`=data — Qt5 COW pattern).
- **Exactly 2 callers** (matches source — strong confirmation):
  - `0x1d7ac30` = PhoneOrHiddenValue lambda: `call 0x1d40050; test al,al; je <plain-phone>` → if true builds
    the `internal:collectible_phone/` link (info_profile_values.cpp:151).
  - `0x1d402c0` = AddPhoneMenu: `if (isSelf() || !IsCollectiblePhone) return;` — confirmed by the self-flag
    read right before the call: `mov eax,[user+0x1a8]; and eax,0x2000; jne <return>` (Self=0x2000 @ user+0x1a8,
    cross-confirming that flag), then `mov rcx,rbx(user); call 0x1d40050; test al,al; je <return>`.
- **UNIQUE entry AOB (35 bytes, 1 match in .text):**
  `40 55 53 56 57 41 56 48 8b ec 48 81 ec 80 00 00 00 48 8b d9 48 8b 41 10 48 8b 08 48 8b 41 10 48 8b 78 78`
  = push rbp/rbx/rsi/rdi/r14; mov rbp,rsp; sub rsp,0x80; mov rbx,rcx; (session→appConfig nav chain).
  (The 23-byte nav-chain core alone = 2 matches; the full prologue is the discriminator → unique.)

### Proposed hook (return-true-for-self)
- **Target RVA 0x1d40050.** MinHook trampoline, `bool(__fastcall*)(void* user)`; entry-byte sanity-check the
  35-byte AOB. Body: read self-id / self-flag from RCX=user; if self (`*(u32*)(user+0x1a8) & 0x2000`), return 1;
  else `return original(user)`. Self-gated so non-self profiles keep stock behavior.
  (Mirrors the existing setFlags/PhoneOrHiddenValue self-detection: Self bit 0x2000 @ user+0x1a8.)
- ⚠️ GUARD (per macOS): do NOT force-true unless the `fragment.getCollectibleInfo` MTP response-ring is live —
  claiming collectible without the ring null-deref-crashes when the row's link is tapped/resolved. The gate
  location is the deliverable; the ring guard is added at impl time.
- Safe-by-default: MH_CreateHook at init, MH_EnableHook ONLY while the toggle (+ring) is on.

### Visual peer badge — proposed hook (foundation + simplest field)
Mirror macOS `patchgram_user_set_flags`: MinHook trampoline on **0x14028e0**, call original first, then
OR the configured badge bits into the live flags word and re-fire if changed:
```c
void hook_UserData_setFlags(void* user, uint32_t which) {
    g_orig_setFlags(user, which);                 // original stores [+0x1a8] & fires _changes
    if (!user || !peer_is_targeted(user)) return;
    uint32_t bits = 0;                            // from binary.visual.peer_badge config:
    if (cfg_verified) bits |= 0x8;                //   Verified
    if (cfg_scam)     bits |= 0x10;               //   Scam
    if (cfg_fake)     bits |= 0x20;               //   Fake
    uint32_t* flags = (uint32_t*)((char*)user + 0x1a8);
    uint32_t old = *flags;
    if ((old | bits) == old) return;              // already set -> nothing to do
    *flags = old | bits;                          // OR in badge bits (atomic enough; same-thread)
}
```
NOTIFY: directly ORing [+0x1a8] does NOT fire `_changes`, so views already painted won't refresh until
the next natural setFlags/repaint. SIMPLEST correct option = instead of writing [+0x1a8] yourself, call
the ORIGINAL again with the augmented value:  `g_orig_setFlags(user, (which | bits))` — but `which` here
is the post-Self-sticky value already stored, so re-calling with `*flags | bits` makes setFlags itself
do the store + `_changes.fire`, guaranteeing badge widgets repaint. Prefer the re-call form:
```c
    uint32_t cur = *(uint32_t*)((char*)user + 0x1a8);
    if ((cur | bits) != cur) g_orig_setFlags(user, cur | bits);   // re-entrant: ext path, new!=old fires once
```
(Re-entrancy is safe: the second call's new==old for everything except the badge bits, so it stores once
and fires once, then a third implicit call can't happen because (cur|bits)|bits==cur|bits → no change.)

### Safety (HOT PATH — fires on every user flag update)
- Reading + ORing [user+0x1a8] is safe: it's a 4-byte aligned field inside an already-constructed
  UserData (setFlags only ever runs on a live peer; `this`=RCX is non-null in all 21 call sites).
- setFlags runs on the main/messenger thread (Qt object); no cross-thread race on the flag word.
- RISK: the re-call form is re-entrant — MUST guard against infinite recursion. The `(cur|bits)!=cur`
  check is the guard: once bits are set, the predicate is false so no further re-call. Verify the target
  filter (`peer_is_targeted`) is cheap and null-safe; do it BEFORE any deref beyond the user ptr.
- Do NOT touch ChannelData::setFlags for the badge unless channel badges are also configured; its flags
  word is 64-bit (use uint64 + RDX), and bits differ (ChannelDataFlag enum, not UserDataFlag).
- Hook resolution: use the 22B unique AOB (or RtlLookupFunctionEntry on a known call site) → MinHook the
  fn start. RVA 0x14028e0 is the 6.9.3 fallback.

## UserData StarsRating + personal-channel fields (Qt5 in-place write targets) ✅ RE-CONFIRMED

Goal: write `_starsRating` (4×int32), `_personalChannelId` (int64), `_personalChannelMessageId` (int64)
in place after `UserData::setFlags`. Qt5 offsets derived TWO independent ways that AGREE:

### (A) Analytical (validated against the 3 known macOS Qt6 anchors)
Modeling member sizes — Qt6 QString=24B, Qt5 QString=8B, Data::Flags=24B, UsernamesInfo=32B,
std::vector=24B, unique_ptr=8B — and walking `UserData` (`data/data_user.h`) from the flags anchor
reproduces the macOS Qt6 offsets EXACTLY (`_starsRating`@0x2c0, `_personalChannelId`@0x2d0,
`_personalChannelMessageId`@0x2d8), which validates the model. Re-running with Qt5 QString=8B
(flags anchor 0x1a8) yields the Windows offsets below.

### (B) Disassembly of Data::ApplyUserUpdate @ RVA 0x1402fa0 (GROUND TRUTH)
This fn (a `setFlags` caller, in the userFull-apply region) inlines setStarsRating + setPersonalChannel
+ setBotManagerId. `user` = RBX/RDX; UserData Self-flag read at `[rax+0x1a8] & 0x2000` confirms the anchor.

setStarsRating (`if (_starsRating != value) { _starsRating = value; peerUpdated(this, 1<<39); }`):
```
0x1404109  movdqu xmm1, [rsp+0x70]        ; value = {level, stars, thisLevelStars, nextLevelStars}
0x1404125  movups xmm0, [rbx+0x230]       ; load current _starsRating (16 bytes)
0x1404131..0x140416d  4× int32 cmp        ; StarsRating::operator== (field-wise, =default)
0x140416f  movups [rbx+0x230], xmm1       ; _starsRating = value  (16-byte SSE store)
0x140417d  movabs r8, 0x8000000000        ; UpdateFlag::StarsRating = 1ULL<<39
0x140418e  call   peerUpdated
```
setPersonalChannel (`if (id!=.. || msg!=..) { id=..; msg=..; peerUpdated(this, 1<<35); }`):
```
0x1403dc1  movabs rdi, 0x800000000        ; UpdateFlag::PersonalChannel = 1ULL<<35
0x1403dcb  cmp    [rdx+0x240], rcx        ; _personalChannelId   != channelId  (int64)
0x1403dd4  cmp    [rdx+0x248], rax        ; _personalChannelMessageId != messageId (int64; MsgId=int64)
0x1403ddd  mov    [rdx+0x240], rcx        ; _personalChannelId   = channelId
0x1403de4  mov    [rdx+0x248], rax        ; _personalChannelMessageId = messageId
0x1403df9  call   peerUpdated
0x1403e29..0x1403e30  mov/[rdx+0x250]      ; _botManagerId (int64) — closes the layout, +0x250
```

### Qt5 x64 offsets on UserData (this = user ptr)
| field | Qt5 off | Qt6 (mac) | width | evidence |
| --- | --- | --- | --- | --- |
| `_starsRating` {level,stars,thisLevelStars,nextLevelStars} | **0x230** | 0x2c0 | 16B (4×int32) | movups [rbx+0x230] R/W @ 0x1404125/0x140416f, flag 1<<39 |
| `_personalChannelId` | **0x240** | 0x2d0 | int64 | cmp/mov [rdx+0x240] @ 0x1403dcb/0x1403ddd, flag 1<<35 |
| `_personalChannelMessageId` | **0x248** | 0x2d8 | **int64** (MsgId wraps int64; NOT int32) | cmp/mov [rdx+0x248] @ 0x1403dd4/0x1403de4 |
| (`_botManagerId`, next field) | 0x250 | 0x2e0 | int64 | mov [rdx+0x250] @ 0x1403e30 (boundary check) |

NOTE: the macOS engine treated `_personalChannelMessageId` as int32 — on this build (and per source,
`MsgId{int64 bare}`) it is **int64** at 0x248; `_botManagerId` follows at 0x250, so a full-qword write to
0x248 is correct and does NOT clobber a neighbor. Confidence: HIGH (two methods agree; disasm exact).

### Safety for in-place writes from a setFlags hook
- All three live inside an already-constructed UserData; setFlags only runs on live peers → writes safe.
- StarsRating: write all 16 bytes ([+0x230..+0x23f]); a partial write leaves a torn struct.
- personalChannelMessageId is int64 — write 8 bytes at +0x248 (sign/zero-extend the int32 wire value).
- These bypass the `_changes`/peerUpdated notify, so already-open profile widgets won't auto-repaint;
  to force a repaint, prefer re-driving the real setters or fire peerUpdated(1<<39 / 1<<35) yourself.
- Do NOT write 0x2c0/0x2d0/0x2d8 (those are Qt6/macOS) on Windows — that lands in unrelated later fields.

## Bot Verification (botVerifyDetails) — `UserData::setBotVerifyDetails` ✅ RE-CONFIRMED (idalib + capstone)

Goal: spoof the "verified by [bot]" badge (custom emoji + description) on a peer (esp. self), as macOS
Patchgram does via `UserData::setBotVerifyDetails`. Source: data_user.cpp:735; struct `Ui::BotVerifyDetails`
(unread_badge.h): `{ UserId botId@0; DocumentId iconId@8; TextWithEntities description@0x10; }`,
`operator bool() == (iconId != 0)`. `_botVerifyDetails` is a `std::unique_ptr<Ui::BotVerifyDetails>`.

### `UserData::setBotVerifyDetails(UserData* this, BotVerifyDetails byVal)` — **RVA 0x1402d80** (VA 0x141402d80)
- bounds [0x1402d80, 0x1402eb0], size 0x130. **ABI: RCX = this(UserData*), RDX = BotVerifyDetails* (by-value 0x20 struct passed by pointer).**
- Found via: callee of Data::ApplyUserUpdate (0x1402fa0) at call site 0x14040a4 (between _botManagerId@0x250
  store and _starsRating@0x230 store — matches source order setBotManagerId→setBotVerifyDetails→setStarsRating),
  and it uniquely carries `mov r8d, 0x40000` (UpdateFlag::VerifyInfo = 1<<18) at 0x1402e88.
- hexrays pseudocode (sub_141402D80) reproduces data_user.cpp:735 exactly: nullptr-clear / make_unique / *p=details branches, then peerUpdated(this, 0x40000).

### `_botVerifyDetails` UserData field offset (Qt5) = **0x228** — a `unique_ptr` raw pointer (8B)
- evidence: `mov rbx, [rsi+0x228]` (0x1402d9d, load current), `mov [rsi+0x228], 0` (clear), `mov [rsi+0x228], rbx`
  (set new). 0x228 = 0x230 - 8, exactly the slot before `_starsRating@0x230` (matches header field order:
  `_phone, _privateForwardName, _botVerifyDetails, _starsRating`). Confidence: HIGH.
- pointer is null when no verification; non-null => points to a heap BotVerifyDetails (0x20 bytes).

### BotVerifyDetails struct (Qt5) — sizeof 0x20, same as macOS
| field | off | width | evidence |
| --- | --- | --- | --- |
| botId (UserId) | 0x0 | int64 | `*v10 = *a2` / `mov [rcx],[rdi]` |
| iconId (DocumentId) | 0x8 | uint64 | `v10[1]=a2[1]`; `a2[1]` is the operator-bool test (iconId!=0) |
| description (TextWithEntities) | 0x10 | 16B | QString d-ptr @ +0x10, QList<EntityInText> @ +0x18 |
- description sub-layout proven by copy helpers: sub_14041FF70 (QString @+0, QtCore/qstring.h:1091 assert => **Qt-5.15.19**), sub_14041FE70 (QList @+8). So inside the struct: QString@0x10, QList@0x18.

### Heap identity (cross-CRT safety)
- alloc: `sub_14575644C(0x20)` = Telegram.exe's own `operator new` (MSVC retry+_callnewh+bad_alloc loop).
- free: `unk_1455469F0(ptr, 0x20)` = sized `operator delete` => `jmp 0x443d7d20` (statically-linked CRT free).
- ~description: `sub_1403FC250` (QString/QList ref-dec). The unique_ptr is created/destroyed entirely by
  Telegram.exe's CRT — so a raw-overwrite of [+0x228] with a foreign-heap pointer is NOT safe to let the
  app free; leak-the-old (don't free) is the only cross-CRT-safe direct write.

### Recommended spoof approach: HOOK setBotVerifyDetails (preferred) — NOT a raw field write
- Hook 0x1402d80 (MinHook), build a BotVerifyDetails on the stack {botId, g_configured_icon_id, description},
  and call g_orig_setBotVerifyDetails(user, &details) for targeted peers. This routes ALL allocation, the
  old-ptr free, the operator!= compare, AND the peerUpdated(VerifyInfo) repaint THROUGH Telegram's own CRT/
  setter — zero cross-CRT hazard, correct ownership, auto-repaint. Build the QString description with the
  existing Qt5-QString recipe (static QArrayData ref=-1) so the copy-ctor just ref-bumps (never frees our buffer).
- Direct field write from setFlags hook is NOT recommended for this field: it's a unique_ptr.
  * If [+0x228] is currently null: we'd have to operator-new a 0x20 struct on OUR heap and store it; when
    Telegram later overwrites/clears it, it frees OUR ptr with ITS delete => cross-CRT crash.
  * If non-null: overwriting without freeing leaks; freeing the old cross-CRT crashes.
  Both are worse than the hook. AVOID the direct write here.
