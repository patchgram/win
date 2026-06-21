// Patchgram for Windows — injected DLL (Telegram Desktop 6.9.3, x64).
//
// This is the FOUNDATION: it resolves the two MTProto hooks at runtime (version-resilient, via unique
// log-string + rip-lea xref + RtlLookupFunctionEntry), installs them with MinHook, and currently acts as
// an MTProto logger (proves the hooks land + the request/response buffers are readable). Porting the
// macOS engine's TL decoder/rewriter (engine.c.template) into the two callbacks turns the rest of the
// patch family on — the wire format is identical, only the hooking/ABI is Windows-specific.
//
// Build: see README.md (MSVC x64 + MinHook). No compiler needed on the end-user's machine — ship the DLL.

#include <windows.h>
#include <intrin.h>          // _ReturnAddress (return-address-gated hook)
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "MinHook.h"          // vendored or via vcpkg (see README)
#include "patchgram_offsets.h"
#include "engine_tl.h"        // portable MTProto TL decoder (ported from the macOS engine)
#include "engine_patches.h"   // config + runtime TL rewriters (ported, Qt5-adapted)

// ---- logging (mirror of the macOS PatchgramHook.log) ---------------------------------------------
// Cap the per-response TL decode the logger does on the MTProto thread. Above this, log only the header.
// Keeps normal traffic + gift/profile responses (<~1k words) fully decoded while never blocking the thread
// on a multi-thousand-word response (premiumPromo/config/dialogs) — that blocking intermittently crashed.
#define PG_LOG_MAX_DECODE_WORDS 1024
static FILE* g_log = nullptr;
static void plog(const char* fmt, ...) {
    if (!g_log) return;
    SYSTEMTIME t; GetLocalTime(&t);
    fprintf(g_log, "[%04d-%02d-%02dT%02d:%02d:%02d] ", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    va_list ap; va_start(ap, fmt); vfprintf(g_log, fmt, ap); va_end(ap);
    fputc('\n', g_log); fflush(g_log);
}

// C-callable bridge so the portable engine (engine_patches.c) writes to the same log file (one
// timestamped line per call). Declared `extern void pg_engine_log(const char*)` over there.
extern "C" void pg_engine_log(const char* line) { plog("%s", line); }

// ---- host allocator bridge (for the Qt5 resize-beyond-capacity writeback) ------------------------
// Telegram statically links the CRT, so its malloc/free use a private heap — we must allocate any
// buffer Telegram will later free from the SAME heap. The modern static UCRT routes malloc/free through
// GetProcessHeap(), so HeapAlloc/HeapFree(GetProcessHeap()) is interchangeable with its free — but ONLY
// if Telegram's buffers actually live there. pg_host_owns() proves that per-pointer (HeapValidate is a
// safe read-only check that returns FALSE for a foreign-heap block), so the engine can refuse to realloc
// rather than corrupt the heap when the assumption doesn't hold.
extern "C" void* pg_host_alloc(size_t n) { return HeapAlloc(GetProcessHeap(), 0, n); }
extern "C" void  pg_host_free(void* p)   { if (p) HeapFree(GetProcessHeap(), 0, p); }
extern "C" int   pg_host_owns(const void* p) {
    return (p && HeapValidate(GetProcessHeap(), 0, p)) ? 1 : 0;
}

// ---- PE helpers ----------------------------------------------------------------------------------
struct Section { uint8_t* start; size_t size; };
static uint8_t* g_module = nullptr;

static Section sectionByName(uint8_t* base, const char* name) {
    auto dos = (IMAGE_DOS_HEADER*)base;
    auto nt  = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        char nm[9] = {0}; memcpy(nm, sec->Name, 8);
        if (strcmp(nm, name) == 0)
            return { base + sec->VirtualAddress, sec->Misc.VirtualSize };
    }
    return { nullptr, 0 };
}

// Find a NUL-terminated ASCII needle inside a section; return its VA (in-memory address) or 0.
static uint8_t* findString(const Section& s, const char* needle) {
    size_t n = strlen(needle);
    if (!s.start || s.size < n) return nullptr;
    for (size_t i = 0; i + n <= s.size; ++i)
        if (memcmp(s.start + i, needle, n) == 0) return s.start + i;
    return nullptr;
}

// Find a rip-relative `lea reg,[rip+disp32]` in .text whose target == wantVA. Returns the lea addr or 0.
// Encoding: REX.W (0x48/0x4C[/0x49/0x4D]) + 0x8D + modrm(mod=00,rm=101 -> (b&0xC7)==0x05) + disp32.
static uint8_t* findRipLeaXref(const Section& text, uint8_t* wantVA) {
    for (size_t i = 0; i + 7 <= text.size; ++i) {
        uint8_t c = text.start[i];
        if ((c == 0x48 || c == 0x4C || c == 0x49 || c == 0x4D)
            && text.start[i+1] == 0x8D && (text.start[i+2] & 0xC7) == 0x05) {
            int32_t disp; memcpy(&disp, text.start + i + 3, 4);
            uint8_t* tgt = text.start + i + 7 + disp;
            if (tgt == wantVA) return text.start + i;
        }
    }
    return nullptr;
}

// Function start that contains `addr`, via the x64 unwind table (robust, no manual prologue scan).
static uint8_t* funcStart(uint8_t* addr) {
    DWORD64 imageBase = 0;
    auto rf = RtlLookupFunctionEntry((DWORD64)addr, &imageBase, nullptr);
    if (!rf) return nullptr;
    return (uint8_t*)(imageBase + rf->BeginAddress);
}

// Resolve a target by: anchor string (in .rdata) -> rip-lea xref (in .text) -> enclosing function.
// Falls back to module_base + rvaFallback if the string route fails.
static uint8_t* resolve(const char* name, const char* anchor, uintptr_t rvaFallback) {
    static Section rdata = sectionByName(g_module, ".rdata");
    static Section text  = sectionByName(g_module, ".text");
    uint8_t* str = findString(rdata, anchor);
    if (str) {
        uint8_t* xref = findRipLeaXref(text, str);
        if (xref) {
            uint8_t* fn = funcStart(xref);
            if (fn) { plog("RESOLVE %s via anchor -> %p", name, fn); return fn; }
        }
    }
    uint8_t* fb = g_module + rvaFallback;
    plog("RESOLVE %s anchor miss -> RVA fallback %p", name, fb);
    return fb;
}

// ---- runtime memory-patch (byte-patch / AOB) engine ---------------------------------------------
// The reusable applier for the byte-patch family (999 accounts, recent-stickers limit, monetization,
// sensitive blur, …). Each patch = an AOB (pattern + mask: 0xFF fixed / 0x00 wildcard) located in .text,
// then `patch` bytes written over each match via VirtualProtect. The HARD part per patch is *deriving*
// the x64 AOB — i.e. locating the function in the stripped 208 MB binary. macOS used IDA-derived vmaddrs;
// on Windows most of these functions have NO usable string/xref anchor (e.g. tdesktop's base::options
// reads values via a central registry, so the recent-stickers `cmp #20` can't be reached from the option
// id string) → deriving each AOB needs an IDA/idalib pass. This engine applies them once they exist.

// Masked AOB search in [hay, hay+haylen). mask[i]: 0xFF = must match pat[i], 0x00 = wildcard. Returns
// the first match offset or -1.
static long pg_mem_find(const uint8_t* hay, size_t haylen, const uint8_t* pat, const uint8_t* mask, size_t n) {
    if (!hay || !pat || n == 0 || haylen < n) return -1;
    for (size_t i = 0; i + n <= haylen; ++i) {
        size_t k = 0;
        for (; k < n; ++k) {
            uint8_t m = mask ? mask[k] : 0xFF;
            if (m && ((hay[i + k] ^ pat[k]) & m)) break;
        }
        if (k == n) return (long)i;
    }
    return -1;
}

// Write `n` bytes at `addr` through a temporary PAGE_EXECUTE_READWRITE, restoring the old protection.
static bool pg_mem_write(uint8_t* addr, const uint8_t* bytes, size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(addr, n, PAGE_EXECUTE_READWRITE, &old)) return false;
    memcpy(addr, bytes, n);
    DWORD tmp = 0; VirtualProtect(addr, n, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), addr, n);
    return true;
}

// Apply a byte-patch: find up to `expected` occurrences of `pat`/`mask` in .text and overwrite each with
// `patch` (same length). Returns the number patched. Logs the outcome. `name` is for diagnostics.
extern "C" int pg_mem_patch(const char* name, const uint8_t* pat, const uint8_t* mask,
                            const uint8_t* patch, size_t n, int expected) {
    static Section text = sectionByName(g_module, ".text");
    if (!text.start) { plog("MEMPATCH %s: no .text", name); return 0; }
    int applied = 0;
    for (size_t off = 0; off + n <= text.size && applied < expected; ) {
        long rel = pg_mem_find(text.start + off, text.size - off, pat, mask, n);
        if (rel < 0) break;
        uint8_t* at = text.start + off + rel;
        if (pg_mem_write(at, patch, n)) { applied++;
            plog("MEMPATCH %s: applied #%d at RVA %#llx", name, applied, (unsigned long long)(at - g_module)); }
        off += rel + 1;
    }
    if (applied != expected) plog("MEMPATCH %s: applied %d/%d (signature drift? re-derive AOB)", name, applied, expected);
    return applied;
}

// Self-test the engine on a private RWX buffer (validates masked find + protected write — never touches
// Telegram). Builds a buffer, finds a masked pattern, writes over it, verifies the result.
static void pg_mem_engine_selftest() {
    uint8_t* buf = (uint8_t*)VirtualAlloc(nullptr, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!buf) { plog("# MEMPATCH selftest: alloc failed"); return; }
    const uint8_t seed[] = { 0x48,0x83,0xf8,0x14, 0x90,0x90 };   // cmp rax,0x14 ; nop nop
    memcpy(buf + 10, seed, sizeof seed);
    const uint8_t pat[]  = { 0x48,0x83,0xf8,0x00 };               // cmp rax, <imm8>
    const uint8_t mask[] = { 0xFF,0xFF,0xFF,0x00 };               // wildcard the immediate
    long at = pg_mem_find(buf, 64, pat, mask, sizeof pat);
    int found_ok = (at == 10 && buf[13] == 0x14);
    const uint8_t newb[] = { 0x48,0x83,0xf8,0xC8 };               // cmp rax,0xC8 (20 -> 200)
    bool wrote = (at >= 0) && pg_mem_write(buf + at, newb, sizeof newb);
    int write_ok = wrote && buf[13] == 0xC8;
    plog("# MEMPATCH selftest: find_ok=%d write_ok=%d (engine ready for derived AOBs)", found_ok, write_ok);
    VirtualFree(buf, 0, MEM_RELEASE);
}

// ---- reversible byte-patch sites (config-toggled) -----------------------------------------------
// pg_mem_patch above is apply-only; the GUI toggles these live, so a site must be locatable ONCE and
// then flipped between Telegram's original byte and our patched byte on each config (re)load. We locate
// the AOB on first use (matching the ORIGINAL bytes), cache the address, then write origByte (disabled)
// or newByte (enabled) — so unticking the patch in the GUI restores the original instruction with no
// restart, exactly like the config-driven DLL patches.
struct PgBytePatch {
    const char*    name;
    const uint8_t* pat; const uint8_t* mask; size_t n;  // AOB (matches the original .text bytes)
    size_t         off;                                  // offset within the match where the patch starts
    const uint8_t* newBytes; size_t plen;                // bytes written when ENABLED (length plen, <=32)
    uint8_t        origCapture[32];                      // ORIGINAL bytes, captured on first scan (restore)
    uint8_t*       site;                                 // cached match address (NULL = not found yet)
    int            searched;                             // 0 until the first scan
};

static void pg_byte_patch_apply(PgBytePatch* p, bool enabled) {
    static Section text = sectionByName(g_module, ".text");
    if (!text.start) { plog("MEMPATCH %s: no .text", p->name); return; }
    if (!p->searched) {
        p->searched = 1;
        long rel = pg_mem_find(text.start, text.size, p->pat, p->mask, p->n);
        p->site = (rel >= 0) ? text.start + rel : nullptr;
        if (p->site) {
            memcpy(p->origCapture, p->site + p->off, p->plen);   // remember the originals for revert
            plog("MEMPATCH %s: located at RVA %#llx (%zu bytes)",
                 p->name, (unsigned long long)(p->site + p->off - g_module), p->plen);
        } else {
            plog("MEMPATCH %s: NOT FOUND (re-derive AOB)", p->name);
        }
    }
    if (!p->site) return;
    uint8_t* at = p->site + p->off;
    const uint8_t* want = enabled ? p->newBytes : p->origCapture;
    if (memcmp(at, want, p->plen) != 0 && pg_mem_write(at, want, p->plen))
        plog("MEMPATCH %s: %s (%zu bytes at RVA %#llx)", p->name,
             enabled ? "ENABLED" : "disabled", p->plen, (unsigned long long)(at - g_module));
}

// More recent stickers — StickersListWidget::collectRecentStickers. The collect lambda guards each push:
//   if (result.size() >= 20 && !OptionUnlimitedRecentStickers.value()) return;   // 20 = kRecentDisplayLimit
// x64 (Telegram 6.9.3): cmp rdx,0x14 ; jb <add> ; cmp byte[opt+8],0 ; jne.. ; cmp byte[opt],0 ; je..
// 200 (0xC8) won't fit a sign-extended cmp imm8, so instead of bumping the limit we flip the `jb` (0x72)
// to an unconditional `jmp` (0xEB): the size+option gate is always taken to the add path, so every recent
// sticker is collected ("unlimited-recent-stickers", matching the option's own name). Reverting writes
// 0x72 back. AOB anchors on `cmp rdx,0x14 ; jb ; cmp byte[rip+disp],0 ; jne` — unique in .text (verified).
static const uint8_t PG_RECENT_PAT[]  = { 0x48,0x83,0xFA,0x14, 0x72,0x00, 0x80,0x3D,0x00,0x00,0x00,0x00, 0x00,0x0F,0x85 };
static const uint8_t PG_RECENT_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0x00, 0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF };
static const uint8_t PG_RECENT_NEW[]  = { 0xEB };  // jb -> jmp
static PgBytePatch g_recentPatch = { "recent-stickers", PG_RECENT_PAT, PG_RECENT_MASK,
                                     sizeof PG_RECENT_PAT, 4, PG_RECENT_NEW, sizeof PG_RECENT_NEW, {0}, nullptr, 0 };

// Hide stories (client-side half) — UserData::setStoriesState + ChannelData::setStoriesState. Each setter
// dispatches on a story-state enum (1..5); state 1 is the "clear / no stories" case (`and` that clears the
// story bits at peer+0x1a8), and state 0 is an assert→int3. So to make every peer look story-less (kills
// the avatar story ring + the click-to-open that the request-drops alone don't remove) we force the state
// to 1, exactly like macOS's data.{user,peer}.stories_state.force_none (`mov w1,#1`). x64: overwrite
// `test edx,edx ; je <state0-assert>` (8 bytes) with `mov edx,1 ; nop ; nop ; nop` — execution then falls
// into the switch, `sub edx,1` -> 0 -> the state-1 clear path. Reverting restores the captured originals.
static const uint8_t PG_STORIES_NEW[] = { 0xBA,0x01,0x00,0x00,0x00, 0x90,0x90,0x90 };  // mov edx,1 ; nop*3
// user setter: 48 8B F9 (mov rdi,rcx) | 85 D2 0F 84 <rel32> (test;je) | 8B 99 A8 01 00 00 (mov ebx,[rcx+0x1a8])
static const uint8_t PG_STORIES_U_PAT[]  = { 0x48,0x8B,0xF9, 0x85,0xD2,0x0F,0x84,0x00,0x00,0x00,0x00, 0x8B,0x99,0xA8,0x01,0x00,0x00 };
static const uint8_t PG_STORIES_U_MASK[] = { 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
static PgBytePatch g_storiesUserPatch = { "hide-stories/user", PG_STORIES_U_PAT, PG_STORIES_U_MASK,
                                          sizeof PG_STORIES_U_PAT, 3, PG_STORIES_NEW, sizeof PG_STORIES_NEW, {0}, nullptr, 0 };
// channel setter: 85 D2 0F 84 <rel32> (test;je) | 48 8B 9F A8 01 00 00 (mov rbx,[rdi+0x1a8])
static const uint8_t PG_STORIES_C_PAT[]  = { 0x85,0xD2,0x0F,0x84,0x00,0x00,0x00,0x00, 0x48,0x8B,0x9F,0xA8,0x01,0x00,0x00 };
static const uint8_t PG_STORIES_C_MASK[] = { 0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
static PgBytePatch g_storiesChanPatch = { "hide-stories/channel", PG_STORIES_C_PAT, PG_STORIES_C_MASK,
                                          sizeof PG_STORIES_C_PAT, 0, PG_STORIES_NEW, sizeof PG_STORIES_NEW, {0}, nullptr, 0 };

// Sensitive blur — HistoryItem::isMediaSensitive (RVA 0x1a02df0). The method returns true when the item
// has an unavailable-reason equal to the QString "sensitive", which makes media blur locally. Forcing it
// to return false (overwrite the prologue with `xor eax,eax ; ret`) makes nothing look sensitive → no
// local blur (matches macOS's `mov w0,#0 ; ret` over the prologue). Stack-safe: patched at the entry
// before any push/sub. AOB = the unique prologue (verified single match in .text).
static const uint8_t PG_BLUR_PAT[]  = { 0x48,0x89,0x5C,0x24,0x18, 0x48,0x89,0x6C,0x24,0x20, 0x56,0x57,0x41,0x56,
                                        0x48,0x83,0xEC,0x30, 0x48,0x8B,0xF9, 0x48,0x8B,0x51,0x28 };
static const uint8_t PG_BLUR_MASK[] = { 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
                                        0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_BLUR_NEW[]  = { 0x31,0xC0,0xC3, 0x90,0x90 };  // xor eax,eax ; ret ; nop ; nop
static PgBytePatch g_blurPatch = { "sensitive-blur", PG_BLUR_PAT, PG_BLUR_MASK,
                                   sizeof PG_BLUR_PAT, 0, PG_BLUR_NEW, sizeof PG_BLUR_NEW, {0}, nullptr, 0 };

// Disable media spoilers — Data::CreateMedia (photo path fn 0x19efd30, document path fn 0x19f00c0). Both
// extract the spoiler flag as bit 3 of the media-flags dword (`shr,3 ; and,1`) and hand the bool to the
// media-creation call. Flipping the `and reg,1` mask to `and reg,0` forces the spoiler bool to 0, so
// created media never carries a spoiler → renders normally (matches macOS's `mov reg,#0`). 1 byte each,
// same length, touches only the spoiler bool. AOBs verified unique in .text.
static const uint8_t PG_SPOIL_PHOTO_PAT[]  = { 0x8B,0x6F,0x10, 0xC1,0xED,0x03, 0x40,0x80,0xE5,0x01 };
static const uint8_t PG_SPOIL_PHOTO_MASK[] = { 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_SPOIL_DOC_PAT[]    = { 0x8B,0xC1, 0xC1,0xE8,0x03, 0x24,0x01, 0x88,0x44,0x24,0x3D };
static const uint8_t PG_SPOIL_DOC_MASK[]   = { 0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_SPOIL_ZERO[]       = { 0x00 };  // and reg,1 -> and reg,0
static PgBytePatch g_spoilPhotoPatch = { "spoilers/photo", PG_SPOIL_PHOTO_PAT, PG_SPOIL_PHOTO_MASK,
                                         sizeof PG_SPOIL_PHOTO_PAT, 9, PG_SPOIL_ZERO, 1, {0}, nullptr, 0 };
static PgBytePatch g_spoilDocPatch   = { "spoilers/doc", PG_SPOIL_DOC_PAT, PG_SPOIL_DOC_MASK,
                                         sizeof PG_SPOIL_DOC_PAT, 6, PG_SPOIL_ZERO, 1, {0}, nullptr, 0 };

// Disable premium effects — HistoryView::Sticker::checkPremiumEffectStart (RVA 0x1767360, void). Early-
// return at the entry (`sub rsp,0x28` -> `ret`) so the method does nothing → premium sticker/effect
// animations never start (matches macOS's entry->ret). Stack-safe: `ret` runs before the sub, so the
// return address is on top of a pristine stack. AOB anchors on the entry + the packed-flags read.
static const uint8_t PG_PREFF_PAT[]  = { 0x48,0x83,0xEC,0x28, 0x0F,0xB6,0x91,0x8D,0x00,0x00,0x00, 0xF6,0xC2,0x02 };
static const uint8_t PG_PREFF_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF };
static const uint8_t PG_PREFF_NEW[]  = { 0xC3 };  // ret
static PgBytePatch g_preffPatch = { "premium-effects", PG_PREFF_PAT, PG_PREFF_MASK,
                                    sizeof PG_PREFF_PAT, 0, PG_PREFF_NEW, sizeof PG_PREFF_NEW, {0}, nullptr, 0 };

// Disable TTL (view-once media) — two reversible byte-patches forcing ttl_seconds to 0 (matches the macOS
// data.create_media / data.media_file force_zero patches). The self-destruct-timer clear (macOS's createView
// hook half) is hook-tier and not included. Same-length, leaf-local, AOBs verified unique in .text.
// (b1) Data::CreateMedia document path (RVA 0x19f00c0): `mov edx,[rax]` (the vttl_seconds() read) -> `xor
//      edx,edx`, so Args.ttlSeconds is built as 0 → new view-once media carries no timer.
static const uint8_t PG_TTL_CREATE_PAT[]  = { 0x41,0xF6,0xC0,0x04, 0x74,0x0D, 0x48,0x8D,0x41,0x44,
                                              0x48,0x85,0xC0, 0x74,0x04, 0x8B,0x10 };
static const uint8_t PG_TTL_CREATE_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
                                              0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF };
static const uint8_t PG_TTL_CREATE_NEW[]  = { 0x31,0xD2 };                  // mov edx,[rax] -> xor edx,edx
static PgBytePatch g_ttlCreatePatch = { "disable-ttl/create-media", PG_TTL_CREATE_PAT, PG_TTL_CREATE_MASK,
                                        sizeof PG_TTL_CREATE_PAT, 15, PG_TTL_CREATE_NEW, 2, {0}, nullptr, 0 };
// (b2) media-getter @ RVA 0x12af4c0 was a mis-ID (a 64-bit `mov rax,[rcx+0x20]` getter, not int32 ttlSeconds)
// — zeroing it null-derefs (crashes 6/6). Removed. The cached-media + self-destruct-timer halves need the
// HistoryItem::createView hook (not yet located), so Disable TTL ships the (b1) construction-time half only.

// 999 accounts — the local account cap (kPremiumMaxAccounts = 6) is enforced at FOUR sites; all must be
// raised together. maxAccounts() clamps to 6 (S1); Main::Domain::add() FATAL-asserts (int3) if size()>=6
// (S2 — patching S1 alone CRASHES on the 7th account); Storage::Domain rejects loading >6 / index>5 (S3/S4
// — needed so the extra accounts reload after restart). S1 uses a mov-imm32 so it takes a true 999; the
// others are `cmp r/m,imm8` so they go to 127 (max signed imm8, keeps length) — far above 6. Mirrors macOS
// `binary.accounts.limit_999`. AOBs verified unique in .text.
static const uint8_t PG_ACC_999[]   = { 0xE7,0x03,0x00,0x00 };  // imm32 999
static const uint8_t PG_ACC_127[]   = { 0x7F };                  // imm8 127
// S1 maxAccounts clamp: 41 8D 41 03 | B9 06 00 00 00 (mov ecx,6) | 3B C1 0F 4F C1 C3
static const uint8_t PG_ACC1_PAT[]  = { 0x41,0x8D,0x41,0x03, 0xB9,0x06,0x00,0x00,0x00, 0x3B,0xC1,0x0F,0x4F,0xC1,0xC3 };
static const uint8_t PG_ACC1_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
static PgBytePatch g_acc1Patch = { "acc999/max", PG_ACC1_PAT, PG_ACC1_MASK, sizeof PG_ACC1_PAT, 5, PG_ACC_999, 4, {0}, nullptr, 0 };
// S2 add() gate: 48 2B C1 48 C1 F8 04 | 48 83 F8 06 (cmp rax,6) | 0F 83
static const uint8_t PG_ACC2_PAT[]  = { 0x48,0x2B,0xC1, 0x48,0xC1,0xF8,0x04, 0x48,0x83,0xF8,0x06, 0x0F,0x83 };
static const uint8_t PG_ACC2_MASK[] = { 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF };
static PgBytePatch g_acc2Patch = { "acc999/add", PG_ACC2_PAT, PG_ACC2_MASK, sizeof PG_ACC2_PAT, 10, PG_ACC_127, 1, {0}, nullptr, 0 };
// S3 storage outer: 8B 4C 24 64 8D 41 FF | 83 F8 05 (cmp eax,5) | 0F 87
static const uint8_t PG_ACC3_PAT[]  = { 0x8B,0x4C,0x24,0x64, 0x8D,0x41,0xFF, 0x83,0xF8,0x05, 0x0F,0x87 };
static const uint8_t PG_ACC3_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF };
static PgBytePatch g_acc3Patch = { "acc999/store-out", PG_ACC3_PAT, PG_ACC3_MASK, sizeof PG_ACC3_PAT, 9, PG_ACC_127, 1, {0}, nullptr, 0 };
// S4 storage inner: 8B 44 24 60 | 83 F8 05 (cmp eax,5) | 0F 87
static const uint8_t PG_ACC4_PAT[]  = { 0x8B,0x44,0x24,0x60, 0x83,0xF8,0x05, 0x0F,0x87 };
static const uint8_t PG_ACC4_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF };
static PgBytePatch g_acc4Patch = { "acc999/store-in", PG_ACC4_PAT, PG_ACC4_MASK, sizeof PG_ACC4_PAT, 6, PG_ACC_127, 1, {0}, nullptr, 0 };

// Local Telegram Premium — Main::Session::premiumPossibleValue() producer lambda (RVA 0x1f98eb0). It reads
// the self-user flags at [user+0x1a8] and isolates the Premium bit (`and edx,0x4000`) → bool. Flipping the
// `and` to `or` (modrm E2->CA) forces bit 14 always set → premium reports true (matches macOS `mov w8,#1`).
// Same length, edx is dead after. AOB unique.
static const uint8_t PG_LPREM_PAT[]  = { 0x48,0x8B,0x41,0x38, 0x48,0x89,0x44,0x24,0x30, 0x48,0x8B,0x40,0x60,
                                         0x8B,0x90,0xA8,0x01,0x00,0x00, 0x81,0xE2,0x00,0x40,0x00,0x00, 0x0F,0x95,0x44,0x24,0x50 };
static const uint8_t PG_LPREM_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
                                         0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_LPREM_NEW[]  = { 0xCA };  // and edx,.. -> or edx,..
static PgBytePatch g_lpremPatch = { "local-premium", PG_LPREM_PAT, PG_LPREM_MASK, sizeof PG_LPREM_PAT, 20, PG_LPREM_NEW, 1, {0}, nullptr, 0 };

// Show bot callback-data on hover — ReplyMarkupClickHandler::getUrlButton() (inlined). The copy/drag-text
// sites B (0x1a40084) and D (0x1a404c0) accept only Url(1)/Auth(12) buttons (`cmp cl,1;je;cmp cl,0xc;jne`).
// Replace that 10-byte test with `mov edx,0xD006 ; bt edx,ecx ; jae reject` so types {1,2,12,14,15} (adds
// Callback, WebView, SimpleWebView) are accepted → callback-data becomes visible. edx dead, reject rel8
// preserved per-site. AOBs unique.
static const uint8_t PG_CBH_B_PAT[]  = { 0x48,0x85,0xC0,0x74,0x50, 0x0F,0xB6,0x08, 0x80,0xF9,0x01,0x74,0x05,0x80,0xF9,0x0C,0x75,0x43 };
static const uint8_t PG_CBH_B_MASK[] = { 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_CBH_B_NEW[]  = { 0xBA,0x06,0xD0,0x00,0x00, 0x0F,0xA3,0xCA, 0x73,0x43 };  // keeps reject rel8 0x43
static PgBytePatch g_cbhBPatch = { "callback-hover/B", PG_CBH_B_PAT, PG_CBH_B_MASK, sizeof PG_CBH_B_PAT, 8, PG_CBH_B_NEW, sizeof PG_CBH_B_NEW, {0}, nullptr, 0 };
static const uint8_t PG_CBH_D_PAT[]  = { 0x48,0x85,0xC0,0x74,0x24, 0x0F,0xB6,0x08, 0x80,0xF9,0x01,0x74,0x05,0x80,0xF9,0x0C,0x75,0x17 };
static const uint8_t PG_CBH_D_MASK[] = { 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_CBH_D_NEW[]  = { 0xBA,0x06,0xD0,0x00,0x00, 0x0F,0xA3,0xCA, 0x73,0x17 };  // keeps reject rel8 0x17
static PgBytePatch g_cbhDPatch = { "callback-hover/D", PG_CBH_D_PAT, PG_CBH_D_MASK, sizeof PG_CBH_D_PAT, 8, PG_CBH_D_NEW, sizeof PG_CBH_D_NEW, {0}, nullptr, 0 };

// Open links without warning — HiddenUrlClickHandler::Open (RVA 0x106f450). All confirmation predicates
// converge on `test r12b,r12b ; je box` @ 0x106faf4 (r12b = IsCtrlPressed) — NOP that `je` (74 0E -> 90 90)
// so it always falls through to the OPEN path (the open arg is populated before all gates → safe). The
// optional 2nd site @ 0x106f9c6 is the forceConfirmation (displayed-text != URL) box `jne` — NOP it (6
// bytes) too for full coverage. Matches macOS's `TBZ -> unconditional open`. AOBs unique.
static const uint8_t PG_LINKS1_PAT[]  = { 0x84,0xDB,0x74,0x05, 0x45,0x84,0xE4, 0x74,0x0E, 0x48,0x8D,0x4D,0xB0, 0xE8,0x00,0x00,0x00,0x00 };
static const uint8_t PG_LINKS1_MASK[] = { 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0x00,0x00,0x00,0x00 };
static const uint8_t PG_LINKS1_NEW[]  = { 0x90,0x90 };  // je box -> nop nop
static PgBytePatch g_links1Patch = { "open-links/gate", PG_LINKS1_PAT, PG_LINKS1_MASK, sizeof PG_LINKS1_PAT, 7, PG_LINKS1_NEW, 2, {0}, nullptr, 0 };
static const uint8_t PG_LINKS2_PAT[]  = { 0x80,0x7C,0x24,0x38,0x00, 0x0F,0x85,0x00,0x00,0x00,0x00, 0x40,0x84,0xFF,0x74,0x09 };
static const uint8_t PG_LINKS2_MASK[] = { 0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0x00,0x00,0x00,0x00, 0xFF,0xFF,0xFF,0xFF,0xFF };
static const uint8_t PG_LINKS2_NEW[]  = { 0x90,0x90,0x90,0x90,0x90,0x90 };  // jne forceConfirm box -> 6x nop
static PgBytePatch g_links2Patch = { "open-links/force", PG_LINKS2_PAT, PG_LINKS2_MASK, sizeof PG_LINKS2_PAT, 5, PG_LINKS2_NEW, 6, {0}, nullptr, 0 };

// Custom Stars / Custom TON — CreditsAmountFromTL (RVA 0x115c470) returns CreditsAmount{whole,nano} through
// an sret pointer in RCX (word0 = (whole<<2)|tonflag, word1 = nano, returns rax=rcx). ONE function serves
// both (branches on the TL ctor) so the two are mutually exclusive on x64 — stars wins when both are on. We
// overwrite the 23-byte entry stub with code that writes the configured constant. VALUE-DEPENDENT: the imm64
// is rendered from config into PG_CREDITS_RENDERED (the reversible engine's newBytes points at that buffer).
static const uint8_t PG_CREDITS_PAT[]  = { 0x40,0x53, 0x48,0x83,0xEC,0x40, 0x8B,0x42,0x08, 0x48,0x8B,0xD9,
                                           0x3D,0xE0,0xE3,0xAE,0x74, 0x74,0x37, 0x3D,0xA3,0xB4,0xB6,0xBB };
static const uint8_t PG_CREDITS_MASK[] = { 0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF, 0xFF,0xFF,0xFF,
                                           0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,0xFF };
static uint8_t PG_CREDITS_RENDERED[23];
static PgBytePatch g_creditsPatch = { "custom-credits", PG_CREDITS_PAT, PG_CREDITS_MASK, sizeof PG_CREDITS_PAT,
                                      0, PG_CREDITS_RENDERED, sizeof PG_CREDITS_RENDERED, {0}, nullptr, 0 };
static void pg_render_credits(uint8_t* out, uint64_t value, int tonflag) {
    static const uint8_t tmpl[23] = { 0x31,0xC0, 0x48,0x89,0x41,0x08, 0x48,0xB8, 0,0,0,0,0,0,0,0,
                                      0x48,0x89,0x01, 0x48,0x89,0xC8, 0xC3 };  // xor eax,eax;mov[rcx+8],rax;mov rax,imm;mov[rcx],rax;mov rax,rcx;ret
    memcpy(out, tmpl, sizeof tmpl);
    uint64_t imm = ((value & ((1ULL << 62) - 1)) << 2) | (tonflag ? 1ULL : 0ULL);
    memcpy(out + 8, &imm, 8);   // imm64 LE into the `mov rax, imm64` operand
}

static void pg_apply_self_phone_hook(bool on);  // defined with the hooks below
static void pg_apply_setflags_hook(bool on);    // defined with the hooks below
static void pg_apply_userid_hook(bool on);      // defined with the hooks below
static void pg_apply_collectible_phone_hook(bool on);  // defined with the hooks below
static void pg_build_custom_phone(void);        // defined with the hooks below
static void pg_build_bot_verify(void);          // defined with the hooks below

// Apply every config-gated byte-patch to the current config. Called at init and on each config reload so
// the GUI toggles take effect live (mirrors the DLL patches' live-reload behaviour).
extern "C" void pg_apply_mem_patches(void) {
    pg_byte_patch_apply(&g_recentPatch, pg_recent_stickers_enabled());
    pg_byte_patch_apply(&g_blurPatch, pg_sensitive_blur_enabled());
    bool spoil = pg_disable_spoilers_enabled();
    pg_byte_patch_apply(&g_spoilPhotoPatch, spoil);
    pg_byte_patch_apply(&g_spoilDocPatch, spoil);
    pg_byte_patch_apply(&g_preffPatch, pg_premium_effects_enabled());
    // Disable TTL: only the (b1) create-media force-zero is applied. (b2) — the agent's "MediaFile::ttlSeconds()"
    // getter — is a 64-bit `mov rax,[rcx+0x20]` (returns rax, a pointer/int64), NOT an int32 ttlSeconds(eax),
    // so the agent mis-identified it; zeroing it nulls a real pointer → reliable crash (verified 6/6). Dropped.
    // (b1) forces ttl_seconds=0 at media construction → incoming view-once media carries no self-destruct timer.
    pg_byte_patch_apply(&g_ttlCreatePatch, pg_disable_ttl_enabled());
    bool acc = pg_account_limit_999_enabled();
    pg_byte_patch_apply(&g_acc1Patch, acc);
    pg_byte_patch_apply(&g_acc2Patch, acc);
    pg_byte_patch_apply(&g_acc3Patch, acc);
    pg_byte_patch_apply(&g_acc4Patch, acc);
    pg_byte_patch_apply(&g_lpremPatch, pg_local_premium_enabled());
    bool cbh = pg_callback_hover_enabled();
    pg_byte_patch_apply(&g_cbhBPatch, cbh);
    pg_byte_patch_apply(&g_cbhDPatch, cbh);
    bool lnk = pg_open_links_enabled();
    pg_byte_patch_apply(&g_links1Patch, lnk);
    pg_byte_patch_apply(&g_links2Patch, lnk);
    // The stories byte-patches ride the SAME toggle as the request-drops, so "Hide stories" is complete:
    // drops empty the feed, these clear the per-peer story state (ring + click).
    bool hs = pg_hide_stories_enabled();
    pg_byte_patch_apply(&g_storiesUserPatch, hs);
    pg_byte_patch_apply(&g_storiesChanPatch, hs);
    pg_build_custom_phone();   // (re)build the static custom-phone QString from config
    pg_build_bot_verify();     // (re)build the static bot-verify description QString + empty entities
    pg_apply_self_phone_hook(pg_hide_self_phone_enabled() || pg_custom_phone_enabled());  // toggle the MinHook
    pg_apply_setflags_hook(pg_peer_badge_enabled() || pg_custom_level_rating_enabled()
                           || pg_local_premium_enabled() || pg_local_channel_enabled()
                           || pg_custom_userid_enabled()     // needs the hook to record g_selfUserId
                           || pg_custom_phone_enabled()      // writes the self _phone field (collectible lookup uses it)
                           || pg_bot_verify_enabled());
    pg_apply_userid_hook(pg_custom_userid_enabled());
    pg_apply_collectible_phone_hook(pg_fragment_phone_enabled());   // fragment-phone display gate
    // Custom Stars / Custom TON (mutually exclusive — one credits fn; stars wins). Render then apply/revert.
    bool cs = pg_custom_stars_enabled(), ct = pg_custom_ton_enabled();
    if (cs || ct) {
        pg_render_credits(PG_CREDITS_RENDERED,
                          (uint64_t)(cs ? pg_custom_stars_value() : pg_custom_ton_value()), cs ? 0 : 1);
        pg_byte_patch_apply(&g_creditsPatch, true);
    } else {
        pg_byte_patch_apply(&g_creditsPatch, false);
    }
}

// ---- the two hooks -------------------------------------------------------------------------------
// ABIs (Win x64): tryToReceive(this); sendPrepared(this, &SerializedRequest, int64 ms).
using TryToReceiveFn  = void(__fastcall*)(void* self);
using SendPreparedFn  = void(__fastcall*)(void* self, void* request, int64_t msCanWait);
static TryToReceiveFn g_origTryToReceive = nullptr;
static SendPreparedFn g_origSendPrepared = nullptr;

// NOTE: this is where the macOS engine's TL logic gets ported. For now we just log, to validate the
// hooks + buffer layout on Windows. See patchgram_offsets.h for the constants used here.
static void __fastcall hkTryToReceive(void* self) {
    // self = Session*. _data at self+0x28; received std::vector<Response> {first,last} at _data+0xc0/0xc8.
    // We run BEFORE the original (which base::takes + drains the queue), so the vector is still populated.
    uint8_t* data = *(uint8_t**)((uint8_t*)self + PG_SESSION_PRIVATE_DATA_OFFSET);
    if (data) {
        uint8_t* begin = *(uint8_t**)(data + PG_SESSION_DATA_RECEIVED_BEGIN_OFFSET);  // first
        uint8_t* end   = *(uint8_t**)(data + PG_SESSION_DATA_RECEIVED_END_OFFSET);    // last
        if (begin && end && end > begin && ((end - begin) % PG_RESPONSE_SIZE) == 0
            && (size_t)(end - begin) <= PG_RESPONSE_SIZE * 4096) {
            for (uint8_t* resp = begin; resp < end; resp += PG_RESPONSE_SIZE) {
                // One-shot: confirm Telegram's reply buffers live in GetProcessHeap (→ the Qt5
                // resize-beyond-capacity realloc is heap-safe). Read-only; logged once.
                static bool heapProbed = false;
                if (!heapProbed) {
                    uint8_t* d = pg_qvec_d(resp + PG_RESPONSE_REPLY_OFFSET);
                    if (d) { heapProbed = true; plog("# HEAP probe: reply buffer in process heap = %d (1=Qt5 realloc safe)", pg_host_owns(d)); }
                }
                if (pg_logger_enabled()) {
                    int32_t reqId = *(int32_t*)(resp + PG_RESPONSE_REQUEST_ID_OFFSET);
                    int32_t wc = 0;
                    uint32_t* words = pg_qvec_data(resp + PG_RESPONSE_REPLY_OFFSET, &wc);  // Qt5 mtpBuffer
                    if (words && wc > 0) {
                        // The whole reply IS the TL result → body starts at word 0. The decode runs
                        // SYNCHRONOUSLY on the MTProto thread, so a huge response (premiumPromo/config/
                        // dialogs, thousands of words) would block it long enough to intermittently trip
                        // Telegram's connection timing → crash. Cap it: above the threshold we log only the
                        // header (ctor+size), never the full deep walk. Keeps the logger safe + useful for
                        // normal traffic. (decoded[] is static → also off the thread stack.)
                        static char decoded[8192];
                        if (wc <= PG_LOG_MAX_DECODE_WORDS) {
                            patchgram_tl_decode((const uint8_t*)words, (size_t)wc * 4, decoded, sizeof(decoded));
                            plog("<- RESPONSE reqId=%d %s", reqId, decoded);
                        } else {
                            plog("<- RESPONSE reqId=%d ctor=%#x wc=%d (large; not decoded)", reqId, words[0], wc);
                        }
                    }
                }
                pg_apply_response(resp);  // run enabled rewriters BEFORE the original drains the queue
            }
        }
    }
    g_origTryToReceive(self);  // original drains+dispatches the queue
}

static void __fastcall hkSendPrepared(void* self, void* request, int64_t msCanWait) {
    if (request) {
        // request = &SerializedRequest (= &shared_ptr<RequestData>); *(request+0) = RequestData*.
        uint8_t* rdata = *(uint8_t**)request;
        if (rdata && pg_logger_enabled()) {
            int32_t wc = 0;
            uint32_t* words = pg_qvec_data(rdata + PG_REQUEST_DATA_BUFFER_OFFSET, &wc);  // Qt5 mtpBuffer
            int32_t   reqId = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
            if (words && wc > PG_SERIALIZED_REQUEST_BODY_POSITION) {
                // Serialized request words: salt(2) sessionId(2) msgId(2) seqNo(1) len(1) then the TL
                // body at word 8 (kMessageBodyPosition). Decode from there.
                const uint32_t* body = words + PG_SERIALIZED_REQUEST_BODY_POSITION;
                size_t bytelen = (size_t)(wc - PG_SERIALIZED_REQUEST_BODY_POSITION) * 4;
                char decoded[8192];
                patchgram_tl_decode((const uint8_t*)body, bytelen, decoded, sizeof(decoded));
                plog("-> REQUEST reqId=%d %s", reqId, decoded);
            }
        }
        if (pg_apply_request(request)) return;  // dropped (block typing/read) → never queue/send it
    }
    g_origSendPrepared(self, request, msCanWait);
}

// ---- Hide self phone hook ------------------------------------------------------------------------
// Info::Profile::PhoneOrHiddenValue map-lambda (RVA 0x1d7ac30). x64 member-with-sret ABI: RCX=closure
// (its first member is the captured `user`), RDX=&TextWithEntities sret, R8=phone, R9=username, stack=
// about,hidden; returns the sret ptr in RAX. We let the original build the result, then — only for the
// SELF user (flags word at user+0x1a8, UserDataFlag::Self = 0x2000) — truncate the returned QString's
// text to empty so Info's addInfoLine() omits the phone row. Qt5-safe: we DON'T memset (Qt6-only; nulling
// a Qt5 QString `d` crashes); we only set size=0, and ONLY on an UNSHARED string (ref==1) so we never
// corrupt the shared "hidden" translation literal. The hook is created at init but ONLY enabled while the
// feature is on (see pg_apply_self_phone_hook) — so it can never affect users who don't toggle it.
using PhoneValFn = void*(__fastcall*)(void* closure, void* sret, void* a3, void* a4, void* a5, void* a6);
static PhoneValFn g_origPhoneVal = nullptr;
static uint8_t*   g_phoneHookTarget = nullptr;
static bool       g_phoneHookEnabled = false;
// Build a STATIC Qt5 QStringData* (ref=-1, leaked, never freed — Telegram's QArrayData::deref never
// deallocates a static, and copy-ctors skip the ref bump) holding ASCII `p` as UTF-16. NULL if empty.
static uint8_t* pg_build_qstring(const char* p) {
    if (!p || !p[0]) return nullptr;
    size_t len = strlen(p);
    uint8_t* d = (uint8_t*)pg_host_alloc(PG_QT5_ARRAYDATA_HEADER_SIZE + (len + 1) * 2);
    if (!d) return nullptr;
    *(int32_t*)(d + PG_QT5_ARRAYDATA_REF_OFFSET)    = -1;
    *(int32_t*)(d + PG_QT5_ARRAYDATA_SIZE_OFFSET)   = (int32_t)len;
    *(uint32_t*)(d + PG_QT5_ARRAYDATA_ALLOC_OFFSET) = (uint32_t)len;
    *(int64_t*)(d + PG_QT5_ARRAYDATA_OFFSET_OFFSET) = PG_QT5_ARRAYDATA_HEADER_SIZE;
    uint16_t* data = (uint16_t*)(d + PG_QT5_ARRAYDATA_HEADER_SIZE);
    for (size_t i = 0; i < len; i++) data[i] = (uint16_t)(uint8_t)p[i];
    data[len] = 0;
    return d;
}
// Build a STATIC empty Qt5 QArrayData* (ref=-1, size=0) — an empty QVector/QString d (e.g. TWE entities).
static uint8_t* pg_build_empty_qarray(void) {
    uint8_t* d = (uint8_t*)pg_host_alloc(PG_QT5_ARRAYDATA_HEADER_SIZE);
    if (!d) return nullptr;
    *(int32_t*)(d + PG_QT5_ARRAYDATA_REF_OFFSET)    = -1;
    *(int32_t*)(d + PG_QT5_ARRAYDATA_SIZE_OFFSET)   = 0;
    *(uint32_t*)(d + PG_QT5_ARRAYDATA_ALLOC_OFFSET) = 0;
    *(int64_t*)(d + PG_QT5_ARRAYDATA_OFFSET_OFFSET) = PG_QT5_ARRAYDATA_HEADER_SIZE;
    return d;
}
static uint8_t* g_customPhoneQStr   = nullptr;
static uint8_t* g_botVerifyDescQStr = nullptr;
static uint8_t* g_emptyEntities     = nullptr;   // shared empty QVector<EntityInText> for built TWEs
static void pg_build_custom_phone(void) { g_customPhoneQStr = pg_build_qstring(pg_custom_phone_text()); }
static void pg_build_bot_verify(void) {
    g_botVerifyDescQStr = pg_build_qstring(pg_bot_verify_desc());
    if (!g_emptyEntities) g_emptyEntities = pg_build_empty_qarray();
}
// Resolved real UserData::setBotVerifyDetails (we CALL it to force the badge; we do NOT hook it).
using SetBotVerifyFn = void(__fastcall*)(void* user, void* details);
static SetBotVerifyFn g_setBotVerifyFn = nullptr;
static void* __fastcall hkPhoneVal(void* closure, void* sret, void* a3, void* a4, void* a5, void* a6) {
    void* rv = g_origPhoneVal(closure, sret, a3, a4, a5, a6);
    if (closure && sret) {
        uint8_t* user = *(uint8_t**)closure;                      // captured user is closure[0]
        // Custom phone is NOT handled here: setFlags writes user->_phone to the custom value, so the original
        // PhoneOrHiddenValue above already built the row from the custom phone WITH matching entities. (Swapping
        // text.d here to a different-length static left the original entities referencing out-of-range offsets,
        // which crashed when the profile also rendered inserted usernames.) Only hide-self-phone post-processes.
        if (user && (*(uint32_t*)(user + 0x1a8) & 0x2000) && pg_hide_self_phone_enabled()) {  // UserDataFlag::Self
            uint8_t* qd = *(uint8_t**)sret;                        // QString text.d (first member of TWE)
            if (qd && *(int32_t*)qd == 1)                         // ref==1 → unshared → safe to truncate
                *(int32_t*)(qd + PG_QT5_ARRAYDATA_SIZE_OFFSET) = 0;  // size=0 → text.isEmpty() → row hidden
        }
    }
    return rv;
}
// Toggle the hook to match config (called at init + each reload). Created once; enabled only while on.
static void pg_apply_self_phone_hook(bool on) {
    if (!g_phoneHookTarget) return;
    if (on == g_phoneHookEnabled) return;
    if (on) { if (MH_EnableHook(g_phoneHookTarget) == MH_OK)  { g_phoneHookEnabled = true;  plog("HIDE SELF PHONE: hook enabled"); } }
    else    { if (MH_DisableHook(g_phoneHookTarget) == MH_OK) { g_phoneHookEnabled = false; plog("HIDE SELF PHONE: hook disabled"); } }
}

// ---- Visual peer badge hook ----------------------------------------------------------------------
// UserData::setFlags(UserData* RCX, uint32_t newFlags EDX) (RVA 0x14028e0) replaces the flags word at
// user+0x1a8 with `which` and fires the _changes notify. We AUGMENT the incoming flags with the badge bit
// (Verified 0x8 / Scam 0x10 / Fake 0x20) for the targeted peers before the original stores+notifies — so
// the badge shows + repaints, and it's re-applied on every flag update (persistent). Self bit 0x2000 picks
// the target set. Created at init, enabled only while the feature is on (safe-by-default).
using SetFlagsFn = void(__fastcall*)(void* user, uint32_t which);
static SetFlagsFn g_origUserSetFlags = nullptr;
static uint8_t*   g_setFlagsHookTarget = nullptr;
static bool       g_setFlagsHookEnabled = false;
// Target-mode match: 0=All, 10=All-except-me, 20=Only-me (self = UserDataFlag::Self bit at user+0x1a8).
static inline bool pg_mode_target(int mode, bool self) { return mode == 0 || (mode == 20 && self) || (mode == 10 && !self); }
static int64_t g_selfUserId = 0;   // recorded from setFlags for self (peer->id.value & kChatTypeMask)
static void __fastcall hkUserSetFlags(void* user, uint32_t which) {
    bool self = user && (*(uint32_t*)((uint8_t*)user + 0x1a8) & 0x2000) != 0;  // UserDataFlag::Self
    if (self) { int64_t id = *(int64_t*)((uint8_t*)user + 8) & 0xFFFFFFFFFFFFLL; if (id) g_selfUserId = id; }
    // Visual peer badge: augment the new flags with the badge bit BEFORE the original stores+notifies.
    if (user && pg_peer_badge_enabled()) {
        uint32_t bits = 0;
        switch (pg_peer_badge_type()) { case 1: bits = 0x8; break; case 2: bits = 0x10; break; case 3: bits = 0x20; break; }
        if (bits && pg_mode_target(pg_peer_badge_mode(), self)) which |= bits;
    }
    // Local Telegram Premium: force the Premium flag (0x4000) on the SELF user so isPremium() reads true
    // everywhere (the 186 inlined feature gates), unlocking premium UI locally. (premiumPossibleValue is
    // also byte-patched, but THIS flag is what actually makes the client treat you as premium.)
    if (user && self && pg_local_premium_enabled()) which |= 0x4000;
    g_origUserSetFlags(user, which);
    // Bot verification: FORCE setBotVerifyDetails for targeted peers with a built BotVerifyDetails {botId,
    // iconId, description}. We call the REAL setter (not a hook) so Telegram's CRT owns the unique_ptr's
    // alloc/free; the description QString + empty entities are leak-based statics. Idempotent (the setter
    // skips when unchanged). botId = the peer's own id (a loaded user) so the "verified by" link is valid.
    // MUST run FIRST among the after-writes: setBotVerifyDetails fires a SYNCHRONOUS peerUpdated notify, so
    // it renders here-and-now — do it while _starsRating / _personalChannelId still hold their original
    // (consistent) values. Writing those raw fields first then rendering a verified profile mid-update
    // crashes (the botVerify×levelRating conflict). They bypass _changes anyway, so doing them after this
    // notify is correct — they show on the next natural refresh as designed.
    if (user && pg_bot_verify_enabled() && g_botVerifyDescQStr && g_setBotVerifyFn && pg_mode_target(pg_bot_verify_mode(), self)) {
        uint8_t details[0x20] = {0};
        *(int64_t*)(details + 0x00) = *(int64_t*)((uint8_t*)user + 8) & 0xFFFFFFFFFFFFLL;  // botId
        *(uint64_t*)(details + 0x08) = pg_bot_verify_icon_id();                            // iconId (custom emoji)
        *(void**)(details + 0x10) = g_botVerifyDescQStr;                                   // description.text d
        *(void**)(details + 0x18) = g_emptyEntities;                                       // description.entities d
        g_setBotVerifyFn(user, details);
    }
    // setFlags.after field writes (in-place; bypass _changes so they show on the next profile open/refresh):
    if (user && pg_custom_level_rating_enabled() && pg_mode_target(pg_clr_mode(), self)) {
        int32_t r[4]; pg_clr_values(r);
        memcpy((uint8_t*)user + 0x230, r, 16);   // _starsRating {level, rating, currentLevelStars, nextLevelStars}
    }
    // Local attached channel: write _personalChannelId (int64 @+0x240) + _personalChannelMessageId (int64
    // @+0x248). The channel MUST already be loaded in the client (open it once) or the profile crashes
    // rendering an unknown channel — that's expected per-design (the user loads it first).
    if (user && pg_local_channel_enabled() && pg_local_channel_id() != 0 && pg_mode_target(pg_local_channel_mode(), self)) {
        int64_t id = pg_local_channel_id(), msg = pg_local_channel_msg();
        memcpy((uint8_t*)user + 0x240, &id, 8);
        memcpy((uint8_t*)user + 0x248, &msg, 8);
    }
    // Custom phone number: swap the SELF user's _phone QString d (UserData+0x218 — _starsRating@0x230 minus
    // the three 8-byte members before it: _phone, _privateForwardName, _botVerifyDetails) to our static
    // custom-phone QString. Unlike the display-only PhoneOrHiddenValue swap, this makes user->phone() return
    // the custom number EVERYWHERE — so the Fragment collectible-info lookup (fragment.getCollectibleInfo)
    // and the collectible popup use it too, instead of leaking the real phone (fixes fragment + custom phone).
    // Sanity-gated on a plausible existing QString (non-null d, size 0..64) so a wrong offset can't corrupt.
    if (user && self && pg_custom_phone_enabled() && g_customPhoneQStr) {
        uint8_t** pphone = (uint8_t**)((uint8_t*)user + 0x218);
        uint8_t* old = *pphone;
        if (old && old != g_customPhoneQStr) {
            int32_t sz = *(int32_t*)(old + PG_QT5_ARRAYDATA_SIZE_OFFSET);
            if (sz >= 0 && sz <= 64) {
                static bool logged = false;
                if (!logged) { logged = true; plog("CUSTOM PHONE: _phone@0x218 size=%d -> custom \"%s\"", sz, pg_custom_phone_text()); }
                *pphone = g_customPhoneQStr;
            }
        }
    }
}
static void pg_apply_setflags_hook(bool on) {
    if (!g_setFlagsHookTarget) return;
    if (on == g_setFlagsHookEnabled) return;
    if (on) { if (MH_EnableHook(g_setFlagsHookTarget) == MH_OK)  { g_setFlagsHookEnabled = true;  plog("SETFLAGS HOOK: enabled"); } }
    else    { if (MH_DisableHook(g_setFlagsHookTarget) == MH_OK) { g_setFlagsHookEnabled = false; plog("SETFLAGS HOOK: disabled"); } }
}

// ---- Custom userID hook --------------------------------------------------------------------------
// QLocale::toString(QLocale* RCX, QString* sret RDX, int64 val R8) (RVA 0x5328c30) is SHARED by 67 sites.
// The profile About-row id is formatted here at call site 0x1c88783 (returns to VA g_module+0x1c88788).
// We hook toString and ONLY when called from that exact site (return addr == gate) for the SELF id
// (val == g_selfUserId, recorded by the setFlags hook) swap val to the configured id — every other number
// formats untouched. Display-only (peer->id is never changed). Created at init, enabled only while on.
using ToStringFn = void(__fastcall*)(void* locale, void* sret, int64_t val);
static ToStringFn g_origToString = nullptr;
static uint8_t*   g_toStringHookTarget = nullptr;
static bool       g_toStringHookEnabled = false;
static uintptr_t  g_idGateAddr = 0;
static void __fastcall hkToString(void* locale, void* sret, int64_t val) {
    if (g_idGateAddr && (uintptr_t)_ReturnAddress() == g_idGateAddr
        && pg_custom_userid_enabled() && pg_custom_userid_value() != 0 && val == g_selfUserId) {
        val = pg_custom_userid_value();
    }
    g_origToString(locale, sret, val);
}
static void pg_apply_userid_hook(bool on) {
    if (!g_toStringHookTarget) return;
    if (on == g_toStringHookEnabled) return;
    if (on) { if (MH_EnableHook(g_toStringHookTarget) == MH_OK)  { g_toStringHookEnabled = true;  plog("CUSTOM USERID: hook enabled"); } }
    else    { if (MH_DisableHook(g_toStringHookTarget) == MH_OK) { g_toStringHookEnabled = false; plog("CUSTOM USERID: hook disabled"); } }
}

// ---- Fragment phone display hook -----------------------------------------------------------------
// Info::Profile::IsCollectiblePhone(UserData* RCX) -> bool (RVA 0x1d40050) decides whether the profile
// phone row renders as a Fragment collectible (link + tap → fragment.getCollectibleInfo). Stock it compares
// user->phone() against the appConfig `fragment_prefixes` list (default {"888"}); the self phone won't match.
// We force TRUE for the self user so the row turns collectible; the engine response ring then answers the
// tap. Created at init, enabled ONLY while fragmentPhone is on — so a collectible tap can never fire without
// the ring live (an unanswered getCollectibleInfo null-derefs). Self-gated → other profiles keep stock.
using IsCollectiblePhoneFn = bool(__fastcall*)(void* user);
static IsCollectiblePhoneFn g_origIsCollectiblePhone = nullptr;
static uint8_t* g_collectiblePhoneHookTarget = nullptr;
static bool     g_collectiblePhoneHookEnabled = false;
static bool __fastcall hkIsCollectiblePhone(void* user) {
    if (user && (*(uint32_t*)((uint8_t*)user + 0x1a8) & 0x2000)) return true;  // UserDataFlag::Self → collectible
    return g_origIsCollectiblePhone(user);
}
static void pg_apply_collectible_phone_hook(bool on) {
    if (!g_collectiblePhoneHookTarget) return;
    if (on == g_collectiblePhoneHookEnabled) return;
    if (on) { if (MH_EnableHook(g_collectiblePhoneHookTarget) == MH_OK)  { g_collectiblePhoneHookEnabled = true;  plog("FRAGMENT PHONE: display hook enabled"); } }
    else    { if (MH_DisableHook(g_collectiblePhoneHookTarget) == MH_OK) { g_collectiblePhoneHookEnabled = false; plog("FRAGMENT PHONE: display hook disabled"); } }
}

// ---- init ----------------------------------------------------------------------------------------
// Read a whole file into a heap buffer (NUL-terminated). Caller frees. NULL if missing.
static char* readWholeFile(const char* p) {
    FILE* f = fopen(p, "rb");
    if (!f) return nullptr;
    fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
    if (n < 0) { fclose(f); return nullptr; }
    char* b = (char*)malloc((size_t)n + 1);
    if (!b) { fclose(f); return nullptr; }
    size_t rd = fread(b, 1, (size_t)n, f); b[rd] = 0; fclose(f);
    return b;
}

// Live config: re-read PatchgramRuntime.json whenever it changes on disk, so toggles from the GUI take
// effect WITHOUT restarting Telegram (re-injecting into an already-loaded DLL does NOT re-run DllMain, so
// a one-shot read would leave the running session on stale config — the cause of "I enabled it but nothing
// happened"). Cheap mtime poll on a worker thread.
static char g_cfgPath[MAX_PATH] = {0};
// Poll the file CONTENT (not its mtime — NTFS can defer/cache directory timestamps, so a write may not
// bump LastWriteTime promptly). Re-read the small JSON each second; reload when the bytes differ.
static DWORD WINAPI configWatcher(LPVOID) {
    char* last = g_cfgPath[0] ? readWholeFile(g_cfgPath) : nullptr;  // baseline = what we loaded at init
    for (;;) {
        Sleep(1000);
        if (!g_cfgPath[0]) continue;
        char* cur = readWholeFile(g_cfgPath);
        if (!cur) continue;
        if (!last || strcmp(cur, last) != 0) {
            pg_config_load(cur);
            pg_apply_mem_patches();   // re-flip the byte-patch family to match the new config (live toggle)
            plog("# config reloaded (PatchgramRuntime.json changed)");
            free(last); last = cur;
        } else {
            free(cur);
        }
    }
}

static void installHooks() {
    g_module = (uint8_t*)GetModuleHandleW(nullptr);  // Telegram.exe
    char path[MAX_PATH]; GetModuleFileNameA((HMODULE)g_module, path, MAX_PATH);
    char* slash = strrchr(path, '\\'); if (slash) strcpy(slash + 1, "PatchgramHook.log");
    g_log = fopen(path, "a");
    plog("# Patchgram-Windows loaded; module=%p", g_module);

    // Load PatchgramRuntime.json (same dir as the exe; same keys as the macOS engine). Missing/empty
    // config → defaults (logger on, rewriters off), so the validated logger keeps working.
    char cfgPath[MAX_PATH]; GetModuleFileNameA((HMODULE)g_module, cfgPath, MAX_PATH);
    char* cslash = strrchr(cfgPath, '\\'); if (cslash) strcpy(cslash + 1, "PatchgramRuntime.json");
    char* cfg = readWholeFile(cfgPath);
    pg_config_load(cfg);   // NULL is fine (defaults)
    if (cfg) free(cfg);
    // Remember the config path and start the live-reload watcher (GUI Save → live effect, no restart).
    strncpy(g_cfgPath, cfgPath, MAX_PATH - 1);
    CreateThread(nullptr, 0, configWatcher, nullptr, 0, nullptr);
    pg_engine_selftest();  // validate the Qt5 realloc logic on a synthetic buffer (safe)
    pg_mem_engine_selftest();  // validate the byte-patch (AOB) applier on a private buffer (safe)
    pg_apply_mem_patches();  // apply config-gated byte-patches (recent-stickers limit, …) to .text now

    uint8_t* tryRecv = resolve("Session::tryToReceive",
                               "Session Error: can't receive in a killed session", PG_RVA_TRY_TO_RECEIVE);
    uint8_t* sendPrep = resolve("Session::sendPrepared",
                                "MTP Info: adding request to toSendMap, msCanWait %1", PG_RVA_SEND_PREPARED);

    if (MH_Initialize() != MH_OK) { plog("ERROR MH_Initialize"); return; }
    if (MH_CreateHook(tryRecv, (void*)&hkTryToReceive, (void**)&g_origTryToReceive) != MH_OK
        || MH_EnableHook(tryRecv) != MH_OK) plog("ERROR hook tryToReceive");
    if (MH_CreateHook(sendPrep, (void*)&hkSendPrepared, (void**)&g_origSendPrepared) != MH_OK
        || MH_EnableHook(sendPrep) != MH_OK) plog("ERROR hook sendPrepared");

    // Hide self phone — create (but DON'T enable) the PhoneOrHiddenValue hook. Resolve by RVA with an
    // entry-byte sanity check so a signature drift disables it instead of hooking the wrong bytes. It's
    // enabled only when the feature is toggled on (pg_apply_self_phone_hook), so it's inert by default.
    uint8_t* phoneFn = g_module + PG_RVA_PHONE_OR_HIDDEN;
    static const uint8_t phoneEntry[] = { 0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x6C,0x24,0x10 };  // prologue
    if (memcmp(phoneFn, phoneEntry, sizeof phoneEntry) == 0) {
        if (MH_CreateHook(phoneFn, (void*)&hkPhoneVal, (void**)&g_origPhoneVal) == MH_OK) {
            g_phoneHookTarget = phoneFn;
            pg_apply_self_phone_hook(pg_hide_self_phone_enabled() || pg_custom_phone_enabled());  // enable if configured
        } else plog("ERROR hook PhoneOrHiddenValue");
    } else {
        plog("HIDE SELF PHONE: entry mismatch at RVA %#x — hook skipped (re-derive)", PG_RVA_PHONE_OR_HIDDEN);
    }

    // Visual peer badge — create (not enable) the UserData::setFlags hook (entry-byte sanity-checked).
    uint8_t* setFlagsFn = g_module + PG_RVA_USER_SET_FLAGS;
    static const uint8_t setFlagsEntry[] = { 0x40,0x53,0x55,0x56,0x57,0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57 };
    if (memcmp(setFlagsFn, setFlagsEntry, sizeof setFlagsEntry) == 0) {
        if (MH_CreateHook(setFlagsFn, (void*)&hkUserSetFlags, (void**)&g_origUserSetFlags) == MH_OK) {
            g_setFlagsHookTarget = setFlagsFn;
            pg_apply_setflags_hook(pg_peer_badge_enabled() || pg_custom_level_rating_enabled()
                           || pg_local_premium_enabled() || pg_local_channel_enabled()
                           || pg_custom_userid_enabled() || pg_custom_phone_enabled()
                           || pg_bot_verify_enabled());
        } else plog("ERROR hook UserData::setFlags");
    } else {
        plog("PEER BADGE: entry mismatch at RVA %#x — hook skipped (re-derive)", PG_RVA_USER_SET_FLAGS);
    }
    // Bot verification — resolve (NOT hook) the real setBotVerifyDetails; the setFlags hook calls it for
    // targeted peers. Sanity-check the entry so a drift disables it instead of calling garbage.
    static const uint8_t botVerifyEntry[] = { 0x48,0x89,0x5C,0x24,0x08, 0x48,0x89,0x54,0x24,0x10, 0x55,0x56,0x57 };
    if (memcmp(g_module + PG_RVA_SET_BOT_VERIFY, botVerifyEntry, sizeof botVerifyEntry) == 0)
        g_setBotVerifyFn = (SetBotVerifyFn)(g_module + PG_RVA_SET_BOT_VERIFY);
    else
        plog("BOT VERIFY: entry mismatch at RVA %#x — disabled (re-derive)", PG_RVA_SET_BOT_VERIFY);

    // Custom userID — hook QLocale::toString, gated by the profile-id call site. Sanity-check the id-extract
    // site (movabs rcx,0xffffffffffff ; mov rbx,[rax+8] ; and rbx,rcx) so the gate addr is trustworthy.
    static const uint8_t useridSite[] = { 0x48,0xB9,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x00,0x00, 0x48,0x8B,0x58,0x08, 0x48,0x23,0xD9 };
    if (memcmp(g_module + PG_RVA_USERID_SITE, useridSite, sizeof useridSite) == 0) {
        g_idGateAddr = (uintptr_t)(g_module + PG_RVA_USERID_GATE);
        uint8_t* toStr = g_module + PG_RVA_QLOCALE_TOSTRING;
        if (MH_CreateHook(toStr, (void*)&hkToString, (void**)&g_origToString) == MH_OK) {
            g_toStringHookTarget = toStr;
            pg_apply_userid_hook(pg_custom_userid_enabled());
        } else plog("ERROR hook QLocale::toString");
    } else {
        plog("CUSTOM USERID: id-site mismatch at RVA %#x — hook skipped (re-derive)", PG_RVA_USERID_SITE);
    }

    // Fragment phone — create (NOT enable) the IsCollectiblePhone display hook. Entry-byte sanity-checked
    // against the verified unique prologue. Enabled only while fragmentPhone is on (the response ring is
    // always loaded with the feature, so a collectible tap can never fire without an answer).
    uint8_t* collFn = g_module + PG_RVA_IS_COLLECTIBLE_PHONE;
    static const uint8_t collEntry[] = { 0x40,0x55,0x53,0x56,0x57,0x41,0x56,0x48,0x8B,0xEC,
                                         0x48,0x81,0xEC,0x80,0x00,0x00,0x00,0x48,0x8B,0xD9 };
    if (memcmp(collFn, collEntry, sizeof collEntry) == 0) {
        if (MH_CreateHook(collFn, (void*)&hkIsCollectiblePhone, (void**)&g_origIsCollectiblePhone) == MH_OK) {
            g_collectiblePhoneHookTarget = collFn;
            pg_apply_collectible_phone_hook(pg_fragment_phone_enabled());
        } else plog("ERROR hook IsCollectiblePhone");
    } else {
        plog("FRAGMENT PHONE: entry mismatch at RVA %#x — display hook skipped (re-derive)", PG_RVA_IS_COLLECTIBLE_PHONE);
    }
    plog("hooks installed");
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        // Do init on a worker thread (avoid loader-lock restrictions on MinHook/file IO).
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD { installHooks(); return 0; }, nullptr, 0, nullptr);
    }
    return TRUE;
}
