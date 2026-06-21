// Patchgram-Windows — runtime TL patch engine (config + rewriters). Implementation (compile as C).
//
// Ported from the macOS engine (engine.c.template), adapted to the Qt5 buffer ABI. The rewriters reuse
// the same wire-format logic; only the buffer access differs (Qt5 single-`d` COW vector vs Qt6 inline).
// Strategy: port the in-place (non-resizing) rewriters first — they need no Qt5 realloc, only a guarded
// in-place write (pg_qvec_unshared). Resizing rewriters (hidden-gift inject, gift spoof rebuild) come
// later and will need a Qt5 detach/realloc path.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

#include "engine_patches.h"
#include "engine_tl.h"
#include "patchgram_offsets.h"

// TL constructor ids used by the rewriters (from the api.tl schema; same on every platform).
#define PG_TL_VECTOR_ID         0x1cb5c415u
#define PG_TL_HELP_APP_CONFIG   0xdd18782eu  // help.appConfig { hash:int, config:JSONValue }
#define PG_TL_JSON_OBJECT       0x99c1d49du  // jsonObject { value:Vector<JSONObjectValue> }
#define PG_TL_JSON_OBJECT_VALUE 0xc0de1bd9u  // jsonObjectValue { key:string, value:JSONValue }
#define PG_TL_JSON_NUMBER       0x2be0dfa4u  // jsonNumber { value:double }
#define PG_TL_JSON_STRING       0xb71e767au  // jsonString { value:string }
#define PG_TL_JSON_BOOL         0xc7345e6au  // jsonBool { value:Bool }
#define PG_TL_BOOL_TRUE         0x997275b5u  // boolTrue
#define PG_TL_BOOL_FALSE        0xbc799737u  // boolFalse
// Fragment phone — collectible-info request/response ctors (tl_schema.c.inc verified).
#define PG_TL_FRAGMENT_GET_COLLECTIBLE_INFO 0xbe1e85bau  // fragment.getCollectibleInfo { collectible:InputCollectible }
#define PG_TL_INPUT_COLLECTIBLE_PHONE       0xa2e214a4u  // inputCollectiblePhone { phone:string }
#define PG_TL_INPUT_COLLECTIBLE_USERNAME    0xe39460a9u  // inputCollectibleUsername { username:string }
#define PG_TL_FRAGMENT_COLLECTIBLE_INFO     0x6ebdff91u  // fragment.collectibleInfo { purchase_date,currency,amount,... }
#define PG_MAX_TRACKED_FRAGMENT_REQUESTS    64
// Custom fact check — messages.getFactCheck reply ring (response-replace, mirrors fragment phone).
#define PG_TL_MESSAGES_GET_FACT_CHECK 0xb9cdc5eeu  // messages.getFactCheck { peer:InputPeer, msg_id:Vector<int> }
#define PG_TL_FACT_CHECK              0xb89bfccfu  // factCheck { flags, need_check:f.0?true, country:f.1?string, text:f.1?TextWithEntities, hash:long }
#define PG_TL_TEXT_WITH_ENTITIES      0x751f3146u  // textWithEntities { text:string, entities:Vector<MessageEntity> }
#define PG_MAX_TRACKED_FACT_CHECK_REQUESTS 64
// Custom list usernames (path B: rewrite the self user's usernames Vector in users.userFull/getUsers replies;
// insert when absent / replace when present, grow-capable with revert-on-failure, never touches UserData).
#define PG_TL_USER                 0x31774388u   // user#31774388 (self = flags0 bit10)
#define PG_TL_USERNAME             0xb4073647u   // username#b4073647 { flags, editable:0, active:1, username:string }
#define PG_TL_USERS_USER_FULL      0x3b6d152eu   // users.userFull (response; top-level ctor of getFullUser reply)
#define PG_TL_USERS_GET_FULL_USER  0xb60f5918u   // users.getFullUser (request)
#define PG_TL_USERS_GET_USERS      0x0d91a548u   // users.getUsers (request)
#define PG_USERNAME_SELF_FLAG_BIT  (1u << 10)    // user.flags0 bit10 = self
#define PG_MAX_CUSTOM_USERNAMES    32
#define PG_ACCOUNT_FREEZE_UNTIL 2015320271   // freeze_until_date = 2033-11-11 11:11:11 UTC

// ---- diagnostics log (shared file with the C++ glue) --------------------------------------------
// The C++ side owns the log file; expose a tiny logger here for patch-fired diagnostics.
extern void pg_engine_log(const char *line);   // implemented in patchgram.cpp

// ---- host allocator bridge (Qt5 resize-beyond-capacity) — implemented in patchgram.cpp ----------
extern void *pg_host_alloc(size_t n);   // HeapAlloc(GetProcessHeap())
extern void  pg_host_free(void *p);     // HeapFree(GetProcessHeap())
extern int   pg_host_owns(const void *p);// HeapValidate(GetProcessHeap(),p) — 1 iff p is in that heap

// ── Qt5 buffer writeback: LEAK-BASED, zero risky frees ───────────────────────────────────────────
// Telegram statically links its CRT, so neither side may free the other's heap blocks. We therefore
// NEVER free Telegram's old `d` and mark our new `d` as a Qt5 STATIC array (ref = -1): QArrayData::deref
// returns "still alive" for ref==-1, so Telegram never deallocates it either. No cross-CRT free in either
// direction → safe regardless of which heap each block lives in. (This mirrors the macOS engine, which
// also leaks: it sets d=NULL + a raw non-owning ptr.) Cost: a small per-rewrite leak (rewrites are
// infrequent + buffers are small). An earlier free-based version crashed the session — do not reintroduce.
#define PG_QT5_REF_STATIC (-1)   // Q_REFCOUNT_INITIALIZE_STATIC → deref never deallocates

// Grow an mtpBuffer to `new_cap` elements, preserving current elements + size (capacity-only, like
// reserve()). Caller then appends within the new slack and publishes the size. Returns false on failure.
static bool pg_qvec_grow(const void *container, int32_t new_cap) {
    uint8_t *d = pg_qvec_d(container);
    if (!d || new_cap <= 0) return false;
    int32_t old_size = *(int32_t *)(d + PG_QT5_ARRAYDATA_SIZE_OFFSET);
    int64_t old_off  = *(int64_t *)(d + PG_QT5_ARRAYDATA_OFFSET_OFFSET);
    if (old_size < 0 || new_cap < old_size) return false;
    const int64_t header = PG_QT5_ARRAYDATA_HEADER_SIZE;            // 0x18
    uint8_t *nd = (uint8_t *)pg_host_alloc((size_t)(header + (int64_t)new_cap * 4));
    if (!nd) return false;
    *(int32_t *)(nd + PG_QT5_ARRAYDATA_REF_OFFSET)    = PG_QT5_REF_STATIC;   // Telegram never frees nd
    *(int32_t *)(nd + PG_QT5_ARRAYDATA_SIZE_OFFSET)   = old_size;            // preserve size
    *(uint32_t *)(nd + PG_QT5_ARRAYDATA_ALLOC_OFFSET) = (uint32_t)new_cap;   // alloc=new_cap, capReserved=0
    *(int64_t *)(nd + PG_QT5_ARRAYDATA_OFFSET_OFFSET) = header;              // data() = nd + 0x18
    memcpy(nd + header, d + old_off, (size_t)old_size * 4);                  // copy existing elements
    *(uint8_t **)container = nd;                                             // publish (old d leaks)
    return true;
}

// Replace an mtpBuffer's contents with a freshly-built `count`-word array (the build-fresh-and-swap
// pattern for fact-check / fragment-phone / gift rebuild — the Qt5 equivalent of the macOS {d=NULL,
// ptr=new, size} trick). Allocates a new STATIC Qt5 `d`, copies `words` in, swaps. Returns false on failure.
static bool pg_qvec_replace(const void *container, const uint32_t *words, int32_t count) {
    uint8_t *d = pg_qvec_d(container);
    if (!d || !words || count <= 0) return false;
    const int64_t header = PG_QT5_ARRAYDATA_HEADER_SIZE;
    uint8_t *nd = (uint8_t *)pg_host_alloc((size_t)(header + (int64_t)count * 4));
    if (!nd) return false;
    *(int32_t *)(nd + PG_QT5_ARRAYDATA_REF_OFFSET)    = PG_QT5_REF_STATIC;   // Telegram never frees nd
    *(int32_t *)(nd + PG_QT5_ARRAYDATA_SIZE_OFFSET)   = count;
    *(uint32_t *)(nd + PG_QT5_ARRAYDATA_ALLOC_OFFSET) = (uint32_t)count;
    *(int64_t *)(nd + PG_QT5_ARRAYDATA_OFFSET_OFFSET) = header;
    memcpy(nd + header, words, (size_t)count * 4);
    *(uint8_t **)container = nd;                                             // publish (old d leaks)
    return true;
}
static void pg_logf(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    pg_engine_log(buf);
}

// ---- config (subset of the macOS keys; extended as rewriters are ported) ------------------------
static bool g_logger_enabled               = true;   // default on (preserves the validated logger)
static bool g_message_settings_enabled     = false;
static bool g_message_allow_noforwards_copy= false;
static bool g_account_freeze_enabled       = false;
// Disable monetization (master + 8 sub-features). On Win x64 the macOS ~70 arm64 byte-patches are non-portable;
// only "Premium UI" is reachable at the appConfig-response tier (inject premium_purchase_blocked=jsonBool(true),
// read inverted w/ default true at main_session.cpp → _premiumPossible=false → buy UI hidden). The other 7 sub-
// features have NO appConfig gate (per-peer/channel MTP flags, the premium user flag, request poisons, .text
// who-read patch) so they are inert placeholders here — kept for macOS parity / future request-drop tier.
static bool g_disable_monetization_enabled            = false;   // master
static bool g_disable_monetization_app_config         = false;   // request poison on macOS — NOT ported (would break client)
static bool g_disable_monetization_premium_ui         = false;   // ✅ functional: premium_purchase_blocked
static bool g_disable_monetization_gifts              = false;   // inert (no appConfig gate)
static bool g_disable_monetization_paid_reactions     = false;   // inert
static bool g_disable_monetization_emoji_statuses     = false;   // inert
static bool g_disable_monetization_stars_ton          = false;   // inert
static bool g_disable_monetization_boosts             = false;   // inert
static bool g_disable_monetization_read_receipts      = false;   // inert (.text patch on macOS)
// Fragment phone — fake a Fragment collectible-info popup for the self phone. Two halves: (1) this response
// ring answers fragment.getCollectibleInfo with a built fragment.collectibleInfo; (2) the IsCollectiblePhone
// hook (patchgram.cpp @0x1d40050) makes the self phone render as collectible (link + tap). The hook is only
// enabled when this feature is on, so the ring is always live before any tap can fire (no null-deref).
static bool    g_fragment_phone_enabled       = false;
static int     g_fragment_phone_target_mode   = 20;     // shape parity (0/10/20); answers all phones (see note)
static int32_t g_fragment_phone_purchase_date = 0;
static int64_t g_fragment_phone_amount        = 0;
static int64_t g_fragment_phone_crypto_amount = 0;
static char    g_fragment_phone_currency[64]        = {0};
static char    g_fragment_phone_crypto_currency[64] = {0};
static char    g_fragment_phone_url[128]            = {0};
static int32_t g_fragment_req_ring[PG_MAX_TRACKED_FRAGMENT_REQUESTS] = {0};  // 0 = empty slot
// Custom fact check — attach a fake local fact-check note by answering messages.getFactCheck with our own
// Vector<factCheck> (response-replace ring; the genuine reply still flows if we don't substitute → never a crash).
static bool    g_fact_check_enabled        = false;
static char    g_fact_check_text[256]      = {0};
static char    g_fact_check_country[64]    = {0};
static int64_t g_fact_check_hash           = 0;
static bool    g_fact_check_need_check     = false;
static int32_t g_fact_check_req_ring[PG_MAX_TRACKED_FACT_CHECK_REQUESTS]  = {0};  // requestId (0 = empty)
static int32_t g_fact_check_req_count[PG_MAX_TRACKED_FACT_CHECK_REQUESTS] = {0};  // msg_id count for that reply
// Custom list usernames — replace the self user's usernames Vector in tracked getFullUser/getUsers replies.
static bool g_custom_usernames_enabled = false;
static char g_custom_usernames[PG_MAX_CUSTOM_USERNAMES][64];
static size_t g_custom_usernames_count = 0;
static int32_t g_custom_username_req_ring[PG_MAX_TRACKED_FRAGMENT_REQUESTS] = {0};
// Per-username Fragment collectible info (payload fields 2..7), so tapping a collectible username answers
// with a built fragment.collectibleInfo (same as the phone). Parallel to g_custom_usernames[].
static int32_t g_cu_date[PG_MAX_CUSTOM_USERNAMES]          = {0};
static int64_t g_cu_amount[PG_MAX_CUSTOM_USERNAMES]        = {0};
static int64_t g_cu_crypto_amount[PG_MAX_CUSTOM_USERNAMES] = {0};
static char    g_cu_currency[PG_MAX_CUSTOM_USERNAMES][16];
static char    g_cu_crypto_currency[PG_MAX_CUSTOM_USERNAMES][16];
static char    g_cu_url[PG_MAX_CUSTOM_USERNAMES][256];
static int32_t g_cu_coll_req[PG_MAX_TRACKED_FRAGMENT_REQUESTS] = {0};  // tracked getCollectibleInfo{username} requestId
static int32_t g_cu_coll_idx[PG_MAX_TRACKED_FRAGMENT_REQUESTS] = {0};  // → username index to answer with
// Gift spoof (base scalar subset; applies to all payments.savedStarGifts responses = "everyone" mode).
static bool    g_gift_spoof_enabled        = false;
static int64_t g_gift_spoof_sender_id      = 0;
static int     g_gift_spoof_sender_peer_type = 0;    // 0 user, 1 channel, 2 chat
static int32_t g_gift_spoof_date           = 0;
static int64_t g_gift_spoof_gift_id        = 0;
static int64_t g_gift_spoof_sticker_id     = 0;
static int64_t g_gift_spoof_stars          = 0;
static int64_t g_gift_spoof_convert_stars  = 0;
static int32_t g_gift_spoof_available      = 0;
static int32_t g_gift_spoof_total          = 0;
static int     g_gift_spoof_force_limited  = 0;
static int32_t g_gift_spoof_gift_num       = 0;
static int     g_gift_spoof_was_refunded   = 0;
static int     g_gift_spoof_upgrade        = 0;   // set savedStarGift.can_upgrade (shows Upgrade button)
static char    g_gift_spoof_caption[1024]  = {0}; // savedStarGift.message text (inject TWE)
static int     g_gift_spoof_auction        = 0;   // set starGift.auction + insert the auction trio
// Spoof profile UNIQUE gifts: rebuild the first regular starGift in a savedStarGifts response as an upgraded
// starGiftUnique with these attributes (engine: pg_gift_unique_rebuild).
static bool    g_gift_unique_enabled       = false;
static char    g_unique_title[256]         = {0};
static int32_t g_unique_num                = 0;
static int64_t g_unique_gift_id            = 0;
static char    g_unique_model_name[128]    = {0};
static int32_t g_unique_model_rarity       = 0;
static char    g_unique_symbol_name[128]   = {0};
static int32_t g_unique_symbol_rarity      = 0;
static char    g_unique_backdrop_name[128] = {0};
static int32_t g_unique_backdrop_center    = 0;
static int32_t g_unique_backdrop_edge      = 0;
static int32_t g_unique_backdrop_pattern   = 0;
static int32_t g_unique_backdrop_text      = 0;
static int32_t g_unique_backdrop_rarity    = 0;
static int32_t g_unique_total_upgraded     = 0;   // availability_issued ("N of M")
static int32_t g_unique_max_upgraded       = 0;   // availability_total
static int64_t g_unique_owner_id           = 0;
static int     g_unique_owner_peer_type    = 0;
static int64_t g_unique_host_id            = 0;
static int     g_unique_host_peer_type     = 0;
static char    g_unique_owner_address[128] = {0};
static int64_t g_unique_value_amount       = 0;
static int64_t g_unique_value_usd          = 0;
static char    g_unique_value_currency[16] = {0};
static uint64_t g_unique_model_emoji_id    = 0;   // model attribute document.id (0 = clone gift's own sticker)
static uint64_t g_unique_symbol_emoji_id   = 0;   // pattern attribute document.id
// Last-resale value info: answered separately (payments.getUniqueStarGiftValueInfo → uniqueStarGiftValueInfo).
static int64_t g_unique_last_resale_amount   = 0;
static int32_t g_unique_last_resale_date     = 0;
static char    g_unique_last_resale_currency[16] = {0};
// Gift target mode (0=all / 10=allExceptMe / 20=onlySelf): only rewrite the targeted profile's gifts. Done by
// tracking the payments.getSavedStarGifts request's peer (inputPeerSelf#7da07ec9 = self) → ring → response take.
#define PG_MAX_TRACKED_GIFT_REQUESTS 32
static int     g_gift_spoof_target_mode    = 0;
static int     g_gift_unique_target_mode   = 0;
static int32_t g_gift_spoof_req_ring[PG_MAX_TRACKED_GIFT_REQUESTS]  = {0};
static int32_t g_gift_unique_req_ring[PG_MAX_TRACKED_GIFT_REQUESTS] = {0};
static int32_t g_value_info_req_ring[PG_MAX_TRACKED_GIFT_REQUESTS]  = {0};   // getUniqueStarGiftValueInfo ring
// Fake transfer (requires giftUniqueEnabled): fabricate the payments.transferStarGift -> Updates reply that
// carries a local "transferred" service message; rewrite the getPaymentForm error so the direct transfer fires.
static bool    g_fake_transfer_enabled = false;
static struct { int32_t request_id; int peer_type; int64_t peer_id; } g_transfer_reqs[PG_MAX_TRACKED_GIFT_REQUESTS] = {0};
static int32_t g_transfer_form_ring[PG_MAX_TRACKED_GIFT_REQUESTS] = {0};
static uint32_t g_transfer_msg_seq = 0;
static uint8_t  g_transfer_src_doc[4096];
static size_t   g_transfer_src_doc_len = 0;
static bool    g_realloc_live_test         = false;  // one-shot identity-replace on a real buffer (diag)
// Show hidden gifts: inject extra starGift entries into the payments.starGifts catalog response.
#define PG_MAX_HIDDEN_GIFTS 24
static int     g_show_hidden_gifts_enabled = 0;
static int     g_hidden_gift_count         = 0;
static int64_t g_hidden_gift_ids[PG_MAX_HIDDEN_GIFTS]  = {0};
static int64_t g_hidden_emoji_ids[PG_MAX_HIDDEN_GIFTS] = {0};
// Request-side patches (no IDA — pure TL rewrite/drop in sendPrepared).
static bool    g_always_offline_enabled    = false;  // force account.updateStatus offline = boolTrue
static bool    g_block_typing_enabled      = false;  // drop messages.setTyping
static bool    g_block_read_enabled        = false;  // drop read-history/contents requests
static bool    g_local_drafts_enabled      = false;  // drop messages.saveDraft (drafts stay local, never sync)
static bool    g_no_phone_on_add_enabled   = false;  // strip add_phone_privacy_exception in addContact
static bool    g_disable_ads_telegram       = false;  // drop messages.getSponsoredMessages (Telegram Ads)
static bool    g_disable_ads_proxy          = false;  // drop help.getPromoData (proxy sponsor / top-promo)
static bool    g_hide_stories_enabled        = false;  // drop stories.* fetch requests (empty the stories feed)
// Byte-patch family (applied to .text by the C++ side; this just owns the enable flag from config).
static bool    g_recent_stickers_enabled   = false;  // raise recent-stickers display limit (jb->jmp)
static bool    g_sensitive_blur_enabled    = false;  // HistoryItem::isMediaSensitive -> return false
static bool    g_disable_spoilers_enabled   = false;  // Data::CreateMedia -> force spoiler flag false
static bool    g_disable_ttl_enabled        = false;  // force view-once media ttl_seconds = 0 (byte-patches)
static bool    g_premium_effects_enabled    = false;  // checkPremiumEffectStart -> early ret (no effect)
static bool    g_account_limit_999_enabled  = false;  // Main::Domain/Storage::Domain account cap 6 -> 999
static bool    g_local_premium_enabled      = false;  // premiumPossibleValue -> force premium bit true
static bool    g_callback_hover_enabled     = false;  // getUrlButton -> widen accepted button types
static bool    g_open_links_enabled         = false;  // HiddenUrlClickHandler::Open -> skip the warning box
static bool    g_hide_self_phone_enabled    = false;  // PhoneOrHiddenValue hook -> empty phone for self
static bool    g_custom_stars_enabled       = false;  // CreditsAmountFromTL -> return custom Stars amount
static int64_t g_custom_stars_value         = 999;
static bool    g_custom_ton_enabled         = false;  // (shares the one credits fn — exclusive with stars)
static int64_t g_custom_ton_value           = 999;
static bool    g_peer_badge_enabled         = false;  // UserData::setFlags hook -> force a verified/scam/fake badge
static int     g_peer_badge_mode            = 0;      // 0=All, 10=All except me, 20=Only me
static int     g_peer_badge_type            = 1;      // 1=Verified(0x8) 2=Scam(0x10) 3=Fake(0x20)
static bool    g_custom_level_rating_enabled = false; // UserData::setFlags hook -> write _starsRating @+0x230
static int     g_clr_mode                    = 0;     // parsed target mode 0=All 10=AllExceptMe 20=OnlyMe
static int32_t g_clr_level = 1, g_clr_rating = 1000, g_clr_current = 0, g_clr_next = 2000;
static bool    g_local_channel_enabled      = false;  // setFlags hook -> write _personalChannelId @+0x240
static int     g_local_channel_mode         = 0;
static int64_t g_local_channel_id           = 0;      // bare ChannelId
static int64_t g_local_channel_msg          = 0;
static bool    g_custom_phone_enabled       = false;  // PhoneOrHiddenValue hook -> show a custom phone (self)
static char    g_custom_phone[64]           = {0};
static bool    g_custom_userid_enabled      = false;  // QLocale::toString hook -> swap displayed self id
static int64_t g_custom_userid              = 0;
static bool    g_bot_verify_enabled         = false;  // force UserData::setBotVerifyDetails for targets
static int     g_bot_verify_mode            = 0;
static uint64_t g_bot_verify_icon_id        = 0;      // custom emoji DocumentId
static char    g_bot_verify_desc[128]       = {0};

static bool json_bool(const char *json, const char *key, bool fallback) {
    if (!json) return fallback;
    char needle[128];
    snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *found = strstr(json, needle);
    if (!found) return fallback;
    const char *colon = strchr(found, ':');
    if (!colon) return fallback;
    colon++;
    while (*colon==' '||*colon=='\n'||*colon=='\r'||*colon=='\t') colon++;
    if (strncmp(colon, "true", 4) == 0)  return true;
    if (strncmp(colon, "false", 5) == 0) return false;
    return fallback;
}
static int64_t json_i64(const char *json, const char *key, int64_t fallback) {
    if (!json) return fallback;
    char needle[128];
    snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *found = strstr(json, needle);
    if (!found) return fallback;
    const char *colon = strchr(found, ':');
    if (!colon) return fallback;
    while (*colon && *colon != '-' && (*colon < '0' || *colon > '9')) colon++;
    if (!*colon) return fallback;
    return strtoll(colon, NULL, 10);
}
// Minimal JSON string reader (no \uXXXX): copies "key":"<value>" into out. Empty out if absent.
static void json_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!out || out_size == 0) return;
    out[0] = 0;
    if (!json) return;
    char needle[128];
    snprintf(needle, sizeof needle, "\"%s\"", key);
    const char *found = strstr(json, needle);
    if (!found) return;
    const char *colon = strchr(found, ':');
    if (!colon) return;
    const char *start = strchr(colon, '"');
    if (!start) return;
    start++;
    size_t off = 0;
    for (const char *c = start; *c; ) {
        char ch = *c++;
        if (ch == '"') break;
        if (ch == '\\') {                       // decode JSON escapes (esp. \n — the username payload separator)
            char e = *c++; if (!e) break;
            switch (e) {
                case 'n': ch = '\n'; break; case 't': ch = '\t'; break; case 'r': ch = '\r'; break;
                case 'b': ch = '\b'; break; case 'f': ch = '\f'; break;
                default:  ch = e;    break;     // \" \\ \/ → the literal char
            }
        }
        if (off + 1 < out_size) out[off++] = ch;
    }
    out[off] = 0;
}

// Parse a channel reference string -> bare ChannelId. Accepts a bare id, or a Bot-API channel id like
// -1001234567890 (= -(1000000000000 + bare)) which we strip to the bare 1234567890.
static int64_t pg_parse_channel_id(const char *ref) {
    if (!ref || !ref[0]) return 0;
    long long v = strtoll(ref, NULL, 10);
    if (v < 0) { long long a = -v; v = (a > 1000000000000LL) ? (a - 1000000000000LL) : a; }
    return (int64_t)v;
}

// Parse a macOS target-mode string into the engine's int convention (0=All, 10=All-except-me, 20=Only-me).
static int pg_parse_target_mode(const char *json, const char *key) {
    char m[32]; json_string(json, key, m, sizeof m);
    if (strcmp(m, "onlySelf") == 0) return 20;
    if (strcmp(m, "allExceptSelf") == 0) return 10;
    return 0;  // "all" / absent
}

int pg_config_load(const char *json) {
    g_logger_enabled                = json_bool(json, "mtprotoLoggerEnabled", true);
    g_message_settings_enabled      = json_bool(json, "messageSettingsEnabled", false);
    g_message_allow_noforwards_copy = json_bool(json, "messageNoForwardsCopyEnabled", false);
    g_account_freeze_enabled        = json_bool(json, "accountFreezeEnabled", false);
    // Disable monetization: sub-features default to the master so the master alone enables everything macOS shows.
    g_disable_monetization_enabled        = json_bool(json, "disableMonetizationEnabled", false);
    {
        bool dm = g_disable_monetization_enabled;
        g_disable_monetization_app_config     = json_bool(json, "disableMonetizationAppConfigEnabled", dm);
        g_disable_monetization_premium_ui     = json_bool(json, "disableMonetizationPremiumUIEnabled", dm);
        g_disable_monetization_gifts          = json_bool(json, "disableMonetizationGiftsEnabled", dm);
        g_disable_monetization_paid_reactions = json_bool(json, "disableMonetizationPaidReactionsEnabled", dm);
        g_disable_monetization_emoji_statuses = json_bool(json, "disableMonetizationEmojiStatusesEnabled", dm);
        g_disable_monetization_stars_ton      = json_bool(json, "disableMonetizationStarsTonCollectiblesEnabled", dm);
        g_disable_monetization_boosts         = json_bool(json, "disableMonetizationBoostsEnabled", dm);
        g_disable_monetization_read_receipts  = json_bool(json, "disableMonetizationReadReceiptsEnabled", dm);
    }
    g_gift_spoof_enabled            = json_bool(json, "giftSpoofEnabled", false);
    g_gift_spoof_sender_id          = json_i64(json, "giftSpoofSenderId", 0);
    g_gift_spoof_sender_peer_type   = (int)json_i64(json, "giftSpoofSenderPeerType", 0);
    g_gift_spoof_date               = (int32_t)json_i64(json, "giftSpoofDate", 0);
    g_gift_spoof_gift_id            = json_i64(json, "giftSpoofGiftId", 0);
    g_gift_spoof_sticker_id         = json_i64(json, "giftSpoofStickerId", 0);
    g_gift_spoof_stars              = json_i64(json, "giftSpoofStars", 0);
    g_gift_spoof_convert_stars      = json_i64(json, "giftSpoofConvertStars", 0);
    g_gift_spoof_available          = (int32_t)json_i64(json, "giftSpoofAvailable", 0);
    g_gift_spoof_total              = (int32_t)json_i64(json, "giftSpoofTotal", 0);
    g_gift_spoof_force_limited      = json_bool(json, "giftSpoofLimited", false) ? 1 : 0;
    g_gift_spoof_gift_num           = (int32_t)json_i64(json, "giftSpoofGiftNum", 0);
    g_gift_spoof_was_refunded       = json_bool(json, "giftSpoofWasRefunded", false) ? 1 : 0;
    g_gift_spoof_upgrade            = json_bool(json, "giftSpoofUpgrade", false) ? 1 : 0;
    g_gift_spoof_auction            = json_bool(json, "giftSpoofAuction", false) ? 1 : 0;
    json_string(json, "giftSpoofCaption", g_gift_spoof_caption, sizeof g_gift_spoof_caption);
    g_gift_spoof_target_mode        = pg_parse_target_mode(json, "giftSpoofTargetMode");
    if (g_gift_spoof_target_mode == 0) memset(g_gift_spoof_req_ring, 0, sizeof g_gift_spoof_req_ring);
    // Spoof profile unique gifts (rebuild starGift -> starGiftUnique).
    g_gift_unique_enabled    = json_bool(json, "giftUniqueEnabled", false);
    g_gift_unique_target_mode = pg_parse_target_mode(json, "giftUniqueTargetMode");
    if (g_gift_unique_target_mode == 0) memset(g_gift_unique_req_ring, 0, sizeof g_gift_unique_req_ring);
    { char e[32]; json_string(json, "giftUniqueModelEmojiId", e, sizeof e); g_unique_model_emoji_id = strtoull(e, NULL, 10); }
    { char e[32]; json_string(json, "giftUniqueSymbolEmojiId", e, sizeof e); g_unique_symbol_emoji_id = strtoull(e, NULL, 10); }
    g_unique_last_resale_amount = json_i64(json, "giftUniqueLastResaleAmount", 0);
    g_unique_last_resale_date   = (int32_t)json_i64(json, "giftUniqueLastResaleDate", 0);
    json_string(json, "giftUniqueLastResaleCurrency", g_unique_last_resale_currency, sizeof g_unique_last_resale_currency);
    // Fake transfer (requires giftUnique — the transferred gift blob + doc come from the unique pipeline).
    g_fake_transfer_enabled = json_bool(json, "giftFakeTransferEnabled", false) && g_gift_unique_enabled;
    if (!g_fake_transfer_enabled) { memset(g_transfer_reqs, 0, sizeof g_transfer_reqs); }
    json_string(json, "giftUniqueTitle",        g_unique_title,         sizeof g_unique_title);
    json_string(json, "giftUniqueModelName",    g_unique_model_name,    sizeof g_unique_model_name);
    json_string(json, "giftUniqueSymbolName",   g_unique_symbol_name,   sizeof g_unique_symbol_name);
    json_string(json, "giftUniqueBackdropName", g_unique_backdrop_name, sizeof g_unique_backdrop_name);
    json_string(json, "giftUniqueOwnerAddress", g_unique_owner_address, sizeof g_unique_owner_address);
    json_string(json, "giftUniqueValueCurrency",g_unique_value_currency,sizeof g_unique_value_currency);
    g_unique_num             = (int32_t)json_i64(json, "giftUniqueNum", 0);
    g_unique_gift_id         = json_i64(json, "giftUniqueGiftId", 0);
    g_unique_model_rarity    = (int32_t)json_i64(json, "giftUniqueModelRarity", 0);
    g_unique_symbol_rarity   = (int32_t)json_i64(json, "giftUniqueSymbolRarity", 0);
    g_unique_backdrop_center = (int32_t)json_i64(json, "giftUniqueBackdropCenter", 0);
    g_unique_backdrop_edge   = (int32_t)json_i64(json, "giftUniqueBackdropEdge", 0);
    g_unique_backdrop_pattern= (int32_t)json_i64(json, "giftUniqueBackdropPattern", 0);
    g_unique_backdrop_text   = (int32_t)json_i64(json, "giftUniqueBackdropText", 0);
    g_unique_backdrop_rarity = (int32_t)json_i64(json, "giftUniqueBackdropRarity", 0);
    g_unique_total_upgraded  = (int32_t)json_i64(json, "giftUniqueTotalUpgraded", 0);
    g_unique_max_upgraded    = (int32_t)json_i64(json, "giftUniqueMaxUpgraded", 0);
    g_unique_owner_id        = json_i64(json, "giftUniqueOwnerId", 0);
    g_unique_owner_peer_type = (int)json_i64(json, "giftUniqueOwnerPeerType", 0);
    g_unique_host_id         = json_i64(json, "giftUniqueHostId", 0);
    g_unique_host_peer_type  = (int)json_i64(json, "giftUniqueHostPeerType", 0);
    g_unique_value_amount    = json_i64(json, "giftUniqueValueAmount", 0);
    g_unique_value_usd       = json_i64(json, "giftUniqueValueUsdAmount", 0);
    g_realloc_live_test             = json_bool(json, "reallocLiveTestEnabled", false);
    g_show_hidden_gifts_enabled     = json_bool(json, "giftShowHiddenEnabled", false) ? 1 : 0;
    g_hidden_gift_count = 0;
    {
        static char payload[PG_MAX_HIDDEN_GIFTS * 48];
        json_string(json, "giftHiddenPayload", payload, sizeof payload);  // "giftId:emojiId,giftId:emojiId,..."
        const char *p = payload;
        while (*p && g_hidden_gift_count < PG_MAX_HIDDEN_GIFTS) {
            char *end = NULL;
            long long gid = strtoll(p, &end, 10);
            if (end == p || *end != ':') break;
            p = end + 1;
            long long eid = strtoll(p, &end, 10);
            if (end == p) break;
            p = end;
            if (gid && eid) { g_hidden_gift_ids[g_hidden_gift_count] = gid;
                              g_hidden_emoji_ids[g_hidden_gift_count] = eid; g_hidden_gift_count++; }
            while (*p == ',' || *p == ' ') p++;
        }
        if (g_show_hidden_gifts_enabled && g_hidden_gift_count == 0) {  // no payload → baked-in defaults (as macOS)
            static const int64_t def_gift[]  = { 6026193266406327981LL, 5969796561943660080LL, 5935895822435615975LL,
                5893356958802511476LL, 5866352046986232958LL, 5801108895304779062LL, 5800655655995968830LL,
                5922558454332916696LL, 5956217000635139069LL };
            static const int64_t def_emoji[] = { 5447213743417105726LL, 5393309541620291208LL, 5359736160224586485LL,
                5317000922096769303LL, 5294268489127731562LL, 5224628072619216265LL, 5226661632259691727LL,
                5345935030143196497LL, 5379850840691476775LL };
            const int n = (int)(sizeof def_gift / sizeof def_gift[0]);
            for (int i = 0; i < n && i < PG_MAX_HIDDEN_GIFTS; i++) {
                g_hidden_gift_ids[i] = def_gift[i]; g_hidden_emoji_ids[i] = def_emoji[i];
            }
            g_hidden_gift_count = n;
        }
    }
    g_always_offline_enabled  = json_bool(json, "alwaysOfflineEnabled", false);
    g_block_typing_enabled    = json_bool(json, "blockTypingEnabled", false);
    g_local_drafts_enabled    = json_bool(json, "localDraftsEnabled", false);
    g_block_read_enabled      = json_bool(json, "blockReadMessagesEnabled", false);
    g_no_phone_on_add_enabled = json_bool(json, "noPhoneOnAddEnabled", false);
    // "Disable ads" split into its two macOS subpatches (Telegram Ads / Proxy sponsor). The legacy
    // single key disableAdsEnabled still turns on BOTH for backward compatibility.
    bool ads_all              = json_bool(json, "disableAdsEnabled", false);
    g_disable_ads_telegram    = ads_all || json_bool(json, "disableAdsTelegramEnabled", false);
    g_disable_ads_proxy       = ads_all || json_bool(json, "disableAdsProxyEnabled", false);
    g_hide_stories_enabled    = json_bool(json, "hideStoriesEnabled", false);
    g_recent_stickers_enabled = json_bool(json, "recentStickersUnlimitedEnabled", false);
    g_sensitive_blur_enabled  = json_bool(json, "sensitiveBlurEnabled", false);
    g_disable_spoilers_enabled = json_bool(json, "disableSpoilersEnabled", false);
    g_disable_ttl_enabled      = json_bool(json, "disableTtlEnabled", false);
    g_premium_effects_enabled  = json_bool(json, "disablePremiumEffectsEnabled", false);
    g_account_limit_999_enabled = json_bool(json, "accountLimit999Enabled", false);
    g_local_premium_enabled    = json_bool(json, "localPremiumEnabled", false);
    g_callback_hover_enabled   = json_bool(json, "callbackHoverEnabled", false);
    g_open_links_enabled       = json_bool(json, "openLinksEnabled", false);
    g_hide_self_phone_enabled  = json_bool(json, "hideSelfPhoneEnabled", false);
    g_custom_stars_enabled     = json_bool(json, "customStarsEnabled", false);
    g_custom_stars_value       = json_i64(json, "customStarsValue", 999);
    g_custom_ton_enabled       = json_bool(json, "customTonEnabled", false);
    g_custom_ton_value         = json_i64(json, "customTonValue", 999);
    g_peer_badge_enabled       = json_bool(json, "peerBadgeEnabled", false);
    g_peer_badge_mode          = (int)json_i64(json, "peerBadgeMode", 0);
    g_peer_badge_type          = (int)json_i64(json, "peerBadgeType", 1);
    g_custom_level_rating_enabled = json_bool(json, "customLevelRatingEnabled", false);
    g_clr_mode    = pg_parse_target_mode(json, "customLevelRatingTargetMode");
    g_clr_level   = (int32_t)json_i64(json, "customLevelRatingLevel", 1);
    g_clr_rating  = (int32_t)json_i64(json, "customLevelRatingRating", 1000);
    g_clr_current = (int32_t)json_i64(json, "customLevelRatingCurrentLevelRating", 0);
    g_clr_next    = (int32_t)json_i64(json, "customLevelRatingNextLevelRating", 2000);
    g_local_channel_enabled = json_bool(json, "localChannelEnabled", false);
    char lchref[64]; json_string(json, "localChannelReference", lchref, sizeof lchref);
    g_local_channel_id  = pg_parse_channel_id(lchref);
    g_local_channel_msg = json_i64(json, "localChannelMessageId", 0);
    g_local_channel_mode = pg_parse_target_mode(json, "localChannelTargetMode");
    g_custom_phone_enabled = json_bool(json, "customPhoneEnabled", false);
    json_string(json, "customPhone", g_custom_phone, sizeof g_custom_phone);
    // Fragment phone (collectible-info response ring; keys mirror macOS fragmentPhone*).
    g_fragment_phone_enabled       = json_bool(json, "fragmentPhoneEnabled", false);
    g_fragment_phone_target_mode   = pg_parse_target_mode(json, "fragmentPhoneTargetMode");
    g_fragment_phone_purchase_date = (int32_t)json_i64(json, "fragmentPhonePurchaseDate", 0);
    g_fragment_phone_amount        = json_i64(json, "fragmentPhoneAmount", 0);
    g_fragment_phone_crypto_amount = json_i64(json, "fragmentPhoneCryptoAmount", 0);
    json_string(json, "fragmentPhoneCurrency",       g_fragment_phone_currency,        sizeof g_fragment_phone_currency);
    json_string(json, "fragmentPhoneCryptoCurrency", g_fragment_phone_crypto_currency, sizeof g_fragment_phone_crypto_currency);
    json_string(json, "fragmentPhoneUrl",            g_fragment_phone_url,             sizeof g_fragment_phone_url);
    if (!g_fragment_phone_enabled) memset(g_fragment_req_ring, 0, sizeof g_fragment_req_ring);
    // Custom fact check (response ring; GUI keys factCheck*).
    g_fact_check_enabled    = json_bool(json, "factCheckEnabled", false);
    json_string(json, "factCheckText",    g_fact_check_text,    sizeof g_fact_check_text);
    json_string(json, "factCheckCountry", g_fact_check_country, sizeof g_fact_check_country);
    g_fact_check_hash       = json_i64(json, "factCheckHash", 0);
    g_fact_check_need_check = json_bool(json, "factCheckNeedCheck", false);
    if (!g_fact_check_enabled) { memset(g_fact_check_req_ring, 0, sizeof g_fact_check_req_ring);
                                 memset(g_fact_check_req_count, 0, sizeof g_fact_check_req_count); }
    // Custom list usernames: payload = newline-separated "username|collectible|date|cur|amt|ccur|camt|url".
    // Field 0 = the username (entry 0 becomes editable/primary); fields 2..7 = the Fragment collectible info
    // answered when that username is tapped (parallel arrays, used by pg_cu_collectible).
    g_custom_usernames_enabled = json_bool(json, "customListUsernamesEnabled", false);
    { char up[8192]; json_string(json, "customListUsernamesPayload", up, sizeof up);
      memset(g_custom_usernames, 0, sizeof g_custom_usernames); g_custom_usernames_count = 0;
      memset(g_cu_date, 0, sizeof g_cu_date); memset(g_cu_amount, 0, sizeof g_cu_amount);
      memset(g_cu_crypto_amount, 0, sizeof g_cu_crypto_amount); memset(g_cu_currency, 0, sizeof g_cu_currency);
      memset(g_cu_crypto_currency, 0, sizeof g_cu_crypto_currency); memset(g_cu_url, 0, sizeof g_cu_url);
      char *line = up;
      while (line && *line && g_custom_usernames_count < PG_MAX_CUSTOM_USERNAMES) {
          char *next = strchr(line, '\n'); if (next) { *next = 0; next++; }
          char *f[8] = {0}; int nf = 0; char *p = line;                  // split into <=8 pipe fields
          f[nf++] = p;
          while (nf < 8 && (p = strchr(p, '|')) != NULL) { *p++ = 0; f[nf++] = p; }
          char *u = f[0]; if (*u == '@') u++;
          size_t n = strlen(u);
          if (n > 0 && n <= 32) {
              size_t idx = g_custom_usernames_count;
              snprintf(g_custom_usernames[idx], 64, "%s", u);
              g_cu_date[idx]          = f[2] ? (int32_t)strtol(f[2], NULL, 10) : 0;
              if (f[3]) snprintf(g_cu_currency[idx], 16, "%s", f[3]);
              g_cu_amount[idx]        = f[4] ? strtoll(f[4], NULL, 10) : 0;
              if (f[5]) snprintf(g_cu_crypto_currency[idx], 16, "%s", f[5]);
              g_cu_crypto_amount[idx] = f[6] ? strtoll(f[6], NULL, 10) : 0;
              if (f[7]) snprintf(g_cu_url[idx], 256, "%s", f[7]);
              g_custom_usernames_count++;
          }
          line = next;
      } }
    if (!g_custom_usernames_enabled || g_custom_usernames_count == 0) {
        memset(g_custom_username_req_ring, 0, sizeof g_custom_username_req_ring);
        memset(g_cu_coll_req, 0, sizeof g_cu_coll_req);
    }
    g_custom_userid_enabled = json_bool(json, "customUserIdEnabled", false);
    char uid[32]; json_string(json, "customUserId", uid, sizeof uid);
    g_custom_userid = strtoll(uid, NULL, 10);   // 0 (empty) = keep original
    g_bot_verify_enabled = json_bool(json, "botVerifyEnabled", false);
    g_bot_verify_mode = pg_parse_target_mode(json, "botVerifyTargetMode");
    if ((int)json_i64(json, "botVerifyPreset", 0) == 1) {   // Custom
        char e[32]; json_string(json, "botVerifyCustomEmojiId", e, sizeof e);
        g_bot_verify_icon_id = strtoull(e, NULL, 10);
        json_string(json, "botVerifyDescription", g_bot_verify_desc, sizeof g_bot_verify_desc);
    } else {                                                 // Scared Cat preset
        g_bot_verify_icon_id = 5222202915040555254ULL;
        strncpy(g_bot_verify_desc, "Meow", sizeof g_bot_verify_desc - 1);
    }
    int noforwards = (g_message_settings_enabled && g_message_allow_noforwards_copy) ? 1 : 0;
    int reqpatches = (g_always_offline_enabled ? 1 : 0) + (g_block_typing_enabled ? 1 : 0)
                   + (g_block_read_enabled ? 1 : 0) + (g_no_phone_on_add_enabled ? 1 : 0)
                   + (g_disable_ads_telegram ? 1 : 0) + (g_disable_ads_proxy ? 1 : 0)
                   + (g_hide_stories_enabled ? 1 : 0);
    int monet = (g_disable_monetization_enabled && g_disable_monetization_premium_ui) ? 1 : 0;
    int enabled = noforwards + (g_account_freeze_enabled ? 1 : 0) + (g_gift_spoof_enabled ? 1 : 0)
                + (g_show_hidden_gifts_enabled ? 1 : 0) + monet + reqpatches;
    pg_logf("# config loaded: logger=%d noforwardsCopy=%d accountFreeze=%d giftSpoof=%d hiddenGifts=%d(%d)"
            " offline=%d blockTyping=%d blockRead=%d noPhone=%d disableAds=%d hideStories=%d monetPremiumUI=%d",
            g_logger_enabled ? 1 : 0, noforwards, g_account_freeze_enabled ? 1 : 0,
            g_gift_spoof_enabled ? 1 : 0, g_show_hidden_gifts_enabled ? 1 : 0, g_hidden_gift_count,
            g_always_offline_enabled ? 1 : 0, g_block_typing_enabled ? 1 : 0,
            g_block_read_enabled ? 1 : 0, g_no_phone_on_add_enabled ? 1 : 0,
            (g_disable_ads_telegram || g_disable_ads_proxy) ? 1 : 0, g_hide_stories_enabled ? 1 : 0, monet);
    return enabled;
}

bool pg_logger_enabled(void) { return g_logger_enabled; }
bool pg_recent_stickers_enabled(void) { return g_recent_stickers_enabled; }
bool pg_hide_stories_enabled(void) { return g_hide_stories_enabled; }
bool pg_sensitive_blur_enabled(void) { return g_sensitive_blur_enabled; }
bool pg_disable_spoilers_enabled(void) { return g_disable_spoilers_enabled; }
bool pg_disable_ttl_enabled(void) { return g_disable_ttl_enabled; }
bool pg_premium_effects_enabled(void) { return g_premium_effects_enabled; }
bool pg_account_limit_999_enabled(void) { return g_account_limit_999_enabled; }
bool pg_local_premium_enabled(void) { return g_local_premium_enabled; }
bool pg_callback_hover_enabled(void) { return g_callback_hover_enabled; }
bool pg_open_links_enabled(void) { return g_open_links_enabled; }
bool pg_hide_self_phone_enabled(void) { return g_hide_self_phone_enabled; }
bool pg_custom_stars_enabled(void) { return g_custom_stars_enabled; }
int64_t pg_custom_stars_value(void) { return g_custom_stars_value; }
bool pg_custom_ton_enabled(void) { return g_custom_ton_enabled; }
int64_t pg_custom_ton_value(void) { return g_custom_ton_value; }
bool pg_peer_badge_enabled(void) { return g_peer_badge_enabled; }
int  pg_peer_badge_mode(void) { return g_peer_badge_mode; }
int  pg_peer_badge_type(void) { return g_peer_badge_type; }
bool pg_custom_level_rating_enabled(void) { return g_custom_level_rating_enabled; }
int  pg_clr_mode(void) { return g_clr_mode; }
void pg_clr_values(int32_t *out4) { out4[0]=g_clr_level; out4[1]=g_clr_rating; out4[2]=g_clr_current; out4[3]=g_clr_next; }
bool pg_local_channel_enabled(void) { return g_local_channel_enabled; }
int  pg_local_channel_mode(void) { return g_local_channel_mode; }
int64_t pg_local_channel_id(void) { return g_local_channel_id; }
int64_t pg_local_channel_msg(void) { return g_local_channel_msg; }
bool pg_custom_phone_enabled(void) { return g_custom_phone_enabled; }
const char *pg_custom_phone_text(void) { return g_custom_phone; }
bool pg_custom_userid_enabled(void) { return g_custom_userid_enabled; }
int64_t pg_custom_userid_value(void) { return g_custom_userid; }
bool pg_bot_verify_enabled(void) { return g_bot_verify_enabled; }
int  pg_bot_verify_mode(void) { return g_bot_verify_mode; }
uint64_t pg_bot_verify_icon_id(void) { return g_bot_verify_icon_id; }
const char *pg_bot_verify_desc(void) { return g_bot_verify_desc; }
bool pg_fragment_phone_enabled(void) { return g_fragment_phone_enabled; }

// Build a synthetic Qt5 mtpBuffer (header + 4 words) in our heap, grow it via pg_qvec_grow, and check
// the elements survived + capacity/size are correct. Validates the realloc logic without touching
// Telegram's data. (Uses pg_host_alloc/free, i.e. GetProcessHeap — the same path Telegram frees through.)
void pg_engine_selftest(void) {
    const int32_t hdr = PG_QT5_ARRAYDATA_HEADER_SIZE;
    uint8_t *d = (uint8_t *)pg_host_alloc((size_t)hdr + 4 * 4);
    if (!d) { pg_logf("# SELFTEST grow: alloc failed"); return; }
    *(int32_t *)(d + PG_QT5_ARRAYDATA_REF_OFFSET)    = 1;
    *(int32_t *)(d + PG_QT5_ARRAYDATA_SIZE_OFFSET)   = 4;
    *(uint32_t *)(d + PG_QT5_ARRAYDATA_ALLOC_OFFSET) = 4;
    *(int64_t *)(d + PG_QT5_ARRAYDATA_OFFSET_OFFSET) = hdr;
    uint32_t seed[4] = { 0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u };
    memcpy(d + hdr, seed, sizeof seed);
    void *cont = &d;                                   // a stand-in QVector lvalue (its `d` pointer)
    int ok = pg_qvec_grow(cont, 16);                   // grow capacity 4 -> 16
    if (ok) {
        int32_t wc = 0; uint32_t *w = pg_qvec_data(cont, &wc);
        int32_t cap = pg_qvec_capacity(cont);
        int data_ok = (w && wc == 4 && cap >= 16
                       && w[0] == seed[0] && w[1] == seed[1] && w[2] == seed[2] && w[3] == seed[3]);
        pg_logf("# SELFTEST grow: %s (size=%d cap=%d data_ok=%d)", data_ok ? "PASS" : "FAIL", wc, cap, data_ok);
    } else {
        pg_logf("# SELFTEST grow: skipped (host heap not owned)");
    }
    pg_host_free(*(uint8_t **)cont);                   // free whatever d points at now (grown or original)
}

// ====================================================================================================
// RESPONSE rewriters
// ====================================================================================================

// Copy/save-protect content: force message#7600b9d3 noforwards (flags.26) and channel#1c32b11c
// noforwards (flags.27) to 0 in the wire response, so restricted chats allow copy/save locally.
// Ported from patchgram_strip_noforwards_in_response; a flat wire-scan (no TL walk), in place.
static void pg_strip_noforwards(void *resp) {
    if (!g_message_settings_enabled || !g_message_allow_noforwards_copy) return;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET, &wc);
    if (!words || wc <= 1) return;
    if (!pg_qvec_unshared((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET)) return;  // never edit a shared buffer
    const int64_t scan = (wc < 262144) ? wc : 262144;
    static uint32_t logs = 0;
    for (int64_t i = 0; i + 1 < scan; i++) {
        if (words[i] == 0x7600b9d3u) {            // message#7600b9d3
            if (words[i + 1] & 0x04000000u) {     // flags.26 = noforwards
                words[i + 1] &= ~0x04000000u;
                if (logs < 96) { logs++; pg_logf("NOFORWARDS strip message word=%lld flagsAfter=0x%x",
                                                 (long long)i, words[i + 1]); }
            }
        } else if (words[i] == 0x1c32b11cu) {     // channel#1c32b11c
            if (words[i + 1] & 0x08000000u) {     // flags.27 = noforwards
                words[i + 1] &= ~0x08000000u;
                if (logs < 96) { logs++; pg_logf("NOFORWARDS strip channel word=%lld flagsAfter=0x%x",
                                                 (long long)i, words[i + 1]); }
            }
        }
    }
}

// ---- account freeze: inject freeze_since/until/appeal into the help.appConfig response ----------
// Ported from patchgram_apply_account_freeze_response. Appends 3 jsonObjectValue entries to the config's
// jsonObject vector, IN PLACE within the buffer's existing Qt5 capacity (no realloc), bumps the vector
// count, re-validates the whole object, then publishes the new element count. Skips (logs) if it won't fit.
static int buf_contains(const uint8_t *hay, size_t haylen, const char *needle, size_t nlen) {
    if (nlen == 0 || haylen < nlen) return 0;
    for (size_t i = 0; i + nlen <= haylen; i++) if (memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}
static size_t appcfg_add_number(uint8_t *out, size_t ap, const char *key, double value) {
    size_t klen = strlen(key);
    uint32_t ctor = PG_TL_JSON_OBJECT_VALUE; memcpy(out + ap, &ctor, 4); ap += 4;
    out[ap++] = (uint8_t)klen; memcpy(out + ap, key, klen); ap += klen;
    while (ap & 3u) out[ap++] = 0;
    uint32_t nctor = PG_TL_JSON_NUMBER; memcpy(out + ap, &nctor, 4); ap += 4;
    memcpy(out + ap, &value, 8); ap += 8;
    return ap;
}
static size_t appcfg_add_bool(uint8_t *out, size_t ap, const char *key, bool value) {
    size_t klen = strlen(key);
    uint32_t ctor = PG_TL_JSON_OBJECT_VALUE; memcpy(out + ap, &ctor, 4); ap += 4;
    out[ap++] = (uint8_t)klen; memcpy(out + ap, key, klen); ap += klen;
    while (ap & 3u) out[ap++] = 0;
    uint32_t bctor = PG_TL_JSON_BOOL; memcpy(out + ap, &bctor, 4); ap += 4;
    uint32_t bval = value ? PG_TL_BOOL_TRUE : PG_TL_BOOL_FALSE; memcpy(out + ap, &bval, 4); ap += 4;
    return ap;
}
static size_t appcfg_add_string(uint8_t *out, size_t ap, const char *key, const char *value) {
    size_t klen = strlen(key), vlen = strlen(value);
    uint32_t ctor = PG_TL_JSON_OBJECT_VALUE; memcpy(out + ap, &ctor, 4); ap += 4;
    out[ap++] = (uint8_t)klen; memcpy(out + ap, key, klen); ap += klen;
    while (ap & 3u) out[ap++] = 0;
    uint32_t sctor = PG_TL_JSON_STRING; memcpy(out + ap, &sctor, 4); ap += 4;
    out[ap++] = (uint8_t)vlen; memcpy(out + ap, value, vlen); ap += vlen;
    while (ap & 3u) out[ap++] = 0;
    return ap;
}
static void pg_account_freeze(void *resp) {
    if (!g_account_freeze_enabled) return;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET, &wc);
    if (!words || wc < 5) return;
    if (words[0] != PG_TL_HELP_APP_CONFIG || words[2] != PG_TL_JSON_OBJECT || words[3] != PG_TL_VECTOR_ID) return;
    if (!pg_qvec_unshared((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET)) return;
    uint8_t *w = (uint8_t *)words;
    const size_t old_len = (size_t)wc * 4;
    if (buf_contains(w, old_len, "freeze_since_date", 17)) return;   // already frozen / injected

    static uint8_t add[256];
    size_t ap = 0;
    ap = appcfg_add_number(add, ap, "freeze_since_date", (double)time(NULL));
    ap = appcfg_add_number(add, ap, "freeze_until_date", (double)PG_ACCOUNT_FREEZE_UNTIL);
    ap = appcfg_add_string(add, ap, "freeze_appeal_url", "https://t.me/spambot");
    if (ap == 0 || (ap & 3u) || ap > sizeof add) return;
    const uint32_t injected = 3;
    const int32_t new_wc = wc + (int32_t)(ap / 4);

    const void *cont = (const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET;
    int32_t cap = pg_qvec_capacity(cont);
    static uint32_t logs = 0;
    int grew = 0;
    if (new_wc > cap) {
        // Not enough slack → Qt5 realloc-beyond-capacity (heap-safe, refuses on a foreign heap).
        if (!pg_qvec_grow(cont, new_wc)) {
            if (logs < 8) { logs++; pg_logf("ACCOUNT FREEZE skip: need %d words > capacity %d, grow unavailable", new_wc, cap); }
            return;
        }
        grew = 1;
        words = pg_qvec_data(cont, &wc);   // buffer moved → re-fetch (wc/size unchanged by grow)
        if (!words) return;
        w = (uint8_t *)words;
        cap = pg_qvec_capacity(cont);
    }
    memcpy(w + old_len, add, ap);                                    // append within (now-sufficient) capacity
    uint32_t cnt; memcpy(&cnt, w + 16, 4); cnt += injected; memcpy(w + 16, &cnt, 4);  // bump jsonObject count
    if (!patchgram_tl_validate(w, (size_t)new_wc * 4)) {
        memcpy(&cnt, w + 16, 4); cnt -= injected; memcpy(w + 16, &cnt, 4);            // revert; size never bumped
        if (logs < 8) { logs++; pg_logf("ACCOUNT FREEZE skip: rebuilt response failed validation"); }
        return;
    }
    pg_qvec_set_size(cont, new_wc);                                  // publish new size
    if (logs < 8) { logs++; pg_logf("ACCOUNT FREEZE injected since/until/appeal -> %d words (cap=%d, grew=%d)", new_wc, cap, grew); }
}

// ---- disable monetization (Premium UI sub-feature only) ----
// Inject premium_purchase_blocked=jsonBool(true) into the help.appConfig jsonObject vector (same inject
// machinery as pg_account_freeze). Read site main_session.cpp: _premiumPossible = !config.get<bool>(
// "premium_purchase_blocked", true) — inverted, default true. Injecting true → _premiumPossible=false →
// premiumCanBuy()=false → buy UI hidden, premium deep-links bounce. AppConfig::getBool matches ONLY
// MTPDjsonBool, so jsonBool is the only encoding that takes (jsonString "true"/jsonNumber 1 are ignored).
// The other 7 monetization sub-features have NO appConfig gate and are not reachable at this tier.
static void pg_disable_monetization(void *resp) {
    if (!g_disable_monetization_enabled) return;
    if (!g_disable_monetization_premium_ui) return;   // only sub-feature with an appConfig key
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET, &wc);
    if (!words || wc < 5) return;
    if (words[0] != PG_TL_HELP_APP_CONFIG || words[2] != PG_TL_JSON_OBJECT || words[3] != PG_TL_VECTOR_ID) return;
    // Require an unshared (ref==1) buffer for BOTH the flip and the inject. Writing a SHARED appConfig
    // buffer crashes — it may be cached/concurrently-held/read-only, so even a single-word flip is unsafe
    // (verified: relaxing this for the flip crashed). A shared appConfig is just skipped this delivery; the
    // next unshared one applies. Better intermittent than corrupting Telegram's cached config.
    if (!pg_qvec_unshared((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET)) return;
    uint8_t *w = (uint8_t *)words;
    const size_t old_len = (size_t)wc * 4;
    static uint32_t logs = 0;

    // The real server SENDS premium_purchase_blocked already (as jsonBool boolFalse = "not blocked").
    // When present, FLIP its bool value boolFalse->boolTrue in place — a same-size ctor swap, no resize
    // and no re-validation needed. This is what actually hides the buy UI (read is inverted, default true).
    if (buf_contains(w, old_len, "premium_purchase_blocked", 24)) {
        for (size_t i = 0; i + 24 <= old_len; i++) {
            if (memcmp(w + i, "premium_purchase_blocked", 24) != 0) continue;
            for (size_t j = (i + 24 + 3) & ~(size_t)3; j + 8 <= old_len && j <= i + 24 + 16; j += 4) {
                uint32_t c; memcpy(&c, w + j, 4);
                if (c != PG_TL_JSON_BOOL) continue;
                uint32_t v; memcpy(&v, w + j + 4, 4);
                if (v == PG_TL_BOOL_FALSE) {
                    v = PG_TL_BOOL_TRUE; memcpy(w + j + 4, &v, 4);
                    if (logs < 8) { logs++; pg_logf("DISABLE MONET flipped premium_purchase_blocked false->true"); }
                } else if (logs < 8) { logs++; pg_logf("DISABLE MONET premium_purchase_blocked already %#x", v); }
                return;
            }
            return;   // key present but jsonBool not located (unexpected encoding) — leave untouched
        }
        return;
    }

    // Key absent → inject premium_purchase_blocked=jsonBool(true).
    static uint8_t add[64];
    size_t ap = 0;
    ap = appcfg_add_bool(add, ap, "premium_purchase_blocked", true);   // never inject false: absence already = "not blocked"
    if (ap == 0 || (ap & 3u) || ap > sizeof add) return;
    const uint32_t injected = 1;
    const int32_t new_wc = wc + (int32_t)(ap / 4);

    const void *cont = (const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET;
    int32_t cap = pg_qvec_capacity(cont);
    int grew = 0;
    if (new_wc > cap) {
        if (!pg_qvec_grow(cont, new_wc)) {
            if (logs < 8) { logs++; pg_logf("DISABLE MONET skip: need %d words > capacity %d, grow unavailable", new_wc, cap); }
            return;
        }
        grew = 1;
        words = pg_qvec_data(cont, &wc);   // buffer moved → re-fetch
        if (!words) return;
        w = (uint8_t *)words;
        cap = pg_qvec_capacity(cont);
    }
    memcpy(w + old_len, add, ap);
    uint32_t cnt; memcpy(&cnt, w + 16, 4); cnt += injected; memcpy(w + 16, &cnt, 4);   // bump jsonObject count
    if (!patchgram_tl_validate(w, (size_t)new_wc * 4)) {
        memcpy(&cnt, w + 16, 4); cnt -= injected; memcpy(w + 16, &cnt, 4);             // revert; size never bumped
        if (logs < 8) { logs++; pg_logf("DISABLE MONET skip: rebuilt response failed validation"); }
        return;
    }
    pg_qvec_set_size(cont, new_wc);
    if (logs < 8) { logs++; pg_logf("DISABLE MONET injected premium_purchase_blocked -> %d words (cap=%d, grew=%d)", new_wc, cap, grew); }
}

// ---- gift target-mode request ring (track payments.getSavedStarGifts whose peer matches the mode) ----
static void pg_ring_track(int32_t *ring, int32_t request_id) {
    if (request_id <= 0) return;
    int empty = -1;
    for (int i = 0; i < PG_MAX_TRACKED_GIFT_REQUESTS; i++) {
        if (ring[i] == request_id) return;
        if (ring[i] == 0 && empty < 0) empty = i;
    }
    ring[empty >= 0 ? empty : 0] = request_id;
}
static int pg_ring_take(int32_t *ring, int32_t request_id) {
    if (request_id <= 0) return 0;
    for (int i = 0; i < PG_MAX_TRACKED_GIFT_REQUESTS; i++)
        if (ring[i] == request_id) { ring[i] = 0; return 1; }
    return 0;
}

// forward decls (TL build helpers defined in the fragment-phone section below).
static size_t pg_tl_put_string(uint8_t *out, size_t ap, const char *s);
static size_t pg_put_u32(uint8_t *o, size_t ap, uint32_t v);

// Insert `add` (4-aligned) at insert_off in the response buffer and OR flag_bit into the flags word at
// flag_off, then validate the whole savedStarGifts object; on failure restore the staged tail + original flags
// and don't publish the new size (byte-identical to no-op). Used by caption + auction. Returns 1 on success.
static int pg_gift_insert_field(const void *cont, size_t insert_off, const uint8_t *add, size_t add_len,
                                size_t flag_off, uint32_t flag_bit) {
    if (!add || add_len == 0 || (add_len & 3u)) return 0;
    int32_t wc = 0; uint32_t *words = pg_qvec_data(cont, &wc);
    if (!words || wc <= 0) return 0;
    uint8_t *body = (uint8_t *)words; const size_t old_len = (size_t)wc * 4;
    if (insert_off > old_len || flag_off + 4 > old_len) return 0;
    const size_t changed = old_len - insert_off;
    static uint8_t stage[131072];
    if (changed > sizeof stage) return 0;
    uint32_t orig_flags; memcpy(&orig_flags, body + flag_off, 4);
    memcpy(stage, body + insert_off, changed);                 // stage the tail that will shift
    const int32_t new_wc = wc + (int32_t)(add_len / 4);
    if (new_wc > pg_qvec_capacity(cont)) {
        if (!pg_qvec_grow(cont, new_wc)) return 0;
        words = pg_qvec_data(cont, &wc); if (!words) return 0; body = (uint8_t *)words;
    }
    memmove(body + insert_off + add_len, body + insert_off, changed);   // open the gap
    memcpy(body + insert_off, add, add_len);                            // drop the new field in
    uint32_t f; memcpy(&f, body + flag_off, 4); f |= flag_bit; memcpy(body + flag_off, &f, 4);  // set the flag
    if (!patchgram_tl_validate_top(body, (size_t)new_wc * 4, 0x95f389b1u)) {                     // payments.savedStarGifts
        memcpy(body + flag_off, &orig_flags, 4);               // revert flag
        memcpy(body + insert_off, stage, changed);             // revert tail (size never bumped → leftover unread)
        return 0;
    }
    pg_qvec_set_size(cont, new_wc);
    return 1;
}
// Caption (savedStarGift.message TWE f0.2) + auction (starGift trio f0.11) on the first regular gift. Each is a
// validated splice; caption goes after the gift (message position), auction inside the starGift (auction_slug).
// Caption + auction + transfer-button: length-changing savedStarGift/starGift field inserts on the first
// regular gift (must run BEFORE pg_gift_unique_rebuild converts the gift to unique). Each is an independent
// validated splice + revert. Self-gates on the savedStarGifts ctor + an unshared buffer.
static void pg_gift_extras(void *resp) {
    int want_cap = g_gift_spoof_enabled && g_gift_spoof_caption[0] != 0;
    int want_auc = g_gift_spoof_enabled && g_gift_spoof_auction != 0;
    int want_xfer = g_fake_transfer_enabled != 0;
    if (!want_cap && !want_auc && !want_xfer) return;
    const void *cont = (const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET;
    { int32_t wc0 = 0; uint32_t *w0 = pg_qvec_data(cont, &wc0);
      if (!w0 || wc0 < 4 || w0[0] != 0x95f389b1u) return;          // payments.savedStarGifts only
      if (!pg_qvec_unshared(cont)) return; }
    static uint32_t logs = 0;
    // Transfer button first (highest offset: transfer_stars is savedStarGift param 16, after message[10]).
    // Insert transfer_stars=0 (free transfer) + flip f0.8 → Telegram shows the Transfer button on the gift.
    if (want_xfer) {
        int32_t wc = 0; uint32_t *words = pg_qvec_data(cont, &wc);
        if (words && wc > 0) {
            size_t goff, glen, foff, aoff, xoff;
            if (patchgram_tl_find_gift_splice((const uint8_t *)words, (size_t)wc * 4, &goff, &glen, &foff, &aoff, &xoff) && xoff) {
                uint32_t fl; memcpy(&fl, (const uint8_t *)words + foff, 4);
                if (!((fl >> 8) & 1u)) {                       // only ADD when transfer_stars absent
                    uint8_t ts[8]; int64_t zero = 0; memcpy(ts, &zero, 8);
                    int ok = pg_gift_insert_field(cont, xoff, ts, 8, foff, (1u << 8));
                    if (logs < 16) { logs++; pg_logf("GIFT TRANSFER-STARS %s (off=%zu)", ok ? "inserted" : "skip", xoff); }
                }
            }
        }
    }
    // Caption next (insert after the gift = message position; higher offset than auction).
    if (want_cap) {
        int32_t wc = 0; uint32_t *words = pg_qvec_data(cont, &wc);
        if (words && wc > 0) {
            size_t goff, glen, foff, aoff, xoff;
            if (patchgram_tl_find_gift_splice((const uint8_t *)words, (size_t)wc * 4, &goff, &glen, &foff, &aoff, &xoff)) {
                uint32_t fl; memcpy(&fl, (const uint8_t *)words + foff, 4);
                if (!((fl >> 2) & 1u)) {                       // only ADD when message is absent
                    static uint8_t twe[1280]; size_t ap = 0;
                    ap = pg_put_u32(twe, ap, PG_TL_TEXT_WITH_ENTITIES);
                    ap = pg_tl_put_string(twe, ap, g_gift_spoof_caption);
                    ap = pg_put_u32(twe, ap, PG_TL_VECTOR_ID); ap = pg_put_u32(twe, ap, 0);   // empty entities
                    if (!(ap & 3u) && ap <= sizeof twe) {
                        int ok = pg_gift_insert_field(cont, goff + glen, twe, ap, foff, (1u << 2));
                        if (logs < 16) { logs++; pg_logf("GIFT CAPTION %s (off=%zu len=%zu)", ok ? "inserted" : "skip", goff + glen, ap); }
                    }
                }
            }
        }
    }
    // Auction trio: auction_slug(string) + gifts_per_round(int) + auction_start_date(int) at the auction_slug
    // boundary; flips starGift.auction (f0.11) at the starGift flags = gift_off+4.
    if (want_auc) {
        int32_t wc = 0; uint32_t *words = pg_qvec_data(cont, &wc);
        if (words && wc > 0) {
            size_t goff, glen, foff, aoff, xoff;
            if (patchgram_tl_find_gift_splice((const uint8_t *)words, (size_t)wc * 4, &goff, &glen, &foff, &aoff, &xoff) && aoff) {
                uint32_t sfl; memcpy(&sfl, (const uint8_t *)words + goff + 4, 4);
                if (!((sfl >> 11) & 1u)) {                     // only ADD when auction is absent
                    static uint8_t trio[256]; size_t ap = 0;
                    ap = pg_tl_put_string(trio, ap, "auction");
                    ap = pg_put_u32(trio, ap, 1);                                  // gifts_per_round
                    ap = pg_put_u32(trio, ap, (uint32_t)(g_gift_spoof_date ? g_gift_spoof_date : 1700000000));
                    if (!(ap & 3u) && ap <= sizeof trio) {
                        int ok = pg_gift_insert_field(cont, aoff, trio, ap, goff + 4, (1u << 11));
                        if (logs < 16) { logs++; pg_logf("GIFT AUCTION %s (off=%zu len=%zu)", ok ? "inserted" : "skip", aoff, ap); }
                    }
                }
            }
        }
    }
}

// ---- gift spoof: rewrite the scalar fields of every gift in a payments.savedStarGifts response ----
// In place via the rw-walker; Qt5 COW-guarded. The walker self-gates on the top ctor, so this no-ops on any
// other response. Target mode (when != all) gates on a request-id the request-side peer match approved.
static void pg_gift_spoof(void *resp) {
    if (!g_gift_spoof_enabled) return;
    int32_t request_id = *(int32_t *)((const uint8_t *)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    if (g_gift_spoof_target_mode != 0 && !pg_ring_take(g_gift_spoof_req_ring, request_id)) return;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET, &wc);
    if (!words || wc <= 0) return;
    if (words[0] != 0x95f389b1u) return;   // payments.savedStarGifts — cheap pre-check before the walk
    if (!pg_qvec_unshared((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET)) return;
    struct PatchgramTLRewrite rw;
    memset(&rw, 0, sizeof rw);
    rw.sender_id      = g_gift_spoof_sender_id;
    rw.sender_peer_type = g_gift_spoof_sender_peer_type;
    rw.date           = g_gift_spoof_date;
    rw.gift_id        = g_gift_spoof_gift_id;
    rw.sticker_id     = g_gift_spoof_sticker_id;
    rw.stars          = g_gift_spoof_stars;
    rw.convert_stars  = g_gift_spoof_convert_stars;
    rw.available      = g_gift_spoof_available;
    rw.total          = g_gift_spoof_total;
    rw.force_limited  = g_gift_spoof_force_limited;
    rw.gift_num       = g_gift_spoof_gift_num;
    rw.was_refunded   = g_gift_spoof_was_refunded;
    rw.force_upgrade  = g_gift_spoof_upgrade;
    int applied = patchgram_tl_rewrite_saved_star_gifts((uint8_t *)words, (size_t)wc * 4, &rw);
    static uint32_t logs = 0;
    if (applied && logs < 32) { logs++; pg_logf("GIFT SPOOF applied %d fields (words=%d)", applied, wc); }
}

// One-shot diagnostic: relocate a real Telegram reply buffer to a FRESH buffer with byte-identical
// content via pg_qvec_replace. If the swap/free machinery or heap model were wrong, Telegram would
// crash or misparse; if it processes the (identical) response normally, the realloc-beyond-capacity
// writeback is proven on a real buffer. Gated by config (reallocLiveTestEnabled), default off.
static void pg_realloc_live_test(void *resp) {
    if (!g_realloc_live_test) return;
    static int done = 0;
    if (done) return;
    const void *cont = (const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data(cont, &wc);
    if (!words || wc <= 0) return;
    if (words[0] != 0xcc1a241eu) return;          // ONLY a high-level RPC result (config#cc1a241e),
    if (!pg_qvec_unshared(cont)) return;          // never a service msg; uniquely-owned only
    done = 1;
    uint32_t ctor0 = words[0];
    int ok = pg_qvec_replace(cont, words, wc) ? 1 : 0;   // identity copy → fresh STATIC buffer (no free)
    int32_t wc2 = 0; uint32_t *w2 = pg_qvec_data(cont, &wc2);
    pg_logf("# REALLOC LIVE TEST: replace ctor=%#x words=%d -> ok=%d newwords=%d match=%d",
            ctor0, wc, ok, wc2, (ok && w2 && wc2 == wc && w2[0] == ctor0) ? 1 : 0);
}

// ---- show hidden gifts: inject extra starGift entries into a payments.starGifts catalog response ----
// Ported from patchgram_inject_hidden_gifts. Clones the first existing gift's (slimmed) sticker Document,
// swaps its id to the chosen custom-emoji id, and splices N new starGift entries (50 Stars, not limited)
// at the FRONT of the gifts vector. In place via memmove + pg_qvec_grow (beyond capacity), re-validated.
#define PG_TL_PAYMENTS_STAR_GIFTS 0x2ed82995u
#define PG_TL_STAR_GIFT_CTOR      0x313a9547u

// Strip a Document's `thumbs` (→ empty vector) so the cloned sticker doc stays small. Returns out length.
static size_t pg_doc_slim(const uint8_t *doc, size_t len, uint8_t *out, size_t outcap) {
    if (len == 0 || len > outcap) return 0;
    size_t toff = 0, tlen = 0;
    patchgram_tl_capture_doc_thumbs(doc, len, &toff, &tlen);
    static const uint8_t empty_vec8[8] = { 0x15, 0xc4, 0xb5, 0x1c, 0, 0, 0, 0 };  // Vector + count 0
    if (toff > 0 && tlen > sizeof empty_vec8 && toff + tlen <= len) {
        size_t newlen = len - tlen + sizeof empty_vec8;
        if (newlen > outcap) return 0;
        memcpy(out, doc, toff);
        memcpy(out + toff, empty_vec8, sizeof empty_vec8);
        memcpy(out + toff + sizeof empty_vec8, doc + toff + tlen, len - toff - tlen);
        return newlen;
    }
    memcpy(out, doc, len);
    return len;
}

static void pg_inject_hidden_gifts(void *resp) {
    if (!g_show_hidden_gifts_enabled || g_hidden_gift_count <= 0) return;
    const void *cont = (const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data(cont, &wc);
    if (!words || wc < 4) return;
    if (words[0] != PG_TL_PAYMENTS_STAR_GIFTS || words[2] != PG_TL_VECTOR_ID) return;
    if (!pg_qvec_unshared(cont)) return;
    const uint8_t *body = (const uint8_t *)words;
    const size_t old_len = (size_t)wc * 4;
    size_t doc_off = 0, doc_len = 0, gifts_end = 0;
    if (!patchgram_tl_find_doc_template(body, old_len, &doc_off, &doc_len, &gifts_end)) return;
    if (doc_off + doc_len > old_len || gifts_end > old_len) return;
    const size_t gifts_start = 16;   // after ctor(w0)+hash(w1)+Vector(w2)+count(w3)
    static uint8_t tmpl[2048];
    size_t tmpl_len = pg_doc_slim(body + doc_off, doc_len, tmpl, sizeof tmpl);
    if (tmpl_len < 16) return;

    static uint8_t add[PG_MAX_HIDDEN_GIFTS * 1280];
    size_t ap = 0; int injected = 0;
    for (int i = 0; i < g_hidden_gift_count && i < PG_MAX_HIDDEN_GIFTS; i++) {
        static uint8_t clone[2048];
        memcpy(clone, tmpl, tmpl_len);
        memcpy(clone + 8, &g_hidden_emoji_ids[i], 8);   // Document.id @ +8 → client fetches that emoji
        size_t need = 4 + 4 + 8 + tmpl_len + 8 + 8;
        if (ap + need > sizeof add) break;
        uint32_t sg = PG_TL_STAR_GIFT_CTOR; memcpy(add + ap, &sg, 4); ap += 4;   // starGift
        int32_t fl = 0; memcpy(add + ap, &fl, 4); ap += 4;                        // flags=0
        memcpy(add + ap, &g_hidden_gift_ids[i], 8); ap += 8;                      // id
        memcpy(add + ap, clone, tmpl_len); ap += tmpl_len;                        // sticker (Document)
        int64_t stars = 50; memcpy(add + ap, &stars, 8); ap += 8;                 // stars
        int64_t conv = 43;  memcpy(add + ap, &conv, 8); ap += 8;                  // convert_stars
        injected++;
    }
    if (injected == 0 || (ap & 3u)) return;

    const int32_t new_wc = wc + (int32_t)(ap / 4);
    int32_t cap = pg_qvec_capacity(cont);
    static uint32_t logs = 0;
    if (new_wc > cap) {
        if (!pg_qvec_grow(cont, new_wc)) {
            if (logs < 16) { logs++; pg_logf("HIDDEN GIFTS skip: need %d words > capacity %d, grow unavailable", new_wc, cap); }
            return;
        }
        words = pg_qvec_data(cont, &wc);   // buffer moved
        if (!words) return;
    }
    uint8_t *w = (uint8_t *)words;
    memmove(w + gifts_start + ap, w + gifts_start, old_len - gifts_start);   // open a gap at the front
    memcpy(w + gifts_start, add, ap);                                        // drop the new gifts in
    uint32_t cnt; memcpy(&cnt, w + 12, 4); cnt += (uint32_t)injected; memcpy(w + 12, &cnt, 4);  // bump count
    if (!patchgram_tl_validate_top(w, (size_t)new_wc * 4, PG_TL_PAYMENTS_STAR_GIFTS)) {
        memcpy(&cnt, w + 12, 4); cnt -= (uint32_t)injected; memcpy(w + 12, &cnt, 4);
        memmove(w + gifts_start, w + gifts_start + ap, old_len - gifts_start);  // revert (size never bumped)
        if (logs < 16) { logs++; pg_logf("HIDDEN GIFTS skip: rebuilt response failed validation"); }
        return;
    }
    pg_qvec_set_size(cont, new_wc);
    if (logs < 16) { logs++; pg_logf("HIDDEN GIFTS injected=%d -> %d words (cap=%d)", injected, new_wc, cap); }
}

// ---- Fragment phone: answer fragment.getCollectibleInfo with a built fragment.collectibleInfo ----
// Record a requestId into the ring (overwrite slot 0 if full). Single-threaded engine → no mutex.
static void pg_fragment_track(int32_t request_id) {
    if (request_id <= 0) return;
    int empty = -1;
    for (int i = 0; i < PG_MAX_TRACKED_FRAGMENT_REQUESTS; i++) {
        if (g_fragment_req_ring[i] == request_id) return;          // already tracked
        if (g_fragment_req_ring[i] == 0 && empty < 0) empty = i;
    }
    g_fragment_req_ring[empty >= 0 ? empty : 0] = request_id;
}
// Consume+clear a requestId; returns 1 if it was one of ours.
static int pg_fragment_take(int32_t request_id) {
    if (request_id <= 0) return 0;
    for (int i = 0; i < PG_MAX_TRACKED_FRAGMENT_REQUESTS; i++)
        if (g_fragment_req_ring[i] == request_id) { g_fragment_req_ring[i] = 0; return 1; }
    return 0;
}
// TL bare-string encoder (len<254 path; collectible fields are short). Pads to a 4-byte boundary.
static size_t pg_tl_put_string(uint8_t *out, size_t ap, const char *s) {
    size_t n = s ? strlen(s) : 0;
    if (n > 253) n = 253;
    out[ap++] = (uint8_t)n;
    memcpy(out + ap, s ? s : "", n); ap += n;
    while (ap & 3u) out[ap++] = 0;
    return ap;
}
// Append a u32 / i64 word to a TL build buffer (used by the fact-check, gift-unique + username builders).
static size_t pg_put_u32(uint8_t *o, size_t ap, uint32_t v) { memcpy(o + ap, &v, 4); return ap + 4; }
static size_t pg_put_i64(uint8_t *o, size_t ap, int64_t  v) { memcpy(o + ap, &v, 8); return ap + 8; }
// Build a fragment.collectibleInfo reply into `out` from explicit fields. Returns word count, 0 on overflow.
static int32_t pg_build_collectible_info_ex(uint8_t *out, size_t outcap, int32_t date,
        const char *cur, int64_t amt, const char *ccur, int64_t camt, const char *url) {
    cur  = (cur  && cur[0])  ? cur  : "TON";
    ccur = (ccur && ccur[0]) ? ccur : "TON";
    url  = (url  && url[0])   ? url  : "https://fragment.com/";
    size_t ap = 0;
    uint32_t ctor = PG_TL_FRAGMENT_COLLECTIBLE_INFO; memcpy(out + ap, &ctor, 4); ap += 4;
    memcpy(out + ap, &date, 4);  ap += 4;
    ap = pg_tl_put_string(out, ap, cur);
    memcpy(out + ap, &amt, 8); ap += 8;
    ap = pg_tl_put_string(out, ap, ccur);
    memcpy(out + ap, &camt, 8); ap += 8;
    ap = pg_tl_put_string(out, ap, url);
    if (ap > outcap || (ap & 3u)) return 0;
    return (int32_t)(ap / 4);
}
static int32_t pg_build_collectible_info(uint8_t *out, size_t outcap) {     // phone variant
    return pg_build_collectible_info_ex(out, outcap, g_fragment_phone_purchase_date,
        g_fragment_phone_currency, g_fragment_phone_amount,
        g_fragment_phone_crypto_currency, g_fragment_phone_crypto_amount, g_fragment_phone_url);
}
// Replace the reply buffer of a tracked getCollectibleInfo response with our built collectibleInfo.
// Whole-buffer swap via pg_qvec_replace (fresh STATIC d, old buffer leaks → no cross-CRT free). Validate
// BEFORE swapping, so a build failure just leaves the server's genuine reply (still a valid answer).
static void pg_fragment_phone(void *resp) {
    if (!g_fragment_phone_enabled) return;
    int32_t request_id = *(int32_t*)((const uint8_t*)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    if (!pg_fragment_take(request_id)) return;
    const void *cont = (const uint8_t*)resp + PG_RESPONSE_REPLY_OFFSET;
    static uint8_t built[512];
    int32_t wc = pg_build_collectible_info(built, sizeof built);
    if (wc <= 0) return;
    static uint32_t logs = 0;
    if (!patchgram_tl_validate(built, (size_t)wc * 4)) {
        if (logs < 8) { logs++; pg_logf("FRAGMENT PHONE skip: built reply failed validation"); }
        return;
    }
    if (!pg_qvec_replace(cont, (const uint32_t*)built, wc)) return;
    if (logs < 48) { logs++; pg_logf("FRAGMENT PHONE response substituted requestId=%d words=%d", request_id, wc); }
}

// ---- Custom-username collectible info: answer getCollectibleInfo{inputCollectibleUsername} like the phone ----
// Read a TL bare string (short-form len byte; usernames are short) into `out`.
static void pg_tl_read_string(const uint8_t *b, size_t bc, char *out, size_t outcap) {
    if (!out || outcap == 0) return; out[0] = 0;
    if (!b || bc < 1) return;
    uint32_t L = b[0]; size_t head, n;
    if (L < 254) { n = L; head = 1; }
    else { if (bc < 4) return; n = (size_t)b[1] | ((size_t)b[2]<<8) | ((size_t)b[3]<<16); head = 4; }
    if (head + n > bc) return;
    size_t copy = (n < outcap - 1) ? n : outcap - 1;
    memcpy(out, b + head, copy); out[copy] = 0;
}
static void pg_cu_coll_track(int32_t request_id, int32_t idx) {
    if (request_id <= 0) return;
    int empty = -1;
    for (int i = 0; i < PG_MAX_TRACKED_FRAGMENT_REQUESTS; i++) {
        if (g_cu_coll_req[i] == request_id) { g_cu_coll_idx[i] = idx; return; }
        if (g_cu_coll_req[i] == 0 && empty < 0) empty = i;
    }
    int slot = (empty >= 0) ? empty : 0;
    g_cu_coll_req[slot] = request_id; g_cu_coll_idx[slot] = idx;
}
static int pg_cu_coll_take(int32_t request_id, int32_t *idx) {
    if (request_id <= 0) return 0;
    for (int i = 0; i < PG_MAX_TRACKED_FRAGMENT_REQUESTS; i++)
        if (g_cu_coll_req[i] == request_id) { *idx = g_cu_coll_idx[i]; g_cu_coll_req[i] = 0; return 1; }
    return 0;
}
// Replace a tracked getCollectibleInfo{username} reply with a built fragment.collectibleInfo (whole-buffer
// swap, validate-first — same machinery as the phone). Uses that username's parsed payload fields.
static void pg_cu_collectible(void *resp) {
    if (!g_custom_usernames_enabled || g_custom_usernames_count == 0) return;
    int32_t request_id = *(int32_t*)((const uint8_t*)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    int32_t idx = -1;
    if (!pg_cu_coll_take(request_id, &idx)) return;
    if (idx < 0 || (size_t)idx >= g_custom_usernames_count) return;
    const void *cont = (const uint8_t*)resp + PG_RESPONSE_REPLY_OFFSET;
    static uint8_t built[512];
    int32_t wc = pg_build_collectible_info_ex(built, sizeof built, g_cu_date[idx],
        g_cu_currency[idx], g_cu_amount[idx], g_cu_crypto_currency[idx], g_cu_crypto_amount[idx], g_cu_url[idx]);
    if (wc <= 0) return;
    static uint32_t logs = 0;
    if (!patchgram_tl_validate(built, (size_t)wc * 4)) {
        if (logs < 8) { logs++; pg_logf("CU COLLECTIBLE skip: built reply failed validation"); }
        return;
    }
    if (!pg_qvec_replace(cont, (const uint32_t*)built, wc)) return;
    if (logs < 48) { logs++; pg_logf("CU COLLECTIBLE substituted req=%d username=%s", request_id, g_custom_usernames[idx]); }
}

// ---- Custom fact check: answer messages.getFactCheck with a built Vector<factCheck> of local notes ----
// Record a getFactCheck requestId + the msg_id count (the reply must carry exactly one factCheck per msg_id).
static void pg_fact_check_track(int32_t request_id, int32_t count) {
    if (request_id <= 0 || count <= 0) return;
    int empty = -1;
    for (int i = 0; i < PG_MAX_TRACKED_FACT_CHECK_REQUESTS; i++) {
        if (g_fact_check_req_ring[i] == request_id) { g_fact_check_req_count[i] = count; return; }
        if (g_fact_check_req_ring[i] == 0 && empty < 0) empty = i;
    }
    int slot = (empty >= 0) ? empty : 0;
    g_fact_check_req_ring[slot] = request_id; g_fact_check_req_count[slot] = count;
}
static int32_t pg_fact_check_take(int32_t request_id) {
    if (request_id <= 0) return 0;
    for (int i = 0; i < PG_MAX_TRACKED_FACT_CHECK_REQUESTS; i++)
        if (g_fact_check_req_ring[i] == request_id) {
            int32_t c = g_fact_check_req_count[i];
            g_fact_check_req_ring[i] = 0; g_fact_check_req_count[i] = 0;
            return c;
        }
    return 0;
}
// Build a bare Vector<factCheck> of `count` identical local notes. Returns word count, 0 on overflow.
static int32_t pg_build_fact_check_reply(uint8_t *out, size_t outcap, int32_t count) {
    if (count <= 0 || !g_fact_check_text[0]) return 0;
    const char *country = g_fact_check_country;                       // may be "" (flags.1 still set)
    const char *text    = g_fact_check_text;
    const int32_t flags = (g_fact_check_need_check ? 1 : 0) | 2;      // bit0=need_check, bit1=country+text
    size_t ap = 0;
    ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID);
    ap = pg_put_u32(out, ap, (uint32_t)count);
    for (int32_t i = 0; i < count; i++) {
        if (ap + 8 > outcap) return 0;
        ap = pg_put_u32(out, ap, PG_TL_FACT_CHECK);
        ap = pg_put_u32(out, ap, (uint32_t)flags);
        ap = pg_tl_put_string(out, ap, country);                     // country:string (flags.1)
        if (ap + 4 > outcap) return 0;
        ap = pg_put_u32(out, ap, PG_TL_TEXT_WITH_ENTITIES);          // text:TextWithEntities
        ap = pg_tl_put_string(out, ap, text);                        //   text:string
        if (ap + 8 > outcap) return 0;
        ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID);                   //   entities:Vector<MessageEntity>
        ap = pg_put_u32(out, ap, 0);                                 //     (empty)
        if (ap + 8 > outcap) return 0;
        ap = pg_put_i64(out, ap, g_fact_check_hash);                 // hash:long
    }
    if (ap > outcap || (ap & 3u)) return 0;
    return (int32_t)(ap / 4);
}
// Replace a tracked messages.getFactCheck reply with our Vector<factCheck>. Whole-buffer swap; validate first.
static void pg_fact_check(void *resp) {
    if (!g_message_settings_enabled || !g_fact_check_enabled || !g_fact_check_text[0]) return;
    int32_t request_id = *(int32_t*)((const uint8_t*)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    int32_t count = pg_fact_check_take(request_id);
    if (count <= 0) return;
    if (count > 64) count = 64;                                       // bound the reply
    const void *cont = (const uint8_t*)resp + PG_RESPONSE_REPLY_OFFSET;
    static uint8_t built[24576];
    int32_t wc = pg_build_fact_check_reply(built, sizeof built, count);
    if (wc <= 0) return;
    static uint32_t logs = 0;
    if (!patchgram_tl_validate(built, (size_t)wc * 4)) {
        if (logs < 8) { logs++; pg_logf("FACT CHECK skip: built reply failed validation"); }
        return;
    }
    if (!pg_qvec_replace(cont, (const uint32_t*)built, wc)) return;
    if (logs < 48) { logs++; pg_logf("FACT CHECK substituted requestId=%d count=%d words=%d", request_id, count, wc); }
}

// ---- Custom list usernames: rewrite the self user's usernames Vector (in-place shrink + revert-on-fail) ----
static void pg_cu_track(int32_t request_id) {
    if (request_id <= 0) return;
    int empty = -1;
    for (int i = 0; i < PG_MAX_TRACKED_FRAGMENT_REQUESTS; i++) {
        if (g_custom_username_req_ring[i] == request_id) return;
        if (g_custom_username_req_ring[i] == 0 && empty < 0) empty = i;
    }
    g_custom_username_req_ring[empty >= 0 ? empty : 0] = request_id;
}
static int pg_cu_take(int32_t request_id) {
    if (request_id <= 0) return 0;
    for (int i = 0; i < PG_MAX_TRACKED_FRAGMENT_REQUESTS; i++)
        if (g_custom_username_req_ring[i] == request_id) { g_custom_username_req_ring[i] = 0; return 1; }
    return 0;
}
// Serialized length of a TL bare string (short form; usernames are <=32 chars), padded to 4.
static size_t pg_cu_str_len(const char *s) {
    size_t n = s ? strlen(s) : 0; size_t t = 1 + n; return t + ((4 - (t & 3)) & 3);
}
// Build a Vector<username> from the config list. First = editable+active (flags 3), rest active (flags 2).
static size_t pg_cu_build_vector(uint8_t *out, size_t outcap) {
    size_t need = 8;
    for (size_t i = 0; i < g_custom_usernames_count; i++) need += 8 + pg_cu_str_len(g_custom_usernames[i]);
    if (need > outcap) return 0;
    size_t ap = 0;
    ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID);
    ap = pg_put_u32(out, ap, (uint32_t)g_custom_usernames_count);
    for (size_t i = 0; i < g_custom_usernames_count; i++) {
        ap = pg_put_u32(out, ap, PG_TL_USERNAME);
        ap = pg_put_u32(out, ap, (i == 0) ? 3u : 2u);
        ap = pg_tl_put_string(out, ap, g_custom_usernames[i]);
    }
    return ap;
}
// Verify a span is exactly `count` username#b4073647 objects landing on a 4-byte boundary (structural,
// version-independent). Returns the end byte offset, or 0 on mismatch. `bc` = total byte count.
static size_t pg_cu_usernames_span(const uint8_t *bytes, size_t bc, size_t off, int32_t count) {
    for (int32_t k = 0; k < count; k++) {
        if (off + 8 > bc) return 0;
        uint32_t ctor; memcpy(&ctor, bytes + off, 4);
        if (ctor != PG_TL_USERNAME) return 0;
        off += 8;                                   // ctor + flags
        if (off >= bc) return 0;
        uint32_t L = bytes[off]; size_t head, n;
        if (L < 254) { n = L; head = 1; }
        else { if (off + 4 > bc) return 0; n = bytes[off+1] | (bytes[off+2]<<8) | (bytes[off+3]<<16); head = 4; }
        size_t total = head + n; total += ((4 - (total & 3)) & 3);
        if (off + total > bc) return 0;
        off += total;
    }
    return off;
}
// ---- TL field-skip helpers (port of the macOS user-constructor walker; version-independent) ----------
// Each advances *off past one field and returns false if it would run past the buffer / hit a bad ctor.
static bool pg_tl_skip_string(const uint8_t *b, size_t bc, size_t *off) {
    if (!off || *off >= bc) return false;
    uint32_t L = b[*off]; size_t head, n;
    if (L < 254) { n = L; head = 1; }
    else { if (*off + 4 > bc) return false; n = (size_t)b[*off+1] | ((size_t)b[*off+2]<<8) | ((size_t)b[*off+3]<<16); head = 4; }
    size_t total = head + n; total += ((4 - (total & 3)) & 3);
    if (*off + total > bc) return false;
    *off += total; return true;
}
static bool pg_tl_skip_u32(size_t bc, size_t *off) { if (!off || *off + 4 > bc) return false; *off += 4; return true; }
static bool pg_tl_skip_i64(size_t bc, size_t *off) { if (!off || *off + 8 > bc) return false; *off += 8; return true; }
static bool pg_tl_skip_user_profile_photo(const uint8_t *b, size_t bc, size_t *off) {  // flags.5?UserProfilePhoto
    if (!off || *off + 4 > bc) return false;
    uint32_t c; memcpy(&c, b + *off, 4); *off += 4;
    if (c == 0x4f11bae1u) return true;                                    // userProfilePhotoEmpty
    if (c != 0x82d1f706u) return false;                                   // userProfilePhoto { flags, id, [stripped], dc }
    uint32_t f; if (*off + 4 > bc) return false; memcpy(&f, b + *off, 4); *off += 4;
    if (!pg_tl_skip_i64(bc, off)) return false;                          // photo_id
    if ((f & (1u<<1)) && !pg_tl_skip_string(b, bc, off)) return false;    // stripped_thumb (bytes)
    return pg_tl_skip_u32(bc, off);                                       // dc_id
}
static bool pg_tl_skip_user_status(const uint8_t *b, size_t bc, size_t *off) {  // flags.6?UserStatus
    if (!off || *off + 4 > bc) return false;
    uint32_t c; memcpy(&c, b + *off, 4); *off += 4;
    switch (c) {
    case 0x09d05049u: case 0x7b197dc8u: case 0x541a1d1au: case 0x65899777u: case 0xcf7d64b1u:
        if (c == 0x7b197dc8u || c == 0x541a1d1au || c == 0x65899777u) return pg_tl_skip_u32(bc, off);  // online/offline/recently-with-int
        return true;                                                     // empty / recently (no int)
    case 0xedb93949u: case 0x8c703fu: return pg_tl_skip_u32(bc, off);     // lastWeek / lastMonth (by-me int)
    default: return false;
    }
}
static bool pg_tl_skip_restriction_reason_vector(const uint8_t *b, size_t bc, size_t *off) {  // flags.18?Vector<RestrictionReason>
    if (!off || *off + 8 > bc) return false;
    uint32_t c; int32_t count; memcpy(&c, b + *off, 4); memcpy(&count, b + *off + 4, 4);
    if (c != PG_TL_VECTOR_ID || count < 0 || count > 64) return false;
    *off += 8;
    for (int32_t i = 0; i < count; i++) {
        uint32_t ic; if (*off + 4 > bc) return false; memcpy(&ic, b + *off, 4);
        if (ic != 0xd072acb4u) return false;                             // restrictionReason { platform, reason, text }
        *off += 4;
        if (!pg_tl_skip_string(b, bc, off) || !pg_tl_skip_string(b, bc, off) || !pg_tl_skip_string(b, bc, off)) return false;
    }
    return true;
}
static bool pg_tl_skip_emoji_status(const uint8_t *b, size_t bc, size_t *off) {  // flags.30?EmojiStatus
    if (!off || *off + 4 > bc) return false;
    uint32_t c; memcpy(&c, b + *off, 4); *off += 4;
    if (c == 0x2de11aaeu) return true;                                    // emojiStatusEmpty
    uint32_t f; if (*off + 4 > bc) return false; memcpy(&f, b + *off, 4); *off += 4;
    if (c == 0xe7ff068au)                                                 // emojiStatus { flags, doc_id, flags.0?until }
        return pg_tl_skip_i64(bc, off) && ((f & 1u) == 0 || pg_tl_skip_u32(bc, off));
    if (c != 0x7184603bu) return false;                                  // emojiStatusCollectible
    return pg_tl_skip_i64(bc, off) && pg_tl_skip_i64(bc, off) && pg_tl_skip_string(b, bc, off)
        && pg_tl_skip_string(b, bc, off) && pg_tl_skip_i64(bc, off) && pg_tl_skip_u32(bc, off)
        && pg_tl_skip_u32(bc, off) && pg_tl_skip_u32(bc, off) && pg_tl_skip_u32(bc, off)
        && ((f & 1u) == 0 || pg_tl_skip_u32(bc, off));
}

// Locate the self user's usernames target. Returns 0 = not found, 1 = REPLACE an existing Vector at
// [*vstart,*vend), 2 = INSERT a Vector at byte *vstart (==*vend; user has no usernames field yet).
// *flags2_widx = the word index of the user's flags2 (its bit0 must be set when inserting). The REPLACE
// path is the macOS structural match; the INSERT path walks the user's flag-gated fields to the offset
// where the flags2.0 Vector belongs (after emoji_status), exactly like the macOS engine.
static int pg_cu_find_self_username_target(const uint32_t *words, int32_t wc,
                                           size_t *vstart, size_t *vend, size_t *flags2_widx) {
    const uint8_t *bytes = (const uint8_t *)words;
    const size_t bc = (size_t)wc * 4;
    const size_t scan = (wc < 8192) ? (size_t)wc : 8192;
    for (size_t i = 0; i + 5 < scan; i++) {
        if (words[i] != PG_TL_USER) continue;
        const uint32_t flags  = words[i + 1];
        const uint32_t flags2 = words[i + 2];
        if (!(flags & PG_USERNAME_SELF_FLAG_BIT)) continue;              // self only (flags bit10)
        if (flags2 & 1u) {                                               // already has usernames → REPLACE
            size_t end_scan = (size_t)wc;
            for (size_t k = i + 2; k < (size_t)wc && k < i + 400; k++) { if (words[k] == PG_TL_USER) { end_scan = k; break; } }
            for (size_t j = i + 2; j + 2 < end_scan; j++) {
                if (words[j] != PG_TL_VECTOR_ID) continue;
                int32_t count = (int32_t)words[j + 1];
                if (count <= 0 || count > 64) continue;
                size_t span_end = pg_cu_usernames_span(bytes, bc, (j + 2) * 4, count);
                if (!span_end) continue;
                *vstart = j * 4; *vend = span_end; *flags2_widx = i + 2;
                return 1;
            }
            continue;                                                    // self but vector not located → skip
        }
        // No usernames field → walk the flag-gated fields to find where the Vector belongs (INSERT).
        size_t off = (i + 3) * 4;                                        // after ctor, flags, flags2
        if (!pg_tl_skip_i64(bc, &off)) continue;                         // id (long, always present)
        bool ok = true;
        if (ok && (flags & (1u<<0))  && !pg_tl_skip_i64(bc, &off)) ok = false;                   // access_hash
        if (ok && (flags & (1u<<1))  && !pg_tl_skip_string(bytes, bc, &off)) ok = false;         // first_name
        if (ok && (flags & (1u<<2))  && !pg_tl_skip_string(bytes, bc, &off)) ok = false;         // last_name
        if (ok && (flags & (1u<<3))  && !pg_tl_skip_string(bytes, bc, &off)) ok = false;         // username
        if (ok && (flags & (1u<<4))  && !pg_tl_skip_string(bytes, bc, &off)) ok = false;         // phone
        if (ok && (flags & (1u<<5))  && !pg_tl_skip_user_profile_photo(bytes, bc, &off)) ok = false;       // photo
        if (ok && (flags & (1u<<6))  && !pg_tl_skip_user_status(bytes, bc, &off)) ok = false;    // status
        if (ok && (flags & (1u<<14)) && !pg_tl_skip_u32(bc, &off)) ok = false;                   // bot_info_version
        if (ok && (flags & (1u<<18)) && !pg_tl_skip_restriction_reason_vector(bytes, bc, &off)) ok = false; // restriction_reason
        if (ok && (flags & (1u<<19)) && !pg_tl_skip_string(bytes, bc, &off)) ok = false;         // bot_inline_placeholder
        if (ok && (flags & (1u<<22)) && !pg_tl_skip_string(bytes, bc, &off)) ok = false;         // lang_code
        if (ok && (flags & (1u<<30)) && !pg_tl_skip_emoji_status(bytes, bc, &off)) ok = false;   // emoji_status
        if (!ok || off > bc || (off & 3u)) continue;
        *vstart = off; *vend = off; *flags2_widx = i + 2;
        return 2;
    }
    return 0;
}
// Response rewriter: REPLACE the self user's usernames Vector, or INSERT one when the account has none
// (flags2.0 clear). Splice in place (memmove tail + write the built Vector); GROW via pg_qvec_grow when
// the new Vector is larger (insert, or replacing a smaller list), exactly like the gift-unique rebuild.
// Always validate the spliced buffer and REVERT byte-identically from a staged copy on failure (never
// publishes a bad buffer; size is only bumped after validation). No UserData write.
static void pg_custom_usernames(void *resp) {
    if (!g_custom_usernames_enabled || g_custom_usernames_count == 0) return;
    int32_t request_id = *(int32_t*)((const uint8_t*)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    const void *cont = (const uint8_t*)resp + PG_RESPONSE_REPLY_OFFSET;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data(cont, &wc);
    if (!words || wc <= 0) return;
    // Only rewrite responses to a TRACKED getFullUser/getUsers request (matches macOS path B). We must NOT
    // rewrite arbitrary/early-startup userFull replies: doing so during Telegram's init window (while the UI
    // is first constructing the self user) races the profile render and crashes intermittently when the
    // PhoneOrHiddenValue hook is also live. A tracked request only fires post-init (e.g. opening the profile).
    if (!pg_cu_take(request_id)) return;
    if (!pg_qvec_unshared(cont)) return;

    size_t vstart = 0, vend = 0, flags2_widx = 0;
    static uint32_t logs = 0;
    int mode = pg_cu_find_self_username_target(words, wc, &vstart, &vend, &flags2_widx);
    if (mode == 0) {
        if (logs < 16) { logs++; pg_logf("CUSTOM USERNAMES skip: self user/target not found req=%d", request_id); }
        return;
    }

    static uint8_t built[2048];
    size_t rep = pg_cu_build_vector(built, sizeof built);
    if (rep == 0 || (rep & 3u)) return;

    const size_t old_bc = (size_t)wc * 4;
    if (vstart > old_bc || vend > old_bc || vend < vstart) return;
    const size_t old_span = vend - vstart;                              // 0 for INSERT
    const size_t new_bc = old_bc - old_span + rep;
    if (new_bc & 3u) return;
    const int32_t new_wc = (int32_t)(new_bc / 4);

    uint8_t *bytes = (uint8_t*)words;
    int32_t cap = pg_qvec_capacity(cont);
    int grew = 0;
    if (new_wc > cap) {
        if (!pg_qvec_grow(cont, new_wc)) {
            if (logs < 16) { logs++; pg_logf("CUSTOM USERNAMES skip: need %d words > cap %d, grow unavailable req=%d", new_wc, cap, request_id); }
            return;
        }
        grew = 1;
        words = pg_qvec_data(cont, &wc);   // buffer moved → re-fetch (content + size preserved by grow)
        if (!words) return;
        bytes = (uint8_t*)words;
    }

    static uint8_t stage[131072];
    const size_t changed = old_bc - vstart;                            // [vstart, old_bc) is what we touch/revert
    if (changed > sizeof stage) return;
    memcpy(stage, bytes + vstart, changed);                            // stage for byte-identical revert
    memmove(bytes + vstart + rep, bytes + vend, old_bc - vend);        // slide the tail (right=grow, left=shrink)
    memcpy(bytes + vstart, built, rep);                                // write the Vector into the gap
    bool set_flag = (mode == 2 && flags2_widx < (size_t)new_wc);
    if (set_flag) bytes[flags2_widx * 4] |= 1u;                        // flags2.0 = usernames present (LE low byte)

    if (!patchgram_tl_validate(bytes, new_bc)) {
        if (set_flag) bytes[flags2_widx * 4] &= ~1u;                   // clear the flag we set
        memcpy(bytes + vstart, stage, changed);                        // restore the original tail+span; size never bumped
        if (logs < 16) { logs++; pg_logf("CUSTOM USERNAMES skip: rewrite failed validation req=%d mode=%d", request_id, mode); }
        return;
    }
    pg_qvec_set_size(cont, new_wc);                                     // publish only after validation
    if (logs < 48) { logs++; pg_logf("CUSTOM USERNAMES %s req=%d count=%zu words %d->%d cap=%d grew=%d first=%s",
                                     mode == 2 ? "inserted" : "rewrote", request_id, g_custom_usernames_count,
                                     (int)(old_bc / 4), new_wc, cap, grew, g_custom_usernames[0]); }
}

// ---- Spoof profile UNIQUE gifts: turn the first regular starGift into an upgraded starGiftUnique --------
// Modeled on pg_inject_hidden_gifts: locate the first savedStarGift.gift (a starGift#313a9547) + its sticker
// Document, build a fresh starGiftUnique#85f0a9cd blob (carrying config attributes, cloning the gift's OWN
// sticker doc UNCHANGED for model+pattern so it still renders), splice it OVER the gift span via memmove
// (+ pg_qvec_grow when larger), then patchgram_tl_validate_top and REVERT from a staged copy on failure.
#define PG_TL_SAVED_STAR_GIFTS_CTOR 0x95f389b1u   // payments.savedStarGifts (matches pg_gift_spoof pre-check)
#define PG_TL_STAR_GIFT_UNIQUE_CTOR 0x85f0a9cdu
#define PG_TL_ATTR_MODEL            0x565251e2u
#define PG_TL_ATTR_PATTERN          0x4e7085eau
#define PG_TL_ATTR_BACKDROP         0x9f2504e4u
#define PG_TL_ATTR_RARITY           0x36437737u
#define PG_TL_PEER_USER_CTOR        0x59511722u
#define PG_TL_PEER_CHANNEL_CTOR     0xa2a5371eu
#define PG_TL_PEER_CHAT_CTOR        0x36c6019au
static uint32_t pg_peer_ctor(int t) {
    return (t == 1) ? PG_TL_PEER_CHANNEL_CTOR : (t == 2) ? PG_TL_PEER_CHAT_CTOR : PG_TL_PEER_USER_CTOR;
}
// Build a starGiftUnique blob into `out`. Returns byte length, 0 on overflow. `src_doc` = the regular gift's
// sticker Document, cloned UNCHANGED as both model+pattern documents (tdesktop drops the gift if model/pattern
// document->sticker() can't resolve, so the gift's already-cached sticker is the safe choice).
static size_t pg_build_unique_blob(uint8_t *out, size_t outcap, const uint8_t *src_doc, size_t src_doc_len) {
    if (src_doc_len < 16 || outcap < 256 + 2 * src_doc_len) return 0;
    size_t ap = 0;
    uint32_t uflags = 0;
    if (g_unique_owner_id)         uflags |= (1u << 0);   // owner_id (Peer)
    if (g_unique_owner_address[0]) uflags |= (1u << 2);   // owner_address
    const int have_value = (g_unique_value_amount || g_unique_value_usd || g_unique_value_currency[0]);
    if (have_value)                uflags |= (1u << 8);   // value trio (all-or-none)
    if (g_unique_host_id)          uflags |= (1u << 12);  // host_id (Peer)
    const int64_t gid = g_unique_gift_id ? g_unique_gift_id : 1;
    ap = pg_put_u32(out, ap, PG_TL_STAR_GIFT_UNIQUE_CTOR);
    ap = pg_put_u32(out, ap, uflags);
    ap = pg_put_i64(out, ap, gid);                                                   // id
    ap = pg_put_i64(out, ap, gid);                                                   // gift_id
    ap = pg_tl_put_string(out, ap, g_unique_title[0] ? g_unique_title : "Gift");     // title
    ap = pg_tl_put_string(out, ap, "Patchgram");                                     // slug
    ap = pg_put_u32(out, ap, (uint32_t)(g_unique_num ? g_unique_num : 1));           // num
    if (g_unique_owner_id)         { ap = pg_put_u32(out, ap, pg_peer_ctor(g_unique_owner_peer_type)); ap = pg_put_i64(out, ap, g_unique_owner_id); }
    if (g_unique_owner_address[0]) { ap = pg_tl_put_string(out, ap, g_unique_owner_address); }
    // attributes: Vector<boxed> = magic + count + [model, pattern, backdrop]
    ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID);
    ap = pg_put_u32(out, ap, 3);
    // model: starGiftAttributeModel{ flags, name, document, rarity }
    ap = pg_put_u32(out, ap, PG_TL_ATTR_MODEL);
    ap = pg_put_u32(out, ap, 0);                                                     // flags (crafted off)
    ap = pg_tl_put_string(out, ap, g_unique_model_name[0] ? g_unique_model_name : "Model");
    if (ap + src_doc_len > outcap) return 0; memcpy(out + ap, src_doc, src_doc_len);
    // Override the cloned Document.id (document#8fd4c4d8 { flags:#, id:long, ... } → id at doc+8) with the
    // configured model emoji id, so the chosen custom emoji renders (if cached; else the attribute is dropped,
    // never a crash). 0 = keep the gift's own sticker (always renders).
    if (g_unique_model_emoji_id && src_doc_len >= 16) memcpy(out + ap + 8, &g_unique_model_emoji_id, 8);
    ap += src_doc_len;
    ap = pg_put_u32(out, ap, PG_TL_ATTR_RARITY);
    ap = pg_put_u32(out, ap, (uint32_t)(g_unique_model_rarity ? g_unique_model_rarity : 5));
    // pattern: starGiftAttributePattern{ name, document, rarity }
    ap = pg_put_u32(out, ap, PG_TL_ATTR_PATTERN);
    ap = pg_tl_put_string(out, ap, g_unique_symbol_name[0] ? g_unique_symbol_name : "Symbol");
    if (ap + src_doc_len > outcap) return 0; memcpy(out + ap, src_doc, src_doc_len);
    if (g_unique_symbol_emoji_id && src_doc_len >= 16) memcpy(out + ap + 8, &g_unique_symbol_emoji_id, 8);
    ap += src_doc_len;
    ap = pg_put_u32(out, ap, PG_TL_ATTR_RARITY);
    ap = pg_put_u32(out, ap, (uint32_t)(g_unique_symbol_rarity ? g_unique_symbol_rarity : 5));
    // backdrop: starGiftAttributeBackdrop{ name, backdrop_id, 4 colors, rarity }
    ap = pg_put_u32(out, ap, PG_TL_ATTR_BACKDROP);
    ap = pg_tl_put_string(out, ap, g_unique_backdrop_name[0] ? g_unique_backdrop_name : "Backdrop");
    ap = pg_put_u32(out, ap, 0);                                                     // backdrop_id
    ap = pg_put_u32(out, ap, (uint32_t)g_unique_backdrop_center);
    ap = pg_put_u32(out, ap, (uint32_t)g_unique_backdrop_edge);
    ap = pg_put_u32(out, ap, (uint32_t)g_unique_backdrop_pattern);
    ap = pg_put_u32(out, ap, (uint32_t)g_unique_backdrop_text);
    ap = pg_put_u32(out, ap, PG_TL_ATTR_RARITY);
    ap = pg_put_u32(out, ap, (uint32_t)(g_unique_backdrop_rarity ? g_unique_backdrop_rarity : 5));
    // availability_issued / availability_total (ALWAYS present, not flag-gated)
    ap = pg_put_u32(out, ap, (uint32_t)(g_unique_total_upgraded ? g_unique_total_upgraded : 1));
    ap = pg_put_u32(out, ap, (uint32_t)(g_unique_max_upgraded   ? g_unique_max_upgraded   : 1000));
    // value trio (flags.8): value_amount(long), value_currency(string), value_usd_amount(long), IN ORDER
    if (have_value) {
        ap = pg_put_i64(out, ap, g_unique_value_amount);
        ap = pg_tl_put_string(out, ap, g_unique_value_currency[0] ? g_unique_value_currency : "TON");
        ap = pg_put_i64(out, ap, g_unique_value_usd);
    }
    if (g_unique_host_id) { ap = pg_put_u32(out, ap, pg_peer_ctor(g_unique_host_peer_type)); ap = pg_put_i64(out, ap, g_unique_host_id); }
    if (ap > outcap || (ap & 3u)) return 0;
    return ap;
}
static void pg_gift_unique_rebuild(void *resp) {
    if (!g_gift_unique_enabled) return;
    int32_t req_id = *(int32_t *)((const uint8_t *)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    if (g_gift_unique_target_mode != 0 && !pg_ring_take(g_gift_unique_req_ring, req_id)) return;
    const void *cont = (const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data(cont, &wc);
    if (!words || wc < 4) return;
    if (words[0] != PG_TL_SAVED_STAR_GIFTS_CTOR) return;   // cheap pre-check
    if (!pg_qvec_unshared(cont)) return;                   // COW-safe: owned buffers only

    const uint8_t *body = (const uint8_t *)words;
    const size_t old_len = (size_t)wc * 4;
    size_t gift_off = 0, gift_len = 0, doc_off = 0, doc_len = 0;
    if (!patchgram_tl_find_saved_gift(body, old_len, &gift_off, &gift_len, &doc_off, &doc_len)) return;
    if (gift_off < 4 || gift_off + gift_len > old_len) return;
    if (doc_len == 0 || doc_off + doc_len > old_len) return;

    static uint8_t docbuf[4096];
    static uint8_t orig_gift[16384];
    static uint8_t blob[24576];
    if (doc_len > sizeof docbuf || gift_len > sizeof orig_gift) return;   // too big to stage safely
    memcpy(docbuf, body + doc_off, doc_len);        // copy BEFORE any memmove/grow shifts the buffer
    memcpy(orig_gift, body + gift_off, gift_len);   // staged copy for revert
    if (g_fake_transfer_enabled && doc_len <= sizeof g_transfer_src_doc) {   // stash a renderable doc for the fake transfer msg
        memcpy(g_transfer_src_doc, docbuf, doc_len); g_transfer_src_doc_len = doc_len;
    }
    size_t blen = pg_build_unique_blob(blob, sizeof blob, docbuf, doc_len);
    if (blen == 0 || (blen & 3u)) return;

    static uint32_t logs = 0;
    const long long delta = (long long)blen - (long long)gift_len;
    if (delta % 4 != 0) return;
    const int32_t new_wc = wc + (int32_t)(delta / 4);
    if (new_wc < 4) return;

    int32_t cap = pg_qvec_capacity(cont);
    if (new_wc > cap) {
        if (!pg_qvec_grow(cont, new_wc)) {
            if (logs < 16) { logs++; pg_logf("GIFT UNIQUE skip: need %d words > cap %d, grow unavailable", new_wc, cap); }
            return;
        }
        words = pg_qvec_data(cont, &wc);            // buffer moved → re-fetch (offsets preserved by grow)
        if (!words) return;
    }
    uint8_t *w = (uint8_t *)words;
    const size_t tail_off = gift_off + gift_len;
    const size_t tail_len = old_len - tail_off;
    memmove(w + gift_off + blen, w + tail_off, tail_len);   // open/close the gap by `delta`
    memcpy(w + gift_off, blob, blen);                       // drop the rebuilt starGiftUnique in
    if (!patchgram_tl_validate_top(w, (size_t)new_wc * 4, PG_TL_SAVED_STAR_GIFTS_CTOR)) {
        memmove(w + gift_off + gift_len, w + gift_off + blen, tail_len);  // slide tail back to original place
        memcpy(w + gift_off, orig_gift, gift_len);                        // restore the original starGift
        if (logs < 16) { logs++; pg_logf("GIFT UNIQUE skip: rebuilt response failed validation"); }
        return;
    }
    pg_qvec_set_size(cont, new_wc);                         // publish only after validation passes
    if (logs < 16) { logs++; pg_logf("GIFT UNIQUE rebuilt gift [%zu,%zu) -> %zu bytes (%d words, cap=%d)",
                                     gift_off, tail_off, blen, new_wc, cap); }
}

// ---- unique gift "last resale" value info: answer payments.getUniqueStarGiftValueInfo with our values ----
// uniqueStarGiftValueInfo#512fe446 { flags, currency:string, value:long, initial_sale_date:int,
// initial_sale_stars:long, initial_sale_price:long, [f0.0 last_sale_date:int, last_sale_price:long] }.
// Whole-buffer replace (fragment-phone pattern): track the request id, build, validate, swap.
#define PG_TL_UNIQUE_VALUE_INFO     0x512fe446u
#define PG_TL_GET_UNIQUE_VALUE_INFO 0x4365af6bu
static int32_t pg_build_value_info(uint8_t *out, size_t outcap) {
    const char *cur = g_unique_last_resale_currency[0] ? g_unique_last_resale_currency
                    : (g_unique_value_currency[0] ? g_unique_value_currency : "TON");
    const int has_last = (g_unique_last_resale_amount || g_unique_last_resale_date);
    const int32_t flags = has_last ? 1 : 0;                       // f0.0 → last_sale_date + last_sale_price
    const int32_t init_date = g_unique_last_resale_date ? g_unique_last_resale_date : 1700000000;
    const int64_t init_amt  = g_unique_value_amount ? g_unique_value_amount : 1;
    size_t ap = 0;
    ap = pg_put_u32(out, ap, PG_TL_UNIQUE_VALUE_INFO);
    ap = pg_put_u32(out, ap, (uint32_t)flags);
    ap = pg_tl_put_string(out, ap, cur);                         // currency
    ap = pg_put_i64(out, ap, g_unique_value_amount);             // value
    ap = pg_put_u32(out, ap, (uint32_t)init_date);               // initial_sale_date
    ap = pg_put_i64(out, ap, init_amt);                          // initial_sale_stars
    ap = pg_put_i64(out, ap, init_amt);                          // initial_sale_price
    if (has_last) {                                              // f0.0 pair, in order, together
        ap = pg_put_u32(out, ap, (uint32_t)(g_unique_last_resale_date ? g_unique_last_resale_date : init_date));
        ap = pg_put_i64(out, ap, g_unique_last_resale_amount);
    }
    if (ap > outcap || (ap & 3u)) return 0;
    return (int32_t)(ap / 4);
}
static void pg_value_info(void *resp) {
    if (!g_gift_unique_enabled) return;
    int32_t request_id = *(int32_t *)((const uint8_t *)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    if (!pg_ring_take(g_value_info_req_ring, request_id)) return;
    static uint8_t built[256];
    int32_t wc = pg_build_value_info(built, sizeof built);
    if (wc <= 0 || !patchgram_tl_validate(built, (size_t)wc * 4)) return;
    if (!pg_qvec_replace((const uint8_t *)resp + PG_RESPONSE_REPLY_OFFSET, (const uint32_t *)built, wc)) return;
    static uint32_t logs = 0;
    if (logs < 16) { logs++; pg_logf("GIFT VALUE INFO substituted requestId=%d words=%d", request_id, wc); }
}

// ---- Fake transfer: answer payments.transferStarGift with a fabricated Updates carrying a local service msg --
#define PG_TL_TRANSFER_STAR_GIFT     0x7f18176au
#define PG_TL_INPUT_SAVED_GIFT_USER  0x69279795u   // { msg_id:int }
#define PG_TL_INPUT_SAVED_GIFT_CHAT  0xf101aa7fu   // { peer:InputPeer, saved_id:long }
#define PG_TL_INPUT_SAVED_GIFT_SLUG  0x2085c238u   // { slug:string }
#define PG_TL_INPUT_PEER_USER        0xdde8a54cu   // { user_id:long, access_hash:long }
#define PG_TL_INPUT_PEER_CHANNEL     0x27bcbbfcu   // { channel_id:long, access_hash:long }
#define PG_TL_INPUT_PEER_CHAT        0x35a95cb9u   // { chat_id:long }
#define PG_TL_INPUT_PEER_SELF        0x7da07ec9u
#define PG_TL_UPDATES                0x74ae4240u
#define PG_TL_UPDATE_NEW_MESSAGE     0x1f2b0afdu
#define PG_TL_MESSAGE_SERVICE        0x7a800e0au
#define PG_TL_MSG_ACTION_SGU         0xe6c31522u
#define PG_TL_GET_PAYMENT_FORM       0x37148dbbu
#define PG_TL_INPUT_INVOICE_SGT      0x4a5f5bd9u
#define PG_TL_RPC_ERROR              0x2144ca19u
static void pg_transfer_track(int32_t id, int pt, int64_t pid) {
    if (id <= 0) return; int e = -1;
    for (int i = 0; i < PG_MAX_TRACKED_GIFT_REQUESTS; i++) {
        if (g_transfer_reqs[i].request_id == id) return;
        if (g_transfer_reqs[i].request_id == 0 && e < 0) e = i;
    }
    int s = e >= 0 ? e : 0; g_transfer_reqs[s].request_id = id; g_transfer_reqs[s].peer_type = pt; g_transfer_reqs[s].peer_id = pid;
}
static int pg_transfer_take(int32_t id, int *pt, int64_t *pid) {
    if (id <= 0) return 0;
    for (int i = 0; i < PG_MAX_TRACKED_GIFT_REQUESTS; i++)
        if (g_transfer_reqs[i].request_id == id) { *pt = g_transfer_reqs[i].peer_type; *pid = g_transfer_reqs[i].peer_id; g_transfer_reqs[i].request_id = 0; return 1; }
    return 0;
}
// Build updates{ [updateNewMessage{ messageService{ peer_id, action=messageActionStarGiftUnique(transferred) }}], date }
// with pts=0/seq=0 so applyUpdates inserts it immediately (no gap/getDifference). No from_id (self id unknown).
static int32_t pg_build_transfer_updates(uint8_t *out, size_t cap, int pt, int64_t pid, int32_t now) {
    static uint8_t gift[24576];
    if (g_transfer_src_doc_len < 16) return 0;
    size_t glen = pg_build_unique_blob(gift, sizeof gift, g_transfer_src_doc, g_transfer_src_doc_len);
    if (glen == 0) return 0;
    uint32_t pc = pg_peer_ctor(pt);
    size_t ap = 0;
    ap = pg_put_u32(out, ap, PG_TL_UPDATES);
    ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID); ap = pg_put_u32(out, ap, 1);     // updates: 1
    ap = pg_put_u32(out, ap, PG_TL_UPDATE_NEW_MESSAGE);
    ap = pg_put_u32(out, ap, PG_TL_MESSAGE_SERVICE);
    ap = pg_put_u32(out, ap, (1u << 1));                                        // flags: out (no from_id)
    ap = pg_put_u32(out, ap, 0x70000000u + (g_transfer_msg_seq++ & 0x0fffffffu)); // id (unique local)
    ap = pg_put_u32(out, ap, pc); ap = pg_put_i64(out, ap, pid);                // peer_id (recipient)
    ap = pg_put_u32(out, ap, (uint32_t)now);                                    // date
    ap = pg_put_u32(out, ap, PG_TL_MSG_ACTION_SGU);                             // action
    ap = pg_put_u32(out, ap, (1u << 1) | (1u << 7));                            //   flags: transferred | peer+saved_id
    if (ap + glen > cap) return 0; memcpy(out + ap, gift, glen); ap += glen;    //   gift (param 9, always)
    ap = pg_put_u32(out, ap, pc); ap = pg_put_i64(out, ap, pid);               //   peer (param 13, bit7)
    ap = pg_put_i64(out, ap, 0);                                                //   saved_id (param 14, bit7)
    ap = pg_put_u32(out, ap, 0); ap = pg_put_u32(out, ap, 0);                   // pts, pts_count
    ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID); ap = pg_put_u32(out, ap, 0);     // users
    ap = pg_put_u32(out, ap, PG_TL_VECTOR_ID); ap = pg_put_u32(out, ap, 0);     // chats
    ap = pg_put_u32(out, ap, (uint32_t)now);                                    // date
    ap = pg_put_u32(out, ap, 0);                                               // seq
    if (ap > cap || (ap & 3u)) return 0;
    return (int32_t)(ap / 4);
}
static void pg_fake_transfer(void *resp) {
    if (!g_fake_transfer_enabled) return;
    int32_t request_id = *(int32_t*)((const uint8_t*)resp + PG_RESPONSE_REQUEST_ID_OFFSET);
    int pt; int64_t pid;
    if (!pg_transfer_take(request_id, &pt, &pid)) return;
    const void *cont = (const uint8_t*)resp + PG_RESPONSE_REPLY_OFFSET;
    static uint8_t built[28672];
    int32_t wc = pg_build_transfer_updates(built, sizeof built, pt, pid, (int32_t)time(NULL));
    if (wc <= 0) return;
    static uint32_t logs = 0;
    if (!patchgram_tl_validate(built, (size_t)wc * 4)) { if (logs < 8) { logs++; pg_logf("FAKE TRANSFER skip: built reply failed validation"); } return; }
    if (!pg_qvec_replace(cont, (const uint32_t*)built, wc)) return;
    if (logs < 16) { logs++; pg_logf("FAKE TRANSFER substituted requestId=%d words=%d", request_id, wc); }
}

void pg_apply_response(void *resp) {
    if (!resp) return;
    pg_realloc_live_test(resp);   // diagnostic (off unless reallocLiveTestEnabled)
    pg_strip_noforwards(resp);
    pg_account_freeze(resp);
    pg_disable_monetization(resp);
    pg_gift_spoof(resp);
    pg_gift_extras(resp);          // caption/auction/transfer-button (regular gift) — before the unique rebuild
    pg_gift_unique_rebuild(resp);
    pg_value_info(resp);
    pg_fake_transfer(resp);
    pg_inject_hidden_gifts(resp);
    pg_fragment_phone(resp);
    pg_cu_collectible(resp);
    pg_fact_check(resp);
    pg_custom_usernames(resp);
    // TODO(port): fake transfer — see NOTES.md §7 for the remaining map.
}

// Request-side patches (no IDA — operate on the serialized TL body at word kMessageBodyPosition=8).
// Returns 1 if the request should be DROPPED (the hook then does not forward it to the original
// sendPrepared, so it is never queued/sent — a clean block with no resend, since it never enters
// toSendMap). 0 = forward as normal (possibly after an in-place edit).
//   body ctors: account.updateStatus#6628562c, messages.setTyping#58943ee2, messages.readHistory#0e306d3a,
//   channels.readHistory#cc104937, messages.readMessageContents#36a73f77, messages.readDiscussion#f731a9f4,
//   contacts.addContact#d9ba2e54; boolTrue#997275b5.
int pg_apply_request(void *req) {
    if (!req) return 0;
    uint8_t *rdata = *(uint8_t **)req;            // SerializedRequest -> RequestData*
    if (!rdata) return 0;
    int32_t wc = 0;
    uint32_t *words = pg_qvec_data(rdata + PG_REQUEST_DATA_BUFFER_OFFSET, &wc);
    if (!words || wc <= PG_SERIALIZED_REQUEST_BODY_POSITION) return 0;
    uint32_t *body = words + PG_SERIALIZED_REQUEST_BODY_POSITION;   // TL body: [0]=ctor, [1..]=params
    const int32_t bodyN = wc - PG_SERIALIZED_REQUEST_BODY_POSITION;
    const uint32_t ctor = body[0];
    const int can_write = pg_qvec_unshared(rdata + PG_REQUEST_DATA_BUFFER_OFFSET);  // COW-safe in-place
    static uint32_t logs = 0;

    // Gift target mode: track payments.getSavedStarGifts#a319e569 whose peer matches the chosen mode, so the
    // gift rewriters only touch the targeted profile (instead of everyone). The body is { flags:#, ...true-
    // flags..., peer:InputPeer, ... } — inputPeerSelf#7da07ec9 is a bare ctor word, so a bounded scan for it
    // == "is the self profile". Forward as normal (return 0). Mode 0=all skips tracking (applies to everyone).
    if ((g_gift_spoof_enabled || g_gift_unique_enabled) && ctor == 0xa319e569u && bodyN >= 2) {
        int has_self = 0;
        const int32_t lim = (bodyN < 256) ? bodyN : 256;
        for (int32_t i = 1; i < lim; i++) { if (body[i] == 0x7da07ec9u) { has_self = 1; break; } }
        int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
        if (g_gift_spoof_enabled && (g_gift_spoof_target_mode == 20 ? has_self
                                   : g_gift_spoof_target_mode == 10 ? !has_self : 0))
            pg_ring_track(g_gift_spoof_req_ring, request_id);
        if (g_gift_unique_enabled && (g_gift_unique_target_mode == 20 ? has_self
                                    : g_gift_unique_target_mode == 10 ? !has_self : 0))
            pg_ring_track(g_gift_unique_req_ring, request_id);
    }
    // Last-resale: track payments.getUniqueStarGiftValueInfo so pg_value_info answers it with our values.
    if (g_gift_unique_enabled && ctor == 0x4365af6bu) {
        int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
        pg_ring_track(g_value_info_req_ring, request_id);
    }
    // Fake transfer: record the recipient peer of payments.transferStarGift#7f18176a so pg_fake_transfer can
    // fabricate the Updates reply. body = { stargift:InputSavedStarGift, to_id:InputPeer }: skip the stargift,
    // then read the to_id peer ctor + id. Forward as normal (return 0).
    if (g_fake_transfer_enabled && ctor == PG_TL_TRANSFER_STAR_GIFT && bodyN >= 2) {
        int ok = 1; int32_t j = 1;                              // j = word index in body, after the ctor
        uint32_t sg = body[j++];
        if (sg == PG_TL_INPUT_SAVED_GIFT_USER) { j += 1; }     // msg_id:int
        else if (sg == PG_TL_INPUT_SAVED_GIFT_CHAT) {          // peer:InputPeer, saved_id:long
            if (j < bodyN) { uint32_t pcc = body[j++];
                if (pcc == PG_TL_INPUT_PEER_USER || pcc == PG_TL_INPUT_PEER_CHANNEL) j += 4;
                else if (pcc == PG_TL_INPUT_PEER_CHAT) j += 2;
                else if (pcc != PG_TL_INPUT_PEER_SELF) ok = 0;
                j += 2; }                                       // saved_id:long
        }
        else if (sg == PG_TL_INPUT_SAVED_GIFT_SLUG) {          // slug:string (1-byte-prefixed, short)
            if (j < bodyN) { uint8_t L = ((const uint8_t*)(body + j))[0]; int32_t sw = (int32_t)((1 + L + 3) / 4); j += sw; }
        }
        else ok = 0;
        if (ok && j + 1 <= bodyN) {
            uint32_t pc = body[j++]; int pt = -1; int64_t pid = 0;
            if (pc == PG_TL_INPUT_PEER_USER)         { pt = 0; if (j + 2 <= bodyN) memcpy(&pid, body + j, 8); }
            else if (pc == PG_TL_INPUT_PEER_CHANNEL) { pt = 1; if (j + 2 <= bodyN) memcpy(&pid, body + j, 8); }
            else if (pc == PG_TL_INPUT_PEER_CHAT)    { pt = 2; if (j + 2 <= bodyN) memcpy(&pid, body + j, 8); }
            if (pt >= 0 && pid) {
                int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
                pg_transfer_track(request_id, pt, pid);
                if (logs < 64) { logs++; pg_logf("FAKE TRANSFER tracked req=%d peer_type=%d", request_id, pt); }
            }
        }
    }
    // Fragment phone: remember every fragment.getCollectibleInfo (phone) requestId so the response ring
    // answers it (must answer EVERY tap or the collectible-phone row null-derefs). Forward as normal
    // (return 0); the substitution happens in pg_apply_response. Phone collectibles only (usernames fall
    // through to the server reply). body[0]=method ctor, body[1]=boxed inputCollectible{Phone,Username}.
    if (g_fragment_phone_enabled && ctor == PG_TL_FRAGMENT_GET_COLLECTIBLE_INFO && bodyN >= 2
            && body[1] == PG_TL_INPUT_COLLECTIBLE_PHONE) {
        int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
        pg_fragment_track(request_id);
        if (logs < 64) { logs++; pg_logf("FRAGMENT PHONE tracked requestId=%d", request_id); }
    }
    // Custom-username collectibles: track getCollectibleInfo{inputCollectibleUsername} whose username matches
    // one of ours, so pg_cu_collectible answers it with that username's configured Fragment info. body[2..] =
    // username:string (after the method ctor + the inputCollectibleUsername ctor).
    if (g_custom_usernames_enabled && g_custom_usernames_count > 0
            && ctor == PG_TL_FRAGMENT_GET_COLLECTIBLE_INFO && bodyN >= 3
            && body[1] == PG_TL_INPUT_COLLECTIBLE_USERNAME) {
        char uname[64];
        pg_tl_read_string((const uint8_t*)(body + 2), (size_t)(bodyN - 2) * 4, uname, sizeof uname);
        char *u = uname; if (*u == '@') u++;
        int32_t idx = -1;
        for (size_t k = 0; k < g_custom_usernames_count; k++)
            if (_stricmp(g_custom_usernames[k], u) == 0) { idx = (int32_t)k; break; }
        if (idx >= 0) {
            int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
            pg_cu_coll_track(request_id, idx);
            if (logs < 64) { logs++; pg_logf("CU COLLECTIBLE tracked req=%d username=%s idx=%d", request_id, u, idx); }
        }
    }
    // Custom fact check: track every messages.getFactCheck so the response ring answers it with our note.
    // The reply needs one factCheck per requested msg_id → capture the msg_id:Vector<int> count. Forward as
    // normal (return 0); substitution happens in pg_apply_response. body[0]=ctor, body[1..]=boxed peer then vec.
    if (g_fact_check_enabled && g_message_settings_enabled && ctor == PG_TL_MESSAGES_GET_FACT_CHECK
            && g_fact_check_text[0]) {
        int32_t fc_count = 0;
        const int32_t lim = (bodyN < 512) ? bodyN : 512;
        for (int32_t j = 1; j + 1 < lim; j++) {
            if (body[j] == PG_TL_VECTOR_ID) {                            // the msg_id:Vector<int>
                int32_t c = (int32_t)body[j + 1];
                if (c > 0 && c <= 256 && j + 2 + c <= lim) { fc_count = c; break; }
            }
        }
        if (fc_count > 0) {
            int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
            pg_fact_check_track(request_id, fc_count);
            if (logs < 64) { logs++; pg_logf("FACT CHECK tracked requestId=%d count=%d", request_id, fc_count); }
        }
    }
    // Custom usernames: remember every users.getFullUser / users.getUsers requestId so the response rewriter
    // can splice the self user's usernames Vector. Forward as normal (return 0).
    if (g_custom_usernames_enabled && g_custom_usernames_count > 0
            && (ctor == PG_TL_USERS_GET_FULL_USER || ctor == PG_TL_USERS_GET_USERS)) {
        int32_t request_id = *(int32_t*)(rdata + PG_REQUEST_DATA_REQUEST_ID_OFFSET);
        pg_cu_track(request_id);
        if (logs < 64) { logs++; pg_logf("CUSTOM USERNAMES tracked req=%d ctor=%#x", request_id, ctor); }
    }
    // Always offline: force account.updateStatus { offline:Bool } to boolTrue (in place).
    if (g_always_offline_enabled && ctor == 0x6628562cu && bodyN >= 2 && can_write) {
        if (body[1] != 0x997275b5u) {
            body[1] = 0x997275b5u;   // boolTrue
            if (logs < 64) { logs++; pg_logf("ALWAYS OFFLINE forced account.updateStatus offline=boolTrue"); }
        }
    }
    // Don't share phone: clear add_phone_privacy_exception (flags.0) in contacts.addContact (in place).
    if (g_no_phone_on_add_enabled && ctor == 0xd9ba2e54u && bodyN >= 2 && can_write) {
        if (body[1] & 1u) {
            body[1] &= ~1u;
            if (logs < 64) { logs++; pg_logf("NO PHONE ON ADD: stripped add_phone_privacy_exception"); }
        }
    }
    // Block typing: drop messages.setTyping.
    if (g_block_typing_enabled && ctor == 0x58943ee2u) {
        if (logs < 64) { logs++; pg_logf("BLOCK TYPING: dropped messages.setTyping"); }
        return 1;
    }
    // Local drafts: drop messages.saveDraft#ad0fa15c so drafts are never synced to the server (stay local).
    if (g_local_drafts_enabled && ctor == 0xad0fa15cu) {
        if (logs < 64) { logs++; pg_logf("LOCAL DRAFTS: dropped messages.saveDraft"); }
        return 1;
    }
    // Block read messages: drop read-history / read-contents / read-discussion requests.
    if (g_block_read_enabled && (ctor == 0x0e306d3au || ctor == 0xcc104937u
                              || ctor == 0x36a73f77u || ctor == 0xf731a9f4u)) {
        if (logs < 64) { logs++; pg_logf("BLOCK READ: dropped request ctor=%#x", ctor); }
        return 1;
    }
    // Disable ads: drop messages.getSponsoredMessages (Telegram Ads) + help.getPromoData (proxy sponsor
    // / top-promo). Same request-side family as macOS's BinaryAdsPatchModule "poisonConstructor" (it
    // mangled the request ctor so the server rejected it) — on Windows we own sendPrepared, so we drop
    // the request pre-queue instead: it never sends, no MTP resend, the ad surfaces just stay empty.
    if ((g_disable_ads_telegram && ctor == 0x3d6ce850u) || (g_disable_ads_proxy && ctor == 0xc0977421u)) {
        if (logs < 64) { logs++; pg_logf("DISABLE ADS: dropped request ctor=%#x", ctor); }
        return 1;
    }
    // Hide stories: drop the stories.* fetch requests that populate the stories feed / per-peer story
    // rings (getAllStories, getPeerStories, getPeerMaxIDs, getPinnedStories, getStoriesArchive,
    // getStoriesByID). With these dropped, no story data ever loads → the stories row stays empty. This
    // is the request-side half of macOS's stories poisonConstructor; the client-side setStoriesState
    // byte-patch (instant-clear of already-cached state) is the IDA-tier complement.
    if (g_hide_stories_enabled && (ctor == 0xeeb0d625u || ctor == 0x2c4ada50u || ctor == 0x78499170u
                                || ctor == 0x5821a5dcu || ctor == 0xb4352016u || ctor == 0x5774ca74u)) {
        if (logs < 64) { logs++; pg_logf("HIDE STORIES: dropped request ctor=%#x", ctor); }
        return 1;
    }
    return 0;
}
