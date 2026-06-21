// Patchgram-Windows — runtime TL patch engine (config + rewriters). Public interface.
//
// This is the writable half of the engine port (the read-only decoder lives in engine_tl.c). It owns the
// config (parsed from PatchgramRuntime.json, same keys as the macOS engine) and the per-request/response
// rewriters ported from engine.c.template, adapted to the Qt5 buffer ABI (see patchgram_offsets.h).
#pragma once
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parse a PatchgramRuntime.json blob and set the enable-flags. Pass NULL/"" to apply defaults
// (logger on, every rewriter off). Safe to call again on config reload. Returns the number of
// rewriter flags that ended up enabled (diagnostics).
int  pg_config_load(const char *json);

// Exercise the Qt5 resize-beyond-capacity realloc (grow→copy→swap→free) on a synthetic buffer in our
// own heap, logging PASS/FAIL. Safe (never touches Telegram data); validates the realloc logic at init.
void pg_engine_selftest(void);

// True if the MTProto logger should emit decoded lines (defaults true so the validated logger keeps
// working with no config file present).
bool pg_logger_enabled(void);

// True if the recent-stickers display-limit byte-patch should be active (the C++ side flips the
// collectRecentStickers `jb`->`jmp` in .text on init and each config reload based on this flag).
bool pg_recent_stickers_enabled(void);

// True if Hide stories is on. Drives BOTH the request-drops (in pg_apply_request) and the client-side
// setStoriesState force-clear byte-patches (applied by the C++ side) — so the stories feed AND the
// per-peer avatar story ring are removed together.
bool pg_hide_stories_enabled(void);

// True if Sensitive blur is on (the C++ side forces HistoryItem::isMediaSensitive to return false).
bool pg_sensitive_blur_enabled(void);

// True if Disable media spoilers is on (the C++ side forces the spoiler flag to 0 in Data::CreateMedia).
bool pg_disable_spoilers_enabled(void);
bool pg_disable_ttl_enabled(void);

// True if Disable premium effects is on (early-returns HistoryView::Sticker::checkPremiumEffectStart).
bool pg_premium_effects_enabled(void);

// True if 999 accounts is on (the C++ side raises the Main::Domain/Storage::Domain account caps).
bool pg_account_limit_999_enabled(void);

// True if Local Telegram Premium is on (forces premiumPossibleValue's premium bit true).
bool pg_local_premium_enabled(void);

// True if Show bot callback-data on hover is on (widens getUrlButton's accepted button types).
bool pg_callback_hover_enabled(void);

// True if Open links without warning is on (NOPs the confirmation-box branch in HiddenUrlClickHandler::Open).
bool pg_open_links_enabled(void);

// True if Hide self phone is on (the C++ side enables a hook that empties PhoneOrHiddenValue for self).
bool pg_hide_self_phone_enabled(void);

// Custom Stars / Custom TON — the C++ side byte-patches CreditsAmountFromTL to return the value. The two
// share ONE function on x64 (mutually exclusive); stars takes priority when both are on.
bool    pg_custom_stars_enabled(void);
int64_t pg_custom_stars_value(void);
bool    pg_custom_ton_enabled(void);
int64_t pg_custom_ton_value(void);

// Visual peer badge — the C++ side hooks UserData::setFlags to OR in a verified/scam/fake flag bit for
// the targeted peers (mode 0=All / 10=All except me / 20=Only me; type 1=Verified 2=Scam 3=Fake).
bool pg_peer_badge_enabled(void);
int  pg_peer_badge_mode(void);
int  pg_peer_badge_type(void);

// Custom level rating — the C++ side writes UserData's _starsRating (4×int32 @ +0x230) from the setFlags hook.
bool pg_custom_level_rating_enabled(void);
int  pg_clr_mode(void);
void pg_clr_values(int32_t *out4);   // [level, rating, currentLevelRating, nextLevelRating]

// Local attached channel — writes UserData's _personalChannelId (int64 @+0x240) + _personalChannelMessageId
// (int64 @+0x248) from the setFlags hook.
bool    pg_local_channel_enabled(void);
int     pg_local_channel_mode(void);
int64_t pg_local_channel_id(void);
int64_t pg_local_channel_msg(void);

// Custom phone — show a custom phone string on the self profile (the C++ side builds a static Qt5 QString
// and swaps it into the PhoneOrHiddenValue result for self).
bool        pg_custom_phone_enabled(void);
const char *pg_custom_phone_text(void);

// Custom userID — swap the DISPLAYED self user id (the About-row id, formatted via QLocale::toString). The
// C++ side hooks QLocale::toString and, gated by the profile-id call's return address + the self id, swaps
// the value. Display-only (peer->id, the global key, is never touched).
bool    pg_custom_userid_enabled(void);
int64_t pg_custom_userid_value(void);

// Bot verification — force a "verified by bot" badge (custom emoji + description) on targeted peers via
// the real UserData::setBotVerifyDetails (so Telegram's CRT owns the alloc/free of the unique_ptr).
bool        pg_bot_verify_enabled(void);
int         pg_bot_verify_mode(void);
uint64_t    pg_bot_verify_icon_id(void);
const char *pg_bot_verify_desc(void);

// Fragment phone — the response ring lives in engine_patches.c; the C++ glue only needs to know whether to
// enable the IsCollectiblePhone display hook (so a collectible-phone tap can never fire without the ring live).
bool        pg_fragment_phone_enabled(void);

// Apply all enabled RESPONSE rewriters to one received-queue entry (`resp` = a Response*). In-place,
// Qt5-safe (skips shared buffers). No-op when nothing is enabled.
void pg_apply_response(void *resp);

// Apply all enabled REQUEST patches to one outgoing request (`req` = &SerializedRequest). Returns 1 if
// the request should be DROPPED (caller must NOT forward it to the original sendPrepared), else 0.
int pg_apply_request(void *req);

#ifdef __cplusplus
}
#endif
