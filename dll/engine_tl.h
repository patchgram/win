// Portable MTProto TL decoder — public interface.
// Ported from the macOS Patchgram engine (engine.c.template). The decoder is pure, read-only C and is
// platform-independent (MTProto wire format is identical everywhere); only the CALLER differs, extracting
// the (words,count) buffer from the Qt5 vs Qt6 container. This is the read-only half of the engine port;
// the in-place rewriters (gifts/messages/etc.) come next and reuse the same schema + walker.
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Decode one MTProto object (the body words, `bytelen` bytes) into `out` as readable TL:
// "name#id { field=value, vec=[...], nested#id { ... } }". Never crashes: on an unknown ctor or a
// short/odd buffer it stops and keeps whatever decoded so far (appends "…" if the output was truncated).
void patchgram_tl_decode(const uint8_t *body, size_t bytelen, char *out, size_t outcap);

// Returns 1 iff `body` is exactly one well-formed TL object consuming all `bytelen` bytes (no output).
// Used to verify an in-place rewrite (e.g. account-freeze inject) before publishing the new size.
int patchgram_tl_validate(const uint8_t *body, size_t bytelen);

// ---- in-place rewrite context (the `rw`-walker) -------------------------------------------------
// Ported from the macOS engine's PatchgramTLRewrite, BASE (non-unique) subset: only fixed-size scalar
// overwrites that don't change the buffer length (date/gift id/stars/sender/sticker/supply/gift_num/
// refunded). The unique-gift + caption rebuild fields (which need a Qt5 realloc) are deferred. The
// walker writes directly into `base` at the byte offset of each matched field — platform-independent.
struct PatchgramTLRewrite {
    uint8_t *base;          // writable buffer base (== the decoded mtpPrime words)
    int64_t  sender_id;     // savedStarGift.from_id Peer id (0 = leave); also flips the peer ctor
    int      sender_peer_type; // 0=peerUser 1=peerChannel 2=peerChat
    int32_t  date;          // savedStarGift.date (0 = leave)
    int64_t  gift_id;       // starGift(.unique).id (0 = leave)
    int64_t  sticker_id;    // gift sticker Document.id → custom emoji id (0 = leave)
    int64_t  stars;         // starGift.stars (0 = leave)
    int64_t  convert_stars; // starGift/savedStarGift.convert_stars (0 = leave; in-place only when present)
    int32_t  available;     // starGift.availability_remains (only when force_limited)
    int32_t  total;         // starGift.availability_total (only when force_limited)
    int      force_limited; // 1 = write available/total verbatim over an already-limited gift
    int32_t  gift_num;      // savedStarGift.gift_num (0 = leave; in-place only when present)
    int      was_refunded;  // 1 = set savedStarGift.refunded (flag.9) in place
    int      force_upgrade; // 1 = set savedStarGift.can_upgrade (flag.10) in place (shows the Upgrade button)
    int      in_from_id;    // walk state: >0 while inside savedStarGift.from_id Peer
    int      in_sticker;    // walk state: >0 while inside starGift.sticker Document
    int      applied;       // count of fields overwritten
    // ---- read-only capture (offset recording for the realloc rebuilders; the walker never writes here) ----
    int      capture;          // 1 = record the spans below during the walk
    size_t   thumbs_off, thumbs_len;   // a Document's `thumbs` field span (while in_sticker) — for doc_slim
    int      find_first_doc;   // 1 = capture the first Document's byte range (clone template)
    int64_t  find_doc_id;      // !=0 = capture the Document#8fd4c4d8 whose id (doc+8) == this (else first doc)
    size_t   found_off, found_len;     // that Document's [off, off+len)
    int      doc_match_pending;        // internal: between matching a Document and the end of its ctor
    // ---- captured custom-emoji doc → sticker-attr flip (unique-gift render; read-only walk) ----
    int      find_sticker_attr;        // 1 = record the documentAttributeSticker ctor word + its flags
    size_t   sticker_attr_off;         // byte offset of that ctor u32 (0 = not seen) — flip to customEmoji
    uint32_t sticker_attr_flags;       // its first param (flags); only flip when this == 0
    size_t   last_ctor_start;          // byte offset of the most recent boxed ctor (set in decode_value)
    int      find_gifts_end;   // 1 = record where payments.starGifts.gifts ends (= start of `chats`)
    size_t   gifts_end_off;
    // ---- unique-gift rebuild capture (Spoof-profile-unique-gifts; read-only walk) ----
    // Captures the FIRST regular savedStarGift.gift (a starGift#313a9547) byte span + that gift's sticker
    // Document span (the doc is cloned UNCHANGED into the rebuilt starGiftUnique so it still renders).
    int      find_saved_gift;          // 1 = arm the capture
    size_t   sg_gift_off, sg_gift_len; // the starGift object span [off, off+len)
    int      sg_gift_pending;          // walk state: between the starGift ctor entry and its exit
    size_t   sg_doc_off, sg_doc_len;   // that gift's sticker Document span (first Document inside the gift)
    int      sg_doc_pending;           // walk state: between the sticker Document ctor entry and its exit
    // caption/auction splice capture (for the same first regular gift):
    size_t   sg_flags_off;             // the wrapping savedStarGift's flags word offset (to flip message f0.2)
    size_t   sg_pending_flags_off;     // walk state: current savedStarGift's flags offset
    size_t   sg_auction_off;           // the starGift's auction_slug insert offset (param boundary)
    size_t   sg_avail_off;             // the starGift's availability_remains insert offset (param boundary, f0.0)
    size_t   sg_title_off;             // the starGift's title insert offset (param boundary, f0.5)
    int      sg_post_gift;             // walk state: inside the target savedStarGift, AFTER its gift field
    size_t   sg_transfer_off;          // the savedStarGift's transfer_stars insert offset (param boundary, f0.8)
    size_t   sg_gift_num_off;          // the savedStarGift's gift_num insert offset (param boundary, f0.19)
    size_t   sg_can_export_off;        // savedStarGift.can_export_at VALUE offset (f0.7) — overwrite to bypass cooldown
    size_t   sg_can_transfer_off;      // savedStarGift.can_transfer_at VALUE offset (f0.13) — overwrite to bypass cooldown
    int      sg_gift_target;           // INPUT: which regular starGift (0-based) to capture (0 = first)
    int      sg_gift_count;            // walk state: regular starGifts seen so far
};

// One regular gift's splice points within a payments.savedStarGifts response (byte offsets into the reply).
struct PgGiftSplice {
    int      found;
    size_t   gift_off, gift_len;       // the starGift object span (gift_off+gift_len = message/caption insert point)
    size_t   sg_flags_off;             // wrapping savedStarGift flags word (message f0.2, transfer f0.8, gift_num f0.19)
    size_t   avail_off;                // starGift availability_remains boundary (f0.0)
    size_t   title_off;                // starGift title boundary (f0.5)
    size_t   auction_off;              // starGift auction_slug boundary (f0.11)
    size_t   transfer_off;             // savedStarGift transfer_stars boundary (f0.8)
    size_t   gift_num_off;             // savedStarGift gift_num boundary (f0.19)
    size_t   can_export_off;           // savedStarGift can_export_at VALUE (f0.7) — overwrite past → bypass cooldown
    size_t   can_transfer_off;         // savedStarGift can_transfer_at VALUE (f0.13) — overwrite past → bypass cooldown
};

// Walk a payments.savedStarGifts response IN PLACE, overwriting the configured scalar fields of each
// gift. Returns the number of fields overwritten (0 if the top ctor isn't payments.savedStarGifts).
int patchgram_tl_rewrite_saved_star_gifts(uint8_t *body, size_t bytelen, struct PatchgramTLRewrite *rw);

// Read-only walk of a payments.savedStarGifts response → the first regular starGift's byte span + that
// gift's sticker Document span. Returns 1 iff a regular gift was found (gift_len>0). doc_len may be 0.
int patchgram_tl_find_saved_gift(const uint8_t *body, size_t bytelen,
                                 size_t *gift_off, size_t *gift_len, size_t *doc_off, size_t *doc_len);
// Same, but for the (gift_index)-th regular starGift (0-based; 0 = first). Used to rebuild EVERY gift,
// not just the first. Returns 1 iff that gift exists.
int patchgram_tl_find_saved_gift_n(const uint8_t *body, size_t bytelen, int gift_index,
                                   size_t *gift_off, size_t *gift_len, size_t *doc_off, size_t *doc_len);
// Find the (gift_index)-th regular starGift in a payments.savedStarGifts reply + all its splice points.
// Returns 1 iff that gift exists (out->found set). gift_index 0 = the first gift (newest = top of the UI).
int patchgram_tl_find_gift_n(const uint8_t *body, size_t bytelen, int gift_index, struct PgGiftSplice *out);

// Capture helpers for the hidden-gifts rebuilder (read-only walks; return 1 on success):
//  - doc_thumbs: locate a Document's `thumbs` field span (used to slim a cloned sticker doc).
//  - doc_template: in a payments.starGifts buffer, find the first Document (clone template) + the byte
//    offset where the gifts vector ends (= the `chats` field), used as a structure guard.
int patchgram_tl_capture_doc_thumbs(const uint8_t *doc, size_t len, size_t *off, size_t *tlen);
// Read-only walk of a single Document → the byte offset of its documentAttributeSticker ctor word + that
// attribute's flags (first param). Returns 1 iff found. Caller flips the ctor → documentAttributeCustomEmoji
// (only when *flags==0) so the cloned/captured sticker renders via the custom-emoji path.
int patchgram_tl_find_sticker_attr(const uint8_t *doc, size_t len, size_t *attr_off, uint32_t *attr_flags);
// Read-only walk of a (bare Vector<Document> / messages.stickerSet / starGiftUpgradePreview) response →
// the byte span of the Document#8fd4c4d8 whose id (doc+8) == doc_id. Returns 1 iff found.
int patchgram_tl_find_doc_by_id(const uint8_t *body, size_t bytelen, int64_t doc_id,
                                size_t *doc_off, size_t *doc_len);
int patchgram_tl_find_doc_template(const uint8_t *body, size_t len,
                                   size_t *doc_off, size_t *doc_len, size_t *gifts_end);
// Validate that `body` is exactly one well-formed object whose top ctor == `expected_top`.
int patchgram_tl_validate_top(const uint8_t *body, size_t bytelen, uint32_t expected_top);

#ifdef __cplusplus
}
#endif
