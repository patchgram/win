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
    size_t   found_off, found_len;     // that Document's [off, off+len)
    int      doc_match_pending;        // internal: between matching a Document and the end of its ctor
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
    int      sg_post_gift;             // walk state: inside the target savedStarGift, AFTER its gift field
    size_t   sg_transfer_off;          // the savedStarGift's transfer_stars insert offset (param boundary, f0.8)
};

// Walk a payments.savedStarGifts response IN PLACE, overwriting the configured scalar fields of each
// gift. Returns the number of fields overwritten (0 if the top ctor isn't payments.savedStarGifts).
int patchgram_tl_rewrite_saved_star_gifts(uint8_t *body, size_t bytelen, struct PatchgramTLRewrite *rw);

// Read-only walk of a payments.savedStarGifts response → the first regular starGift's byte span + that
// gift's sticker Document span. Returns 1 iff a regular gift was found (gift_len>0). doc_len may be 0.
int patchgram_tl_find_saved_gift(const uint8_t *body, size_t bytelen,
                                 size_t *gift_off, size_t *gift_len, size_t *doc_off, size_t *doc_len);
int patchgram_tl_find_gift_splice(const uint8_t *body, size_t bytelen, size_t *gift_off, size_t *gift_len,
                                  size_t *flags_off, size_t *auction_off, size_t *transfer_off);

// Capture helpers for the hidden-gifts rebuilder (read-only walks; return 1 on success):
//  - doc_thumbs: locate a Document's `thumbs` field span (used to slim a cloned sticker doc).
//  - doc_template: in a payments.starGifts buffer, find the first Document (clone template) + the byte
//    offset where the gifts vector ends (= the `chats` field), used as a structure guard.
int patchgram_tl_capture_doc_thumbs(const uint8_t *doc, size_t len, size_t *off, size_t *tlen);
int patchgram_tl_find_doc_template(const uint8_t *body, size_t len,
                                   size_t *doc_off, size_t *doc_len, size_t *gifts_end);
// Validate that `body` is exactly one well-formed object whose top ctor == `expected_top`.
int patchgram_tl_validate_top(const uint8_t *body, size_t bytelen, uint32_t expected_top);

#ifdef __cplusplus
}
#endif
