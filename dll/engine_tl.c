// Portable MTProto TL decoder — implementation (compile as C: cl /TC).
//
// Ported VERBATIM (behaviour-identical) from the macOS Patchgram engine's TL walker
// (engine.c.template lines ~5245-5824), with the rewrite/capture context (`PatchgramTLRewrite *rw`)
// dropped: this is the READ-ONLY decoder used by the MTProto logger. Every rewriter branch in the
// original was guarded by `if (rw ...)`, so removing them yields byte-identical decoded output. The
// in-place rewriters will reintroduce `rw` in a separate, Qt5-aware writeback path.
//
// Schema: tl_schema.c.inc (generated, layer 227, 2464 ctors) provides g_tl_strpool / g_tl_ctors /
// g_tl_ctor_count / g_tl_params. It references the two structs below, so they are declared first.

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

#include "engine_tl.h"

/* Param type opcodes — MUST match scripts/gen_tl_schema_c.py (the schema generator). */
enum {
    PG_TL_INT = 0, PG_TL_LONG = 1, PG_TL_DOUBLE = 2, PG_TL_STRING = 3, PG_TL_BYTES = 4,
    PG_TL_INT128 = 5, PG_TL_INT256 = 6, PG_TL_FLAGS = 7, PG_TL_TRUE = 8, PG_TL_BOXED = 9,
    PG_TL_COMPLEX = 10
};
struct PatchgramTLCtor { uint32_t id; uint32_t name_off; uint16_t pstart; uint16_t pcount; };
struct PatchgramTLParam { uint32_t name_off; uint8_t flag_idx; uint8_t flag_bit; uint8_t vec; uint8_t op; };

#include "tl_schema.c.inc"

#define PATCHGRAM_TL_VECTOR_ID 0x1cb5c415u

struct PatchgramTLReader { const uint8_t *p; size_t len; size_t pos; bool err; };
struct PatchgramTLOut { char *buf; size_t cap; size_t len; bool full; };

static const struct PatchgramTLCtor *patchgram_tl_find(uint32_t id) {
    int lo = 0, hi = (int)g_tl_ctor_count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) >> 1;
        uint32_t v = g_tl_ctors[mid].id;
        if (v < id) { lo = mid + 1; }
        else if (v > id) { hi = mid - 1; }
        else { return &g_tl_ctors[mid]; }
    }
    return NULL;
}
// A NULL `o->buf` is a "silent sink": every put no-ops and `full` is never set, so the walker traverses
// the WHOLE buffer (used by patchgram_tl_validate to re-parse without allocating an output buffer).
static void patchgram_tl_put(struct PatchgramTLOut *o, const char *s) {
    if (!o->buf || o->full) { return; }
    while (*s) {
        if (o->len + 1 >= o->cap) { o->full = true; break; }
        o->buf[o->len++] = *s++;
    }
    o->buf[o->len] = 0;
}
static void patchgram_tl_put_raw(struct PatchgramTLOut *o, const uint8_t *b, size_t n) {
    if (!o->buf || o->full) { return; }
    for (size_t i = 0; i < n; i++) {
        if (o->len + 1 >= o->cap) { o->full = true; break; }
        o->buf[o->len++] = (char)b[i];
    }
    o->buf[o->len] = 0;
}
static uint32_t patchgram_tl_u32(struct PatchgramTLReader *r) {
    if (r->pos + 4 > r->len) { r->err = true; return 0; }
    uint32_t v; memcpy(&v, r->p + r->pos, 4); r->pos += 4; return v;
}
static int64_t patchgram_tl_i64(struct PatchgramTLReader *r) {
    if (r->pos + 8 > r->len) { r->err = true; return 0; }
    int64_t v; memcpy(&v, r->p + r->pos, 8); r->pos += 8; return v;
}
static double patchgram_tl_f64(struct PatchgramTLReader *r) {
    if (r->pos + 8 > r->len) { r->err = true; return 0; }
    double v; memcpy(&v, r->p + r->pos, 8); r->pos += 8; return v;
}
static void patchgram_tl_put_hex(struct PatchgramTLOut *o, const uint8_t *b, size_t n) {
    static const char H[] = "0123456789abcdef";
    patchgram_tl_put(o, "0x");
    for (size_t i = 0; i < n && !o->full; i++) {
        char two[2] = { H[b[i] >> 4], H[b[i] & 0xf] };
        patchgram_tl_put_raw(o, (const uint8_t *)two, 2);
    }
}
// TL string/bytes: 1-or-4-byte length prefix, payload, padded to 4. Text shown quoted (raw UTF-8,
// capped), binary shown as hex (capped). Advances the reader past the padded field.
static void patchgram_tl_str(struct PatchgramTLReader *r, struct PatchgramTLOut *o, bool as_text) {
    if (r->pos >= r->len) { r->err = true; return; }
    size_t head, n;
    uint32_t L = r->p[r->pos];
    if (L < 254) { n = L; head = 1; }
    else {
        if (r->pos + 4 > r->len) { r->err = true; return; }
        n = (size_t)r->p[r->pos + 1] | ((size_t)r->p[r->pos + 2] << 8) | ((size_t)r->p[r->pos + 3] << 16);
        head = 4;
    }
    size_t start = r->pos + head;
    if (start + n > r->len) { r->err = true; n = (start < r->len) ? r->len - start : 0; }
    if (as_text) {
        size_t shown = n > 96 ? 96 : n;
        patchgram_tl_put(o, "\"");
        patchgram_tl_put_raw(o, r->p + start, shown);
        if (n > shown) { patchgram_tl_put(o, "\xe2\x80\xa6"); }
        patchgram_tl_put(o, "\"");
    } else {
        size_t shown = n > 32 ? 32 : n;
        patchgram_tl_put_hex(o, r->p + start, shown);
        if (n > shown) { patchgram_tl_put(o, "\xe2\x80\xa6"); }
    }
    size_t total = head + n;
    r->pos += total + ((4 - (total & 3)) & 3);
}

// ---- gift rewrite: TL constructor ids + the per-field in-place scalar overwriter ----------------
#define PG_TL_PAYMENTS_SAVED_STAR_GIFTS 0x95f389b1u
#define PG_TL_PAYMENTS_STAR_GIFTS       0x2ed82995u
#define PG_TL_SAVED_STAR_GIFT           0x41df43fcu
#define PG_TL_STAR_GIFT                 0x313a9547u
#define PG_TL_STAR_GIFT_UNIQUE          0x85f0a9cdu
#define PG_TL_PEER_USER                 0x59511722u
#define PG_TL_PEER_CHANNEL              0xa2a5371eu
#define PG_TL_PEER_CHAT                 0x36c6019au
#define PG_TL_DOCUMENT                  0x8fd4c4d8u

// Overwrite one fixed-size scalar field of a gift in place (base subset; ported from
// patchgram_gift_rewrite_field, sans the unique-gift branches). `r->pos` is the field's byte offset.
static void patchgram_gift_rewrite_field(struct PatchgramTLRewrite *rw, uint32_t ctor,
                                         const struct PatchgramTLParam *p, struct PatchgramTLReader *r) {
    if (p->vec) { return; }
    const char *name = g_tl_strpool + p->name_off;
    if (ctor == PG_TL_SAVED_STAR_GIFT && p->op == PG_TL_INT && rw->date && strcmp(name, "date") == 0) {
        if (r->pos + 4 <= r->len) { int32_t v = rw->date; memcpy(rw->base + r->pos, &v, 4); rw->applied++; }
    } else if ((ctor == PG_TL_STAR_GIFT || ctor == PG_TL_STAR_GIFT_UNIQUE)
               && p->op == PG_TL_LONG && rw->gift_id && strcmp(name, "id") == 0) {
        if (r->pos + 8 <= r->len) { int64_t v = rw->gift_id; memcpy(rw->base + r->pos, &v, 8); rw->applied++; }
    } else if (ctor == PG_TL_STAR_GIFT && p->op == PG_TL_LONG && rw->stars && strcmp(name, "stars") == 0) {
        if (r->pos + 8 <= r->len) { int64_t v = rw->stars; memcpy(rw->base + r->pos, &v, 8); rw->applied++; }
    } else if ((ctor == PG_TL_STAR_GIFT || ctor == PG_TL_SAVED_STAR_GIFT) && p->op == PG_TL_LONG
               && rw->convert_stars && strcmp(name, "convert_stars") == 0) {
        if (r->pos + 8 <= r->len) { int64_t v = rw->convert_stars; memcpy(rw->base + r->pos, &v, 8); rw->applied++; }
    } else if (ctor == PG_TL_STAR_GIFT && p->op == PG_TL_INT && rw->force_limited
               && strcmp(name, "availability_remains") == 0) {
        if (r->pos + 4 <= r->len) { int32_t v = rw->available; memcpy(rw->base + r->pos, &v, 4); rw->applied++; }
    } else if (ctor == PG_TL_STAR_GIFT && p->op == PG_TL_INT && rw->force_limited
               && strcmp(name, "availability_total") == 0) {
        if (r->pos + 4 <= r->len) { int32_t v = rw->total; memcpy(rw->base + r->pos, &v, 4); rw->applied++; }
    } else if (ctor == PG_TL_SAVED_STAR_GIFT && p->op == PG_TL_INT && rw->gift_num
               && strcmp(name, "gift_num") == 0) {
        if (r->pos + 4 <= r->len) { int32_t v = rw->gift_num; memcpy(rw->base + r->pos, &v, 4); rw->applied++; }
    } else if (ctor == PG_TL_DOCUMENT && rw->in_sticker && p->op == PG_TL_LONG && rw->sticker_id
               && strcmp(name, "id") == 0) {
        if (r->pos + 8 <= r->len) { int64_t v = rw->sticker_id; memcpy(rw->base + r->pos, &v, 8); rw->applied++; }
    } else if ((ctor == PG_TL_PEER_USER || ctor == PG_TL_PEER_CHANNEL || ctor == PG_TL_PEER_CHAT)
               && rw->in_from_id && p->op == PG_TL_LONG && rw->sender_id) {
        // peerUser/Channel/Chat .id (only long in from_id) — flip the peer ctor (4 bytes back) + the id.
        if (r->pos + 8 <= r->len && r->pos >= 4) {
            uint32_t pc = (rw->sender_peer_type == 1) ? PG_TL_PEER_CHANNEL
                        : (rw->sender_peer_type == 2) ? PG_TL_PEER_CHAT : PG_TL_PEER_USER;
            memcpy(rw->base + r->pos - 4, &pc, 4);
            int64_t v = rw->sender_id; memcpy(rw->base + r->pos, &v, 8);
            rw->applied++;
        }
    }
}

static void patchgram_tl_decode_ctor(uint32_t id, struct PatchgramTLReader *r,
                                     struct PatchgramTLOut *o, int depth, bool with_id,
                                     struct PatchgramTLRewrite *rw);

static void patchgram_tl_decode_value(uint8_t vec, uint8_t op, struct PatchgramTLReader *r,
                                      struct PatchgramTLOut *o, int depth, struct PatchgramTLRewrite *rw) {
    if (r->err || o->full) { return; }
    if (depth > 24) { r->err = true; return; }
    if (vec) {
        if (vec == 1) {
            if (patchgram_tl_u32(r) != PATCHGRAM_TL_VECTOR_ID) { patchgram_tl_put(o, "<novec>"); r->err = true; return; }
        }
        int32_t n = (int32_t)patchgram_tl_u32(r);
        if (n < 0 || n > 200000) { patchgram_tl_put(o, "<badvec>"); r->err = true; return; }
        patchgram_tl_put(o, "[");
        for (int32_t k = 0; k < n && !r->err && !o->full; k++) {
            if (k) { patchgram_tl_put(o, ", "); }
            patchgram_tl_decode_value(0, op, r, o, depth + 1, rw);
        }
        patchgram_tl_put(o, "]");
        return;
    }
    char tmp[48];
    switch (op) {
        case PG_TL_INT:    snprintf(tmp, sizeof tmp, "%d", (int32_t)patchgram_tl_u32(r)); patchgram_tl_put(o, tmp); break;
        case PG_TL_FLAGS:  snprintf(tmp, sizeof tmp, "0x%x", patchgram_tl_u32(r)); patchgram_tl_put(o, tmp); break;
        case PG_TL_LONG:   snprintf(tmp, sizeof tmp, "%lld", (long long)patchgram_tl_i64(r)); patchgram_tl_put(o, tmp); break;
        case PG_TL_DOUBLE: snprintf(tmp, sizeof tmp, "%g", patchgram_tl_f64(r)); patchgram_tl_put(o, tmp); break;
        case PG_TL_INT128: if (r->pos + 16 <= r->len) { patchgram_tl_put_hex(o, r->p + r->pos, 16); r->pos += 16; } else { r->err = true; } break;
        case PG_TL_INT256: if (r->pos + 32 <= r->len) { patchgram_tl_put_hex(o, r->p + r->pos, 32); r->pos += 32; } else { r->err = true; } break;
        case PG_TL_STRING: patchgram_tl_str(r, o, true); break;
        case PG_TL_BYTES:  patchgram_tl_str(r, o, false); break;
        case PG_TL_TRUE:   patchgram_tl_put(o, "true"); break;
        case PG_TL_BOXED:  if (rw) { rw->last_ctor_start = r->pos; } patchgram_tl_decode_ctor(patchgram_tl_u32(r), r, o, depth + 1, false, rw); break;
        default:           patchgram_tl_put(o, "<complex>"); r->err = true; break;
    }
}

static void patchgram_tl_decode_ctor(uint32_t id, struct PatchgramTLReader *r,
                                     struct PatchgramTLOut *o, int depth, bool with_id,
                                     struct PatchgramTLRewrite *rw) {
    if (r->err || o->full) { return; }
    if (depth > 24) { r->err = true; return; }
    char scratch[24];
    const struct PatchgramTLCtor *c = patchgram_tl_find(id);
    if (!c) {
        snprintf(scratch, sizeof scratch, "unknown#%08x", id);
        patchgram_tl_put(o, scratch);
        r->err = true;  /* unknown params → stop rather than misparse */
        return;
    }
    patchgram_tl_put(o, g_tl_strpool + c->name_off);
    if (with_id) { snprintf(scratch, sizeof scratch, "#%08x", id); patchgram_tl_put(o, scratch); }
    // capture: remember the first Document's start (clone template) — finalized to a length below.
    if (rw && rw->find_first_doc && rw->found_len == 0 && !rw->doc_match_pending && id == PG_TL_DOCUMENT) {
        rw->found_off = rw->last_ctor_start; rw->doc_match_pending = 1;
    }
    // capture (unique-gift rebuild): first regular starGift span, then its sticker Document span (the first
    // Document *inside* that gift). Mirrors the find_first_doc entry/exit pattern; doc gated on sg_gift_pending
    // so a unique gift appearing before the regular one can't steal the doc.
    if (rw && rw->find_saved_gift) {
        if (rw->sg_gift_len == 0 && !rw->sg_gift_pending && id == PG_TL_STAR_GIFT) {
            // Capture the sg_gift_target-th regular starGift (skip the earlier ones, just counting them).
            if (rw->sg_gift_count == rw->sg_gift_target) { rw->sg_gift_off = rw->last_ctor_start; rw->sg_gift_pending = 1; }
            rw->sg_gift_count++;
        } else if (rw->sg_gift_pending && rw->sg_doc_len == 0 && !rw->sg_doc_pending && id == PG_TL_DOCUMENT) {
            rw->sg_doc_off = rw->last_ctor_start; rw->sg_doc_pending = 1;
        }
    }
    if (c->pcount == 0) { return; }
    uint32_t flagvals[256];
    memset(flagvals, 0, sizeof flagvals);
    patchgram_tl_put(o, " { ");
    bool first = true;
    for (uint16_t i = 0; i < c->pcount && !r->err && !o->full; i++) {
        const struct PatchgramTLParam *p = &g_tl_params[c->pstart + i];
        // caption/auction capture: record the wrapping savedStarGift's flags offset (committed when the first
        // regular starGift is found) and the starGift's auction_slug insert boundary (param pos, present or not).
        if (rw && rw->find_saved_gift) {
            if (p->op == PG_TL_FLAGS && id == PG_TL_SAVED_STAR_GIFT) rw->sg_pending_flags_off = r->pos;
            if (rw->sg_gift_pending && rw->sg_auction_off == 0 && id == PG_TL_STAR_GIFT
                && strcmp(g_tl_strpool + p->name_off, "auction_slug") == 0) rw->sg_auction_off = r->pos;
            // availability_remains (f0.0) insert boundary — captured at the param index (present or not), so
            // a non-limited gift can be MADE limited by inserting availability_remains+total right after `stars`.
            if (rw->sg_gift_pending && rw->sg_avail_off == 0 && id == PG_TL_STAR_GIFT
                && strcmp(g_tl_strpool + p->name_off, "availability_remains") == 0) rw->sg_avail_off = r->pos;
            // title (f0.5) insert boundary — shown as the gift name on auction/upgraded gifts.
            if (rw->sg_gift_pending && rw->sg_title_off == 0 && id == PG_TL_STAR_GIFT
                && strcmp(g_tl_strpool + p->name_off, "title") == 0) rw->sg_title_off = r->pos;
        }
        // transfer_stars (savedStarGift param 16, f0.8) is AFTER the gift, so capture it once we're past the
        // gift in the target savedStarGift (find_saved_gift is already cleared by then → use sg_post_gift).
        if (rw && rw->sg_post_gift && rw->sg_transfer_off == 0 && id == PG_TL_SAVED_STAR_GIFT
            && strcmp(g_tl_strpool + p->name_off, "transfer_stars") == 0) rw->sg_transfer_off = r->pos;
        if (rw && rw->sg_post_gift && rw->sg_gift_num_off == 0 && id == PG_TL_SAVED_STAR_GIFT
            && strcmp(g_tl_strpool + p->name_off, "gift_num") == 0) rw->sg_gift_num_off = r->pos;
        if (p->op == PG_TL_FLAGS) {
            const size_t flags_pos = r->pos;
            uint32_t v = patchgram_tl_u32(r);
            // refunded#flag.9 / can_upgrade#flag.10 are pure boolean true-bits (gate no field) → set them in
            // place during the walk (same-size flags-word write, no splice).
            if (rw && id == PG_TL_SAVED_STAR_GIFT && rw->was_refunded && !((v >> 9) & 1u)) {
                v |= (1u << 9);
                if (flags_pos + 4 <= r->len) { memcpy(rw->base + flags_pos, &v, 4); rw->applied++; }
            }
            if (rw && id == PG_TL_SAVED_STAR_GIFT && rw->force_upgrade && !((v >> 10) & 1u)) {
                v |= (1u << 10);
                if (flags_pos + 4 <= r->len) { memcpy(rw->base + flags_pos, &v, 4); rw->applied++; }
            }
            if (i < 256) { flagvals[i] = v; }
            if (!first) { patchgram_tl_put(o, ", "); }
            first = false;
            patchgram_tl_put(o, g_tl_strpool + p->name_off);
            snprintf(scratch, sizeof scratch, "=0x%x", v);
            patchgram_tl_put(o, scratch);
            continue;
        }
        if (p->flag_idx != 0xFF) {
            uint32_t fv = flagvals[p->flag_idx];  // flag_idx is uint8 → always in [0,255]
            if (!((fv >> p->flag_bit) & 1u)) { continue; }
            if (p->op == PG_TL_TRUE) {
                if (!first) { patchgram_tl_put(o, ", "); }
                first = false;
                patchgram_tl_put(o, g_tl_strpool + p->name_off);
                patchgram_tl_put(o, "=true");
                continue;
            }
        }
        if (!first) { patchgram_tl_put(o, ", "); }
        first = false;
        patchgram_tl_put(o, g_tl_strpool + p->name_off);
        patchgram_tl_put(o, "=");
        // rw-walker: overwrite this scalar field if configured, and track when we descend into a
        // savedStarGift.from_id Peer / starGift.sticker Document (so the nested id rewrites apply).
        int mark_from_id = 0, mark_sticker = 0;
        const size_t before_pos = r->pos;
        if (rw) {
            patchgram_gift_rewrite_field(rw, id, p, r);
            const char *pn = g_tl_strpool + p->name_off;
            if (id == PG_TL_SAVED_STAR_GIFT && p->op == PG_TL_BOXED && !p->vec && strcmp(pn, "from_id") == 0) {
                mark_from_id = 1; rw->in_from_id++;
            } else if (id == PG_TL_STAR_GIFT && p->op == PG_TL_BOXED && !p->vec && strcmp(pn, "sticker") == 0) {
                mark_sticker = 1; rw->in_sticker++;
            }
            // capture: where payments.starGifts.gifts ends (= start of `chats`) — read-only guard.
            if (rw->find_gifts_end && id == PG_TL_PAYMENTS_STAR_GIFTS && strcmp(pn, "chats") == 0) {
                rw->gifts_end_off = r->pos;
            }
        }
        patchgram_tl_decode_value(p->vec, p->op, r, o, depth, rw);
        if (mark_from_id) { rw->in_from_id--; }
        if (mark_sticker) { rw->in_sticker--; }
        // capture: a sticker Document's `thumbs` field span (for doc_slim's thumbnail stripping).
        if (rw && rw->capture && rw->in_sticker && id == PG_TL_DOCUMENT
            && strcmp(g_tl_strpool + p->name_off, "thumbs") == 0) {
            rw->thumbs_off = before_pos; rw->thumbs_len = r->pos - before_pos;
        }
    }
    // capture: finalize the first Document's byte length once its ctor is fully parsed.
    if (rw && rw->doc_match_pending && id == PG_TL_DOCUMENT && !r->err) {
        rw->found_len = r->pos - rw->found_off; rw->doc_match_pending = 0; rw->find_first_doc = 0;
    }
    // capture (unique-gift rebuild): finalize the sticker doc (inner) then the gift (outer) on ctor exit.
    if (rw && rw->find_saved_gift && !r->err) {
        if (rw->sg_doc_pending && id == PG_TL_DOCUMENT) {
            rw->sg_doc_len = r->pos - rw->sg_doc_off; rw->sg_doc_pending = 0;
        } else if (rw->sg_gift_pending && id == PG_TL_STAR_GIFT) {
            rw->sg_gift_len = r->pos - rw->sg_gift_off; rw->sg_gift_pending = 0; rw->find_saved_gift = 0;
            rw->sg_flags_off = rw->sg_pending_flags_off;   // the savedStarGift wrapping this gift
            rw->sg_post_gift = 1;                          // now capture transfer_stars (after the gift)
        }
    }
    // transfer_stars capture window ends when the target savedStarGift closes.
    if (rw && rw->sg_post_gift && id == PG_TL_SAVED_STAR_GIFT) rw->sg_post_gift = 0;
    patchgram_tl_put(o, " }");
}

void patchgram_tl_decode(const uint8_t *body, size_t bytelen, char *out, size_t outcap) {
    if (outcap < 8) { if (outcap) { out[0] = 0; } return; }
    out[0] = 0;
    struct PatchgramTLReader r = { body, bytelen, 0, false };
    struct PatchgramTLOut o = { out, outcap, 0, false };
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err) { patchgram_tl_put(&o, "<empty>"); return; }
    patchgram_tl_decode_ctor(top, &r, &o, 0, true, NULL);
    if (o.full && outcap >= 4) { memcpy(out + outcap - 4, "\xe2\x80\xa6", 3); out[outcap - 1] = 0; }
}

// Full-walk validity check (no output): returns 1 iff `body` is exactly one well-formed TL object that
// consumes all `bytelen` bytes with no read error. Used to verify an in-place rewrite before publishing it.
int patchgram_tl_validate(const uint8_t *body, size_t bytelen) {
    if (!body || bytelen < 4 || (bytelen & 3u)) { return 0; }
    struct PatchgramTLReader r = { body, bytelen, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };   // silent sink → walk the whole object
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err) { return 0; }
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, NULL);
    return (!r.err && r.pos == bytelen) ? 1 : 0;
}

// Walk a payments.savedStarGifts response IN PLACE via the rw-walker, overwriting configured scalar
// fields of each gift. Output suppressed (NULL silent sink → full traversal). Returns fields overwritten.
int patchgram_tl_rewrite_saved_star_gifts(uint8_t *body, size_t bytelen, struct PatchgramTLRewrite *rw) {
    if (!body || bytelen < 4 || !rw) { return 0; }
    struct PatchgramTLReader r = { body, bytelen, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };   // silent sink → walk the whole response
    rw->base = body;
    rw->in_from_id = 0;
    rw->in_sticker = 0;
    rw->applied = 0;
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err || top != PG_TL_PAYMENTS_SAVED_STAR_GIFTS) { return 0; }
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, rw);
    return rw->applied;
}

int patchgram_tl_find_saved_gift(const uint8_t *body, size_t bytelen,
                                 size_t *gift_off, size_t *gift_len, size_t *doc_off, size_t *doc_len) {
    if (gift_off) *gift_off = 0; if (gift_len) *gift_len = 0;
    if (doc_off)  *doc_off  = 0; if (doc_len)  *doc_len  = 0;
    if (!body || bytelen < 16) { return 0; }
    struct PatchgramTLRewrite rw; memset(&rw, 0, sizeof rw);
    rw.base = (uint8_t *)body;
    rw.find_saved_gift = 1;
    struct PatchgramTLReader r = { body, bytelen, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };   // silent sink
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err || top != PG_TL_PAYMENTS_SAVED_STAR_GIFTS) { return 0; }
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, &rw);
    if (rw.sg_gift_len == 0) { return 0; }
    if (gift_off) *gift_off = rw.sg_gift_off; if (gift_len) *gift_len = rw.sg_gift_len;
    if (doc_off)  *doc_off  = rw.sg_doc_off;  if (doc_len)  *doc_len  = rw.sg_doc_len;
    return 1;
}

// Find the (gift_index)-th regular starGift + all its splice points (see PgGiftSplice). One read-only walk.
int patchgram_tl_find_gift_n(const uint8_t *body, size_t bytelen, int gift_index, struct PgGiftSplice *out) {
    if (out) memset(out, 0, sizeof *out);
    if (!body || bytelen < 16 || !out || gift_index < 0) { return 0; }
    struct PatchgramTLRewrite rw; memset(&rw, 0, sizeof rw);
    rw.base = (uint8_t *)body;
    rw.find_saved_gift = 1;
    rw.sg_gift_target = gift_index;
    struct PatchgramTLReader r = { body, bytelen, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err || top != PG_TL_PAYMENTS_SAVED_STAR_GIFTS) { return 0; }
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, &rw);
    if (rw.sg_gift_len == 0) { return 0; }                       // no gift at that index
    out->found = 1;
    out->gift_off = rw.sg_gift_off; out->gift_len = rw.sg_gift_len;
    out->sg_flags_off = rw.sg_flags_off;
    out->avail_off = rw.sg_avail_off; out->title_off = rw.sg_title_off; out->auction_off = rw.sg_auction_off;
    out->transfer_off = rw.sg_transfer_off; out->gift_num_off = rw.sg_gift_num_off;
    return 1;
}

int patchgram_tl_validate_top(const uint8_t *body, size_t bytelen, uint32_t expected_top) {
    if (!body || bytelen < 4 || (bytelen & 3u)) { return 0; }
    struct PatchgramTLReader r = { body, bytelen, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err || top != expected_top) { return 0; }
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, NULL);
    return (!r.err && r.pos == bytelen) ? 1 : 0;
}

// Read-only walk of a single Document to find its `thumbs` field span (for doc_slim).
int patchgram_tl_capture_doc_thumbs(const uint8_t *doc, size_t len, size_t *off, size_t *tlen) {
    if (off) *off = 0; if (tlen) *tlen = 0;
    if (!doc || len < 4) return 0;
    struct PatchgramTLRewrite rw; memset(&rw, 0, sizeof rw);
    rw.base = (uint8_t *)doc; rw.capture = 1; rw.in_sticker = 1;
    struct PatchgramTLReader r = { doc, len, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err) return 0;
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, &rw);
    if (off) *off = rw.thumbs_off; if (tlen) *tlen = rw.thumbs_len;
    return (rw.thumbs_len > 0) ? 1 : 0;
}

// Read-only walk of a payments.starGifts buffer → first Document span (clone template) + the offset
// where the gifts vector ends (= start of `chats`). Returns 1 if both were found + structure is sane.
int patchgram_tl_find_doc_template(const uint8_t *body, size_t len,
                                   size_t *doc_off, size_t *doc_len, size_t *gifts_end) {
    if (doc_off) *doc_off = 0; if (doc_len) *doc_len = 0; if (gifts_end) *gifts_end = 0;
    if (!body || len < 16) return 0;
    struct PatchgramTLRewrite rw; memset(&rw, 0, sizeof rw);
    rw.base = (uint8_t *)body; rw.find_first_doc = 1; rw.find_gifts_end = 1;
    struct PatchgramTLReader r = { body, len, 0, false };
    struct PatchgramTLOut o = { NULL, 0, 0, false };
    uint32_t top = patchgram_tl_u32(&r);
    if (r.err || top != PG_TL_PAYMENTS_STAR_GIFTS) return 0;
    patchgram_tl_decode_ctor(top, &r, &o, 0, false, &rw);
    if (doc_off) *doc_off = rw.found_off; if (doc_len) *doc_len = rw.found_len;
    if (gifts_end) *gifts_end = rw.gifts_end_off;
    return (rw.found_len > 0 && rw.gifts_end_off >= 16) ? 1 : 0;
}
