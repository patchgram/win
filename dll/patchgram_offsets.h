// Patchgram-Windows offsets for Telegram Desktop 6.9.3 (x64, **Qt 5.15.19** static).
// ALL values VERIFIED against the real binary + tdesktop v6.9.3 source — see re/offsets.md, re/signatures.md.
#pragma once
#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
#else
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#endif

// Function RVAs (module-relative) — fallback if the anchor-string resolver misses.
#define PG_RVA_TRY_TO_RECEIVE   0x2193a50ULL   // MTP::details::Session::tryToReceive
#define PG_RVA_SEND_PREPARED    0x2192cb0ULL   // MTP::details::Session::sendPrepared
#define PG_RVA_PHONE_OR_HIDDEN  0x1d7ac30ULL   // Info::Profile::PhoneOrHiddenValue map-lambda (hide self phone)
#define PG_RVA_USER_SET_FLAGS   0x14028e0ULL   // UserData::setFlags(this, uint32 flags) (visual peer badge)
#define PG_RVA_SET_BOT_VERIFY   0x1402d80ULL   // UserData::setBotVerifyDetails(this, BotVerifyDetails*)
#define PG_RVA_QLOCALE_TOSTRING 0x5328c30ULL   // QLocale::toString(qlonglong) — shared; for custom userID
#define PG_RVA_IS_COLLECTIBLE_PHONE 0x1d40050ULL // Info::Profile::IsCollectiblePhone(UserData*)->bool (fragment phone)
#define PG_RVA_USERID_SITE      0x1c8875eULL   // AboutWithAdvancedValue id-extract (movabs mask; mov [rax+8])
#define PG_RVA_USERID_GATE      0x1c88788ULL   // return addr of the profile-id toString call (the gate)

// ── Qt 5.15 QVector<T> / mtpBuffer = a SINGLE 8-byte COW pointer `d` (NOT Qt6's 24-byte {d,ptr,size}).
//    The macOS engine assumes Qt6; on Windows size+data are reached THROUGH `d` (Qt5 QArrayData header):
//    ref(int)@0x0, size(int)@0x4, alloc(uint:31)@0x8, offset(qptrdiff)@0x10. data() = (char*)d + offset.
#define PG_QT5_ARRAYDATA_SIZE_OFFSET    0x04   // int32  QArrayData::size  (element count)
#define PG_QT5_ARRAYDATA_ALLOC_OFFSET   0x08   // uint31 QArrayData::alloc (allocated capacity, mask 0x7fffffff)
#define PG_QT5_ARRAYDATA_OFFSET_OFFSET  0x10   // int64  QArrayData::offset (header -> data distance)
#define PG_QT5_ARRAYDATA_HEADER_SIZE    0x18   // sizeof(QArrayData); the standard data() offset

// Decode an mtpBuffer/QVector<int32> stored as a single `d` pointer at `container`.
// Returns the element data pointer (== QVector::constData()) or nullptr; *outCount gets the size.
static inline uint32_t* pg_qvec_data(const void* container, int32_t* outCount) {
    uint8_t* d = *(uint8_t**)container;
    if (!d) { if (outCount) *outCount = 0; return NULL; }
    int32_t count = *(int32_t*)(d + PG_QT5_ARRAYDATA_SIZE_OFFSET);
    int64_t off   = *(int64_t*)(d + PG_QT5_ARRAYDATA_OFFSET_OFFSET);
    if (outCount) *outCount = count;
    return (uint32_t*)(d + off);
}

// Qt5 QArrayData::ref is at d+0 (atomic int). ref==1 means the buffer is uniquely owned (unshared),
// so in-place edits are safe (no copy-on-write holder to corrupt). A freshly received/parsed reply
// buffer in the queue is ref==1. We REFUSE to write a shared (ref!=1) buffer rather than corrupt it.
#define PG_QT5_ARRAYDATA_REF_OFFSET 0x0
static inline bool pg_qvec_unshared(const void* container) {
    uint8_t* d = *(uint8_t**)container;
    if (!d) return false;
    return *(int32_t*)(d + PG_QT5_ARRAYDATA_REF_OFFSET) == 1;
}

// The raw `d` handle (QArrayData*) of an mtpBuffer/QVector — needed to read capacity / write size for
// in-place resizes within existing capacity (account-freeze inject, etc.). NULL if the vector is empty.
static inline uint8_t* pg_qvec_d(const void* container) { return *(uint8_t**)container; }
// Allocated capacity in elements (Qt5 alloc is a 31-bit field).
static inline int32_t pg_qvec_capacity(const void* container) {
    uint8_t* d = *(uint8_t**)container;
    if (!d) return 0;
    return (int32_t)(*(uint32_t*)(d + PG_QT5_ARRAYDATA_ALLOC_OFFSET) & 0x7fffffffu);
}
// Publish a new element count after an in-place append (writes QArrayData::size, int32 at d+0x4).
static inline void pg_qvec_set_size(const void* container, int32_t count) {
    uint8_t* d = *(uint8_t**)container;
    if (d) *(int32_t*)(d + PG_QT5_ARRAYDATA_SIZE_OFFSET) = count;
}

// ── Session (this = RCX) ───────────────────────────────────────────────────────────────────────
#define PG_SESSION_INSTANCE_OFFSET            0x10   // Session::_instance (Instance*)
#define PG_SESSION_SHIFTED_DCID_OFFSET        0x18   // Session::_shiftedDcId (int32)
#define PG_SESSION_PRIVATE_DATA_OFFSET        0x28   // Session::_data (SessionData*)        [same as macOS]
#define PG_SESSION_KILLED_OFFSET              0x48   // Session::_killed (bool)
#define PG_SESSION_NEED_TO_RECEIVE_OFFSET     0x49   // Session::_needToReceive (bool)

// ── SessionData (_data): received std::vector<Response> {first,last,end} + locks ────────────────
#define PG_SESSION_DATA_RECEIVED_BEGIN_OFFSET 0xc0   // first  (macOS 0x120)
#define PG_SESSION_DATA_RECEIVED_END_OFFSET   0xc8   // last   (macOS 0x128)
#define PG_SESSION_DATA_RECEIVED_CAP_OFFSET   0xd0   // end-of-storage
#define PG_SESSION_DATA_RECEIVED_MUTEX_OFFSET 0xd8   // haveReceivedMutex (QReadWriteLock)
#define PG_SESSION_DATA_TOSEND_MAP_OFFSET     0x80   // toSendMap
#define PG_SESSION_DATA_TOSEND_MUTEX_OFFSET   0x98   // toSendMutex

// ── Response element (mtproto_response.h): {mtpBuffer reply; uint64 outerMsgId; int32 requestId} ─
#define PG_RESPONSE_SIZE                      0x18   // sizeof(Response)              (macOS 0x28)
#define PG_RESPONSE_REPLY_OFFSET              0x00   // reply (mtpBuffer `d` ptr) — decode w/ pg_qvec_data
#define PG_RESPONSE_OUTER_MSGID_OFFSET        0x08   // outerMsgId (uint64)
#define PG_RESPONSE_REQUEST_ID_OFFSET         0x10   // requestId  (int32)           (macOS 0x20)

// ── RequestData (request side; RDX in sendPrepared is &shared_ptr<RequestData>) ─────────────────
#define PG_REQUEST_DATA_BUFFER_OFFSET         0x00   // mtpBuffer base (`d` ptr) — decode w/ pg_qvec_data
#define PG_REQUEST_DATA_REQUEST_ID_OFFSET     0x20   // requestId (int32)            (macOS 0x30)
#define PG_SERIALIZED_REQUEST_BODY_POSITION   8      // TL body ctor word index      (unchanged: wire fmt)
