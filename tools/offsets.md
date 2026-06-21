# x64 struct offsets — VERIFIED on Telegram.exe 6.9.3 (Win, Qt 5.15.19)

Status: **all §3 offsets confirmed** by disassembling `Session::tryToReceive` (RVA 0x2193a50) and
`Session::sendPrepared` (RVA 0x2192cb0) and cross-referencing tdesktop **v6.9.3** source
(`mtproto/session.{h,cpp}`, `mtproto/mtproto_response.h`, `mtproto/details/mtproto_serialized_request.h`,
`mtproto/core_types.h`). Reproduce with `re/.venv/Scripts/python re/disasm.py fn 0x<rva>`.

## ⚠️ Headline: the Windows build is **Qt 5.15.19**, not Qt6

Proven by binary strings (`qt_prfxpath=C:/Telegram/Libraries/win64/Qt-5.15.19`,
`.../Qt-5.15.19/include/QtCore/qvector.h`) **and** by struct sizes (below). The macOS Patchgram build
links **Qt6** (24-byte `QList`/`QVector` = `{Data* d; T* ptr; qsizetype size}`). The Windows build links
**Qt5** whose `QVector<T>` is a **single 8-byte pointer** `Data* d` (copy-on-write), with `size`/data
reached *through* `d`. **Every macOS `QVECTOR_*` / `QSTRING_*` offset is wrong on Windows.** This is the
single most important porting fact.

### Qt5 `QVector<T>` / `mtpBuffer` access (the one to port everywhere)
`mtpBuffer = QVector<mtpPrime>` (`mtpPrime = int32`). The container is one pointer `d`:
```
d        = *(void**)(container + 0)          // QTypedArrayData<mtpPrime>* (QArrayData header)
size     = *(int32_t*)((char*)d + 0x04)      // element count  (QArrayData::size)
offset   = *(int64_t*)((char*)d + 0x10)      // qptrdiff QArrayData::offset (header->data distance)
data     = (mtpPrime*)((char*)d + offset)    // == QVector::constData(); element [i] at data + i
```
Qt5 `QArrayData` header (64-bit): `ref@0x0 (int)`, `size@0x4 (int)`, `alloc:31|capReserved:1@0x8 (uint)`,
pad, `offset@0x10 (qptrdiff)`. Verified directly in `sendPrepared`:
`*(request->data()+4)=0` compiles to `mov qword [d + offset + 0x10], 0` and `*(request->data()+6)=0` to
`mov dword [d + offset + 0x18], 0` (data() = d+offset, words are 4 bytes → +4 words = +0x10).
**Writes are COW**: an unshared buffer is edited in place; to rewrite a *shared* buffer you must `detach`
(the original `data()` path calls a detach helper at 0x14216c1f0). A freshly received/serialized buffer is
typically refcount-1 (unshared), so in-place edits in the two hooks are safe — but check `d->ref`/use a
detach if a rewriter ever touches an aliased buffer.

## Confirmed — `Session` (this = RCX)
| field | offset | evidence |
| --- | --- | --- |
| `_instance` (Instance*) | `this+0x10` | `mov r14,[rdi+0x10]` → `QPointer<Instance>(_instance)` |
| `_shiftedDcId` (int32) | `this+0x18` | `imul [rdi+0x18]` (BareDcId main-session check, %10000) |
| `_data` (SessionData*) | **`this+0x28`** | `mov rcx,[rdi+0x28]` (same as macOS 0x28) |
| `_killed` (bool) | `this+0x48` | `cmp byte [rcx+0x48],0` at entry |
| `_needToReceive` (bool) | `this+0x49` | `mov byte [rcx+0x49],1` in the `paused()` branch |

## Confirmed — `SessionData` (`_data`, the received/queue holder)
`tryToReceive` does `base::take(_data->haveReceivedMessages())` = a `std::vector<Response>` move
(MSVC vector = `{first, last, end}` pointers): it reads three pointers and zeroes the source.
| field | offset | evidence |
| --- | --- | --- |
| received vector `first` (begin) | **`_data+0xc0`** | `mov rbp,[rcx+0xc0]; mov [rcx+0xc0],0` |
| received vector `last` (end)    | **`_data+0xc8`** | `mov rsi,[rcx+0xc8]; mov [rcx+0xc8],0` |
| received vector `end` (cap)     | `_data+0xd0`     | `mov rax,[rcx+0xd0]; mov [rcx+0xd0],0` |
| `haveReceivedMutex` (QReadWriteLock) | `_data+0xd8` | `add rbx,0xd8` (lock taken around the take) |
| `toSendMap`   | `_data+0x80` | `sub rcx,-0x80` (emplace target in sendPrepared) |
| `toSendMutex` | `_data+0x98` | `add rbx,0x98` (QWriteLocker around the emplace) |

macOS used received begin/end @ `0x120/0x128`; on Windows it is **`0xc0/0xc8`**. Iterate
`for (resp = first; resp != last; resp += RESPONSE_SIZE)` — these are real `Response*`, not a `{begin,end}`
index pair. Our hook runs **before** the original (which takes + drains the queue), so the vector is full.

## Confirmed — `Response` (`mtproto_response.h`), the received-queue element
```cpp
struct Response { mtpBuffer reply; mtpMsgId outerMsgId; mtpRequestId requestId; };
```
Qt5 `mtpBuffer` = 8 bytes → `sizeof(Response) = 8 + 8 + 4 → align8 → 0x18`.
| field | offset | evidence |
| --- | --- | --- |
| `reply` (QVector `d`)  | `resp+0x00` | base subobject; decode via the Qt5 access above |
| `outerMsgId` (uint64)  | `resp+0x08` | layout |
| `requestId` (int32)    | **`resp+0x10`** | `cmp dword [rbp+0x10],0` (`if (message.requestId)`) |
| **`RESPONSE_SIZE`**    | **`0x18`**  | loop `add rbp,0x18; cmp rbp,last` |

macOS: requestId@0x20, stride 0x28. Windows: **requestId@0x10, stride 0x18** (Qt5 buffer is 8 not 24).
The response's TL ctor = `reply` buffer word[0] (`data[0]`); the whole reply is the decoded RPC result.

## Confirmed — `SerializedRequest` / `RequestData` (request side, RDX in sendPrepared)
```cpp
class SerializedRequest { std::shared_ptr<RequestData> _data; };   // 16 bytes {ptr, ctrl}
class RequestData : public mtpBuffer {        // mtpBuffer base @ +0 (8 bytes, Qt5)
    SerializedRequest after;                  // +0x08  (shared_ptr, 16 bytes)
    crl::time lastSentTime;                   // +0x18  (int64)
    mtpRequestId requestId;                   // +0x20  (int32)
    bool needsLayer, forceSendInContainer;    // +0x24, +0x25
};
```
`request` (RDX) is `&SerializedRequest` = `&shared_ptr`: `*(req+0)` = `RequestData*`, `*(req+8)` = control
block (the `lock inc [ctrl+8]` is the shared_ptr refcount bump).
| field | offset | evidence |
| --- | --- | --- |
| `RequestData*` (shared_ptr ptr)     | `*(req+0x0)` | `mov rdx,[r15]` |
| request buffer `d` (mtpBuffer base) | `RequestData+0x0` | base class; decode via Qt5 access |
| **`requestId`** (int32)             | **`RequestData+0x20`** | `mov eax,[rdx+0x20]` (emplace key) |
| body TL ctor word index             | **8** (`kMessageBodyPosition`) | salt2+session2+msgid2+seqno1+len1 |

macOS used requestId @ request_data+0x30; Windows = **0x20** (8-byte Qt5 buffer base shifts everything).
`SERIALIZED_REQUEST_BODY_POSITION = 8` is wire-format and unchanged. `request->data()` = the Qt5 buffer
data pointer; the outgoing message words are salt/sessionId/msgId/seqNo/len then the TL body at word 8.

## Net effect on the macOS → Windows port
- `SESSION_PRIVATE_DATA_OFFSET` 0x28 → **0x28** (unchanged).
- received begin/end 0x120/0x128 → **0xc0/0xc8**; `RESPONSE_SIZE` 0x28 → **0x18**;
  `RESPONSE_REQUEST_ID_OFFSET` 0x20 → **0x10**.
- `REQUEST_DATA_REQUEST_ID_OFFSET` 0x30 → **0x20**.
- `SERIALIZED_REQUEST_BODY_POSITION` 8 → **8** (unchanged).
- **QVECTOR/QSTRING**: macOS direct `{d,ptr,size}` @ 0x0/0x8/0x10 → **Qt5 single `d`**; size@`d+4`,
  data@`d + *(d+0x10)`. The TL engine must read/write every `mtpBuffer`/`QString` through `d`.
- QString (Qt5) is the same `QArrayData`-backed shape: `d = *(qstr+0)`, `size = *(int*)(d+4)`,
  `utf16 = (char16_t*)(d + *(qptrdiff*)(d+0x10))`. (Verify when porting the self-phone/username patches.)
