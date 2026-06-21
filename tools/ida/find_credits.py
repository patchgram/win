import time, sys
t0=time.time()
import idapro
rc=idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
print("open rc:", rc, "in %.1fs"%(time.time()-t0), flush=True)
import ida_funcs, ida_bytes, ida_segment, idautils, ida_ua, idc, ida_nalt
import ida_hexrays
ida_hexrays.init_hexrays_plugin()
BASE=0x140000000

# Find .text bounds
text_start=text_end=None
for s in idautils.Segments():
    name=ida_segment.get_segm_name(ida_segment.getseg(s))
    seg=ida_segment.getseg(s)
    if name==".text":
        text_start, text_end = seg.start_ea, seg.end_ea
print("text:", hex(text_start), hex(text_end), flush=True)

# Strategy: find immediate references to ctor ids 0xbbb6b4a3 (stars) and 0x74aee3e0 (ton)
# via IDA's xref-to-immediate is unreliable; instead scan code for the dword immediates and
# map each to its containing function, then intersect with functions that also use 1e9 (0x3b9aca00).
import struct
def scan_imm(dword):
    res=set()
    ea=text_start
    needle=struct.pack("<I",dword)
    # use ida_bytes.find_bytes
    cur=text_start
    while cur < text_end:
        f=ida_bytes.find_bytes(needle, cur, text_end)
        if f==idc.BADADDR or f is None or f>=text_end: break
        fn=ida_funcs.get_func(f)
        if fn: res.add(fn.start_ea)
        cur=f+1
    return res

t=time.time()
stars_fns = scan_imm(0xbbb6b4a3)
ton_fns   = scan_imm(0x74aee3e0)
e9_fns    = scan_imm(0x3b9aca00)
print("scan done in %.1fs"%(time.time()-t), flush=True)
print("fns with starsAmount id:", sorted(hex(x-BASE) for x in stars_fns), flush=True)
print("fns with starsTonAmount id:", sorted(hex(x-BASE) for x in ton_fns), flush=True)
# Candidate FromTL: has BOTH ctor ids AND the 1e9 constant (ton path divides by 1e9)
both = stars_fns & ton_fns
print("fns with BOTH ctor ids:", sorted(hex(x-BASE) for x in both), flush=True)
cand = both & e9_fns
print("CANDIDATE FromTL (both ids + 1e9):", sorted(hex(x-BASE) for x in cand), flush=True)
# also ton-only + 1e9 (in case stars/ton split into separate fns)
ton_e9 = ton_fns & e9_fns
print("ton id + 1e9 fns:", sorted(hex(x-BASE) for x in ton_e9), flush=True)
idapro.close_database(save=False)
print("done", flush=True)
