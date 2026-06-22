import time, sys, struct, bisect, os
t0=time.time()
import idapro
EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "..", "Telegram", "Telegram.exe")
rc=idapro.open_database(EXE, run_auto_analysis=False)
print("open rc:", rc, "in %.1fs"%(time.time()-t0), flush=True)
import ida_funcs, ida_bytes, ida_segment, idautils, ida_ua, idc, ida_nalt
BASE=0x140000000

text_start=text_end=None
for s in idautils.Segments():
    seg=ida_segment.getseg(s)
    name=ida_segment.get_segm_name(seg)
    if name==".text":
        text_start, text_end = seg.start_ea, seg.end_ea
print("text:", hex(text_start-BASE), hex(text_end-BASE), flush=True)

data=ida_bytes.get_bytes(text_start, text_end-text_start)
print("got %d bytes of .text"%len(data), flush=True)

needle=struct.pack("<i",0x1a8)

# Build function start list (from .pdata-derived funcs IDA already knows)
starts=[]
f=ida_funcs.get_next_func(text_start-1)
while f and f.start_ea < text_end:
    starts.append(f.start_ea)
    f=ida_funcs.get_next_func(f.start_ea)
print("funcs in text:", len(starts), flush=True)
starts.sort()
def func_of(ea):
    i=bisect.bisect_right(starts, ea)-1
    return starts[i] if i>=0 else None

WRITE_MNEM=("mov","or","and","xor","btr","bts","add","sub","bt")
hits={}
pos=0; count=0
while True:
    i=data.find(needle, pos)
    if i<0: break
    pos=i+1
    ea=text_start+i
    # Use IDA's decoder: decode instruction whose displacement field ends at ea+4.
    # Try decoding starting a few bytes back.
    done=False
    for back in range(2,9):
        insn=ida_ua.insn_t()
        L=ida_ua.decode_insn(insn, ea-back)
        if L==0: continue
        if (ea-back)+L < ea+4: continue
        # check operands for disp 0x1a8 memory
        ok=False
        for op in insn.ops:
            if op.type in (ida_ua.o_displ, ida_ua.o_phrase) and op.addr==0x1a8:
                ok=True
        if not ok:
            # also check raw: it may be o_mem etc; accept if the disp bytes are at right place
            continue
        mn=ida_ua.print_insn_mnem(ea-back)
        fs=func_of(ea)
        dis=idc.generate_disasm_line(ea-back, 0)
        iswrite = mn in WRITE_MNEM and ("ptr [" in dis.lower()) and (dis.lower().find("ptr [") < dis.lower().find("1a8")) if "1a8" in dis.lower() else False
        # simpler: is first operand the memory write?
        iswrite=False
        if insn.ops[0].type in (ida_ua.o_displ,) and insn.ops[0].addr==0x1a8 and mn in WRITE_MNEM:
            iswrite=True
        hits.setdefault(fs,[]).append(((ea-back)-BASE, mn, dis, iswrite))
        count+=1
        done=True
        break

print("total 0x1a8 accesses decoded:", count, "in", len(hits), "funcs", flush=True)
writers=[]
for fs, lst in hits.items():
    if any(w for *_,w in lst):
        writers.append((fs,lst))
writers.sort()
print("=== functions that WRITE [reg+0x1a8] : %d ==="%len(writers), flush=True)
for fs,lst in writers:
    fn=ida_funcs.get_func(fs)
    sz=(fn.end_ea-fn.start_ea) if fn else 0
    print("FN %08x  size=%d  (%d 0x1a8-accesses)"%(fs-BASE, sz, len(lst)), flush=True)
    for rva,mn,dis,w in lst:
        print("    %08x  %s  %s"%(rva, "<W>" if w else "  ", dis), flush=True)
idapro.close_database(save=False)
print("done in %.1fs"%(time.time()-t0), flush=True)
