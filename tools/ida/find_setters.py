import time, sys, struct, bisect
t0=time.time()
import idapro
rc=idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
print("open rc:", rc, "in %.1fs"%(time.time()-t0), flush=True)
import ida_funcs, ida_bytes, ida_segment, idautils, ida_ua, idc
BASE=0x140000000

text_start=text_end=None
for s in idautils.Segments():
    seg=ida_segment.getseg(s)
    if ida_segment.get_segm_name(seg)==".text":
        text_start, text_end = seg.start_ea, seg.end_ea
print("text:", hex(text_start-BASE), hex(text_end-BASE), flush=True)

# build func starts
starts=[]
f=ida_funcs.get_next_func(text_start-1)
while f and f.start_ea < text_end:
    starts.append(f.start_ea); f=ida_funcs.get_next_func(f.start_ea)
starts.sort()
def func_of(ea):
    i=bisect.bisect_right(starts, ea)-1
    return starts[i] if i>=0 else None

# Find instructions whose immediate operand == target value (mov reg,imm64).
targets={ 'PersonalChannel(1<<35)':1<<35, 'StarsRating(1<<39)':1<<39 }
results={}
for name,val in targets.items():
    found={}
    # scan instructions across all funcs
    for st in starts:
        fn=ida_funcs.get_func(st)
        if not fn: continue
        ea=fn.start_ea
        while ea < fn.end_ea:
            insn=ida_ua.insn_t()
            L=ida_ua.decode_insn(insn, ea)
            if L==0: ea+=1; continue
            for op in insn.ops:
                if op.type==ida_ua.o_imm and (op.value & 0xFFFFFFFFFFFFFFFF)==val:
                    found.setdefault(st,[]).append(ea-BASE)
            ea+=L
    results[name]=found
    print("\n=== %s: %d funcs contain imm ==="%(name,len(found)), flush=True)
    for st,lst in sorted(found.items()):
        print("  FN %08x  at %s"%(st-BASE, [hex(x) for x in lst]), flush=True)

idapro.close_database(save=False)
print("done in %.1fs"%(time.time()-t0), flush=True)
