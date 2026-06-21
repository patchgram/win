import time, struct
t0=time.time()
import idapro
rc=idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
import ida_segment, idautils, ida_bytes, ida_ua, idc
BASE=0x140000000
ts=te=None
for s in idautils.Segments():
    seg=ida_segment.getseg(s)
    if ida_segment.get_segm_name(seg)==".text":
        ts,te=seg.start_ea,seg.end_ea
data=ida_bytes.get_bytes(ts,te-ts)
from collections import Counter
# Look at ALL immediates (and/test/cmp/or) against [reg+0x1a8] including combined masks
needle=struct.pack("<i",0x1a8)
imm=Counter(); samp={}
pos=0
while True:
    i=data.find(needle,pos)
    if i<0: break
    pos=i+1
    ea=ts+i
    for back in range(2,10):
        insn=ida_ua.insn_t()
        L=ida_ua.decode_insn(insn,ea-back)
        if L==0: continue
        if (ea-back)+L<ea+4: continue
        if not any(op.type==ida_ua.o_displ and op.addr==0x1a8 for op in insn.ops): continue
        mn=ida_ua.print_insn_mnem(ea-back)
        if mn in ("and","test","or","cmp","xor"):
            for op in insn.ops:
                if op.type==ida_ua.o_imm:
                    v=op.value&0xffffffff
                    # only interested in masks touching bits 3,4,5 (0x8,0x10,0x20)
                    if v & 0x38:
                        imm[(mn,v)]+=1
                        samp.setdefault((mn,v),idc.generate_disasm_line(ea-back,0))
        break
print("=== ops vs [reg+0x1a8] with imm touching bits 3/4/5 (0x38 mask) ===")
for (mn,v),c in sorted(imm.items(), key=lambda kv:(kv[0][1],)):
    print("  %-5s imm=0x%-8x count=%-3d  e.g. %s"%(mn,v,c,samp[(mn,v)]))
idapro.close_database(save=False)
print("done in %.1fs"%(time.time()-t0))
