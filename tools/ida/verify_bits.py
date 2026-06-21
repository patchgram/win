import time, struct
t0=time.time()
import idapro
rc=idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
print("open rc:", rc, flush=True)
import ida_segment, idautils, ida_bytes, ida_funcs, ida_ua, idc
BASE=0x140000000
text_start=text_end=None
for s in idautils.Segments():
    seg=ida_segment.getseg(s)
    if ida_segment.get_segm_name(seg)==".text":
        text_start, text_end=seg.start_ea, seg.end_ea
data=ida_bytes.get_bytes(text_start, text_end-text_start)

def count(b):
    c=0; pos=0
    while True:
        i=data.find(b,pos)
        if i<0: break
        c+=1; pos=i+1
    return c

# Extend channel AOB to unique: add the next bytes after 'mov r13,rcx' (45 33 e4 45 8b fc)
chan="48 89 4c 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 58 48 8b da 4c 8b e9 45 33 e4 45 8b fc"
b=bytes(int(x,16) for x in chan.split())
print("ChannelData::setFlags AOB (36B) count:", count(b), flush=True)

# Cross-validate bit positions: scan for 'test dword [reg+0x1a8], imm' / 'and eax,imm after mov from +0x1a8'
# Find every test/and with disp 0x1a8 and report the immediate (these are isVerified/isScam/isFake etc reads).
needle=struct.pack("<i",0x1a8)
from collections import Counter
imm_counter=Counter()
pos=0
samples={}
while True:
    i=data.find(needle,pos)
    if i<0: break
    pos=i+1
    ea=text_start+i
    for back in range(2,10):
        insn=ida_ua.insn_t()
        L=ida_ua.decode_insn(insn, ea-back)
        if L==0: continue
        if (ea-back)+L < ea+4: continue
        # must have a mem op with disp 0x1a8
        memok=any(op.type in (ida_ua.o_displ,) and op.addr==0x1a8 for op in insn.ops)
        if not memok: continue
        mn=ida_ua.print_insn_mnem(ea-back)
        if mn in ("test","and"):
            # find imm operand
            for op in insn.ops:
                if op.type==ida_ua.o_imm:
                    v=op.value & 0xffffffffffffffff
                    imm_counter[v]+=1
                    if v not in samples:
                        samples[v]=idc.generate_disasm_line(ea-back,0)
        break

print("\n=== immediates used in test/and against [reg+0x1a8] (bit -> count) ===", flush=True)
flagnames={0x1:"Contact",0x2:"MutualContact",0x4:"Deleted",0x8:"Verified",0x10:"Scam",0x20:"Fake",
           0x40:"BotInlineGeo",0x80:"Blocked",0x400:"Support",0x2000:"Self",0x4000:"Premium",
           0x8000000:"Forum",0x40000:"StoriesHidden"}
for v,c in sorted(imm_counter.items()):
    nm=flagnames.get(v,"")
    print("  imm=0x%-10x  count=%-4d  %-14s  e.g. %s"%(v,c,nm,samples[v]), flush=True)

idapro.close_database(save=False)
print("\ndone in %.1fs"%(time.time()-t0), flush=True)
