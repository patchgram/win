#!/usr/bin/env python3
# Fast capstone scan to VERIFY predicted Qt5 UserData offsets by finding the
# setPersonalChannel store-pair ([u+0x240] int64 + [u+0x248] int32) and the
# setStarsRating 16-byte block accesses ([u+0x230..0x23c]).
import sys, struct, bisect, os
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG, CS_OP_IMM

EXE = r"E:\patchgram\patchgramtest\Telegram.exe"
pe = pefile.PE(EXE, fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.__data__
secs = {}
for s in pe.sections:
    nm = s.Name.rstrip(b"\x00").decode("latin1")
    secs[nm] = (s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
tva,tvs,tfo,tfs = secs[".text"]

# function bounds from .pdata
pva,pvs,pfo,pfs = secs[".pdata"]
fns=[]
for i in range(pvs//12):
    b,e,u = struct.unpack_from("<III", data, pfo+i*12)
    if b or e: fns.append((b,e))
fns.sort()
starts=[b for b,e in fns]
def func_of(rva):
    j=bisect.bisect_right(starts,rva)-1
    if 0<=j<len(fns) and fns[j][0]<=rva<fns[j][1]: return fns[j]
    return None

md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True

# Collect, per function, the set of memory displacements accessed and whether write/read,
# but only for a candidate displacement set. We scan all .text once.
TARGETS = set([0x230,0x234,0x238,0x23c,0x240,0x244,0x248,
               # also collect the alternate models in case alignment differs:
               0x228,0x22c,0x238,0x250,0x258,
               0x2b0,0x2c0,0x2c8,0x2d0,0x2d8])  # qt6 values (should NOT appear on win)

text = data[tfo:tfo+tfs]
# scan function by function for speed/attribution
per_fn={}  # fn_start -> list of (rva, mnem, disp, is_write, op_str)
code_all = md
for (b,e) in fns:
    if not (tva<=b<tva+tvs): continue
    fo = tfo + (b - tva)
    chunk = data[fo:fo+(e-b)]
    for ins in md.disasm(chunk, base+b):
        for idx,op in enumerate(ins.operands):
            if op.type==CS_OP_MEM and op.mem.base!=0 and op.mem.index==0:
                disp=op.mem.disp
                if disp in TARGETS:
                    is_write = (idx==0 and ins.mnemonic in
                                ("mov","movups","movaps","movq","movdqu","movdqa","and","or","xor","add","sub"))
                    per_fn.setdefault(b,[]).append((ins.address-base, ins.mnemonic, disp, is_write, ins.op_str))

# Heuristic: find functions touching BOTH 0x240 and 0x248 (personalChannel) ;
# and functions touching the 0x230 block.
print("=== functions touching 0x240 AND 0x248 (setPersonalChannel candidates) ===")
for fs,lst in sorted(per_fn.items()):
    disps=set(d for _,_,d,_,_ in lst)
    if 0x240 in disps and 0x248 in disps:
        f=func_of(fs)
        print("FN %08x size=%d"%(fs, (f[1]-f[0]) if f else 0))
        for rva,mn,d,w,ops in lst:
            print("   %08x %-7s %s  [%s]"%(rva,mn,ops,"W" if w else "r"))

print("\n=== functions touching 0x230 (and 0x234/0x238/0x23c) (starsRating candidates) ===")
for fs,lst in sorted(per_fn.items()):
    disps=set(d for _,_,d,_,_ in lst)
    if 0x230 in disps:
        f=func_of(fs)
        print("FN %08x size=%d  disps=%s"%(fs,(f[1]-f[0]) if f else 0, sorted(hex(x) for x in disps if 0x230<=x<=0x24c)))
        for rva,mn,d,w,ops in lst:
            if 0x230<=d<=0x24c:
                print("   %08x %-7s %s  [%s]"%(rva,mn,ops,"W" if w else "r"))

print("\n=== any function touching qt6 0x2c0/0x2d0/0x2d8 (should be empty/unrelated on Win) ===")
for fs,lst in sorted(per_fn.items()):
    disps=set(d for _,_,d,_,_ in lst)
    if disps & {0x2c0,0x2d0,0x2d8}:
        print("FN %08x disps=%s"%(fs, sorted(hex(x) for x in (disps & {0x2c0,0x2d0,0x2d8}))))
