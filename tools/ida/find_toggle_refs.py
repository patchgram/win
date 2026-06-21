#!/usr/bin/env python3
# Find ALL code (any instruction form) referencing the OptionUnlimitedRecentStickers toggle object
# range [0xd3db610, 0xd3db690] — disassembling each .pdata function correctly from its start (a linear
# whole-.text sweep mis-aligns on data and misses things). Prints ref addr + enclosing function.
import struct, bisect, sys
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM
import capstone
RIP = capstone.x86.X86_REG_RIP

EXE = r"E:\patchgram\patchgramtest\Telegram.exe"
LO, HI = 0xd3db600, 0xd3db698     # toggle object range (RVAs)

pe = pefile.PE(EXE, fast_load=True); base = pe.OPTIONAL_HEADER.ImageBase; data = pe.__data__
secs = [(s.Name.rstrip(b"\x00").decode("latin1"), s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def sec(n):
    for t in secs:
        if t[0] == n: return t
def foff(rva):
    for nm, va, vs, fo, fs in secs:
        if va <= rva < va + max(vs, fs): return fo + (rva - va)
    return None
nm, tva, tvs, tfo, tfs = sec(".text")
# function bounds from .pdata
pnm, pva, pvs, pfo, pfs = sec(".pdata")
funcs = []
for i in range(pvs // 12):
    b, e, u = struct.unpack_from("<III", data, pfo + i * 12)
    if b or e: funcs.append((b, e))
funcs.sort()
md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
hits = []
for (b, e) in funcs:
    if not (tva <= b < tva + tvs): continue
    fo = foff(b)
    code = data[fo:fo + (e - b)]
    for ins in md.disasm(code, base + b):
        for op in ins.operands:
            if op.type == CS_OP_MEM and op.mem.base == RIP:
                tgt = ins.address + ins.size + op.mem.disp - base
                if LO <= tgt < HI:
                    hits.append((ins.address - base, b, tgt, ins.mnemonic, ins.op_str))
for a, fb, tgt, mn, ops in hits:
    print("ref @ %08x  fn %08x  -> %08x  %s %s" % (a, fb, tgt, mn, ops))
print("(%d refs into toggle range)" % len(hits))
