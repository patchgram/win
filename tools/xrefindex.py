#!/usr/bin/env python3
# Lightweight x64 call-graph + data-xref index for the stripped Telegram.exe.
#
# Why: IDA's full auto-analysis (type inference, FLIRT, propagation across 215k fns) takes hours and we
# don't need 99% of it. To LOCATE an anchor-less function we only need two relations:
#   (1) who calls whom              (reverse call-graph: callees(F), callers(F))
#   (2) who references address X    (rip-relative data refs: lea/mov/cmp [rip+disp] -> X)
# A single capstone pass over every .pdata function (function bounds come free from .pdata) builds both in
# a few minutes. Then anchor->function tracing is instant: find the fn that refs a string, walk callers/
# callees, decompile only the handful of candidates with idalib.
#
# Build once:   python xrefindex.py build           -> writes xrefindex.pkl next to the exe-tooling
# Query refs:   python xrefindex.py refs 0xRVA       -> every instruction (call/lea/mov/cmp) targeting RVA
# Callers:      python xrefindex.py callers 0xRVA    -> functions that CALL the function containing RVA
# Callees:      python xrefindex.py callees 0xRVA    -> call targets inside the function containing RVA
import sys, struct, bisect, pickle, os
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_IMM
import capstone
RIP = capstone.x86.X86_REG_RIP

EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "Telegram", "Telegram.exe")
IDX = os.path.join(os.path.dirname(__file__), "xrefindex.pkl")

def load_pe():
    pe = pefile.PE(EXE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__
    secs = {}
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1")
        secs[nm] = (s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData)
    return pe, base, data, secs

def foff(secs, rva):
    for nm,(va,vs,fo,fs) in secs.items():
        if va <= rva < va + max(vs,fs): return fo + (rva-va)
    return None

def func_bounds(data, secs):
    pva,pvs,pfo,pfs = secs[".pdata"]
    fns = []
    for i in range(pvs//12):
        b,e,u = struct.unpack_from("<III", data, pfo + i*12)
        if b or e: fns.append((b,e))
    fns.sort()
    return fns

def build():
    pe, base, data, secs = load_pe()
    tva,tvs,tfo,tfs = secs[".text"]
    fns = func_bounds(data, secs)
    starts = [b for b,e in fns]
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    # data_refs[target_rva] = list of (insn_rva, func_start, mnemonic)
    # call_to[callee_start] = set(caller_start) ; call_from[caller_start] = set(callee_start)
    data_refs = {}
    call_to = {}; call_from = {}
    n=0
    for (b,e) in fns:
        if not (tva <= b < tva+tvs): continue
        fo = foff(secs, b)
        if fo is None: continue
        code = data[fo:fo+(e-b)]
        for ins in md.disasm(code, base+b):
            # direct calls (E8 rel32) -> resolve target, map to containing function
            if ins.mnemonic == "call" and len(ins.operands)==1 and ins.operands[0].type==CS_OP_IMM:
                tgt = ins.operands[0].imm - base
                # map tgt to the function that starts <= tgt
                j = bisect.bisect_right(starts, tgt)-1
                callee = starts[j] if j>=0 else tgt
                call_from.setdefault(b,set()).add(callee)
                call_to.setdefault(callee,set()).add(b)
            # rip-relative memory refs
            for op in ins.operands:
                if op.type==CS_OP_MEM and op.mem.base==RIP:
                    t = ins.address + ins.size + op.mem.disp - base
                    data_refs.setdefault(t, []).append((ins.address-base, b, ins.mnemonic))
        n+=1
    idx = {"base":base, "starts":starts, "data_refs":data_refs,
           "call_to":{k:sorted(v) for k,v in call_to.items()},
           "call_from":{k:sorted(v) for k,v in call_from.items()}}
    with open(IDX,"wb") as f: pickle.dump(idx, f, protocol=4)
    print("built: %d funcs, %d ref-targets, %d call edges -> %s (%.1f MB)" %
          (n, len(data_refs), sum(len(v) for v in call_to.values()), IDX, os.path.getsize(IDX)/1e6))

def load_idx():
    with open(IDX,"rb") as f: return pickle.load(f)

def func_of(starts, rva):
    j = bisect.bisect_right(starts, rva)-1
    return starts[j] if j>=0 else None

def cmd_refs(rva):
    idx = load_idx()
    hits = idx["data_refs"].get(rva, [])
    print("refs to %#x: %d" % (rva, len(hits)))
    for ia, fb, mn in hits[:60]:
        print("  %08x  in fn %08x  %s" % (ia, fb, mn))

def cmd_callers(rva):
    idx = load_idx()
    f = func_of(idx["starts"], rva)
    cs = idx["call_to"].get(f, [])
    print("function %#x has %d callers:" % (f, len(cs)))
    for c in cs[:80]: print("  %08x" % c)

def cmd_callees(rva):
    idx = load_idx()
    f = func_of(idx["starts"], rva)
    cs = idx["call_from"].get(f, [])
    print("function %#x calls %d targets:" % (f, len(cs)))
    for c in cs[:120]: print("  %08x" % c)

if __name__=="__main__":
    cmd = sys.argv[1] if len(sys.argv)>1 else "build"
    if cmd=="build": build()
    elif cmd=="refs": cmd_refs(int(sys.argv[2],16))
    elif cmd=="callers": cmd_callers(int(sys.argv[2],16))
    elif cmd=="callees": cmd_callees(int(sys.argv[2],16))
    else: print("usage: build | refs RVA | callers RVA | callees RVA")
