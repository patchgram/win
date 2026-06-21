#!/usr/bin/env python3
"""Capstone-backed disassembly + field-access analysis for Telegram.exe (x64).

Used to VERIFY the §3 struct offsets the macOS engine assumes, by reading the
actual memory accesses tryToReceive / sendPrepared emit on the Windows build.

Subcommands:
  dis <hexRVA> [n]        linear disassembly of n bytes (default = whole .pdata fn) at an RVA
  fn  <hexRVA>            disassemble the entire enclosing .pdata function
  mem <hexRVA>            disassemble fn, list every [reg+disp] memory operand grouped by base reg

RVAs are module-relative (ImageBase 0x140000000); pass WITHOUT the base.
"""
import sys, os, struct, bisect
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, CS_OP_REG, CS_OP_IMM

EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "Telegram", "Telegram.exe")
IMAGE_BASE_FALLBACK = 0x140000000

def load():
    pe = pefile.PE(EXE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__
    secs = []
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1")
        secs.append((nm, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData))
    return base, data, secs

def sec(secs, name):
    for t in secs:
        if t[0] == name:
            return t
    return None

def rva_to_foff(secs, rva):
    for nm, va, vsz, foff, fsz in secs:
        if va <= rva < va + max(vsz, fsz):
            return foff + (rva - va)
    return None

def read_pdata(data, secs):
    nm, va, vsz, foff, fsz = sec(secs, ".pdata")
    funcs = []
    for i in range(vsz // 12):
        b, e, u = struct.unpack_from("<III", data, foff + i * 12)
        if b == 0 and e == 0:
            continue
        funcs.append((b, e))
    funcs.sort()
    return funcs

def func_of(funcs, rva):
    begins = [f[0] for f in funcs]
    i = bisect.bisect_right(begins, rva) - 1
    if 0 <= i < len(funcs) and funcs[i][0] <= rva < funcs[i][1]:
        return funcs[i]
    return None

def get_code(rva, n):
    base, data, secs = load()
    foff = rva_to_foff(secs, rva)
    if foff is None:
        if n is None:
            funcs = read_pdata(data, secs)
            f = func_of(funcs, rva)
        raise SystemExit("RVA not mapped")
    if n is None:
        funcs = read_pdata(data, secs)
        f = func_of(funcs, rva)
        if not f:
            raise SystemExit("no enclosing .pdata fn; pass an explicit length")
        rva = f[0]
        n = f[1] - f[0]
        foff = rva_to_foff(secs, rva)
    return base, data[foff:foff+n], rva, n

def md():
    m = Cs(CS_ARCH_X86, CS_MODE_64)
    m.detail = True
    return m

def cmd_dis(arg, n=None):
    base, code, rva, n = get_code(int(arg, 16), int(n) if n else None)
    for ins in md().disasm(code, base + rva):
        print(f"{ins.address-base:#08x}  {ins.mnemonic:<7} {ins.op_str}")

def cmd_fn(arg):
    cmd_dis(arg, None)

def cmd_mem(arg):
    base, code, rva, n = get_code(int(arg, 16), None)
    groups = {}      # base_reg -> set of (disp, mnemonic, addr_rva, op_str)
    m = md()
    for ins in m.disasm(code, base + rva):
        for op in ins.operands:
            if op.type == CS_OP_MEM:
                breg = ins.reg_name(op.mem.base) if op.mem.base else "-"
                ireg = ins.reg_name(op.mem.index) if op.mem.index else None
                disp = op.mem.disp
                key = breg + (f"+{ireg}*{op.mem.scale}" if ireg else "")
                groups.setdefault(key, []).append((disp, ins.mnemonic, ins.address-base, ins.op_str))
    for key in sorted(groups):
        print(f"\n== base {key} ==")
        seen = set()
        for disp, mn, a, ops in sorted(groups[key], key=lambda t: (t[0], t[2])):
            tag = (key, disp)
            star = " " if tag in seen else "*"
            seen.add(tag)
            print(f" {star} +{disp:#06x}  @{a:#08x}  {mn:<6} {ops}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1]; a = sys.argv[2:]
    {"dis": lambda: cmd_dis(a[0], a[1] if len(a) > 1 else None),
     "fn":  lambda: cmd_fn(a[0]),
     "mem": lambda: cmd_mem(a[0]),
     }.get(cmd, lambda: print("unknown cmd"))()
