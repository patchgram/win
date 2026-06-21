#!/usr/bin/env python3
"""Patchgram-Windows RE helper for Telegram.exe (PE32+ x64, static Qt).

Subcommands:
  enum                       parse .pdata -> count + list of function [begin,end) RVAs
  func <hexRVA>              find the .pdata function containing an RVA (begin/end)
  strings <substr> [n]       find ASCII/UTF-16 strings in .rdata/.text containing substr -> RVA
  xref <hexRVA> [max]        find rip-relative `lea reg,[rip+disp]` in .text pointing at RVA,
                             and the enclosing function (via .pdata)
  bytes <hexRVA> <n>         hex-dump n bytes at an RVA (from file) — for signature extraction
  sig <hexRVA> [n]           emit a starter AOB signature (first n entry bytes, no wildcards yet)

RVAs are relative to ImageBase (0x140000000). Pass them WITHOUT the base, e.g. `func 0x12abc`.
"""
import sys, struct, bisect
import pefile

EXE = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "Telegram", "Telegram.exe")

def load():
    pe = pefile.PE(EXE, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    data = pe.__data__  # whole file bytes
    secs = []
    for s in pe.sections:
        nm = s.Name.rstrip(b"\x00").decode("latin1")
        secs.append((nm, s.VirtualAddress, s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData))
    return pe, base, data, secs

def sec(secs, name):
    for nm, va, vsz, foff, fsz in secs:
        if nm == name:
            return va, vsz, foff, fsz
    return None

def rva_to_foff(secs, rva):
    for nm, va, vsz, foff, fsz in secs:
        if va <= rva < va + max(vsz, fsz):
            return foff + (rva - va)
    return None

def read_pdata(data, secs):
    va, vsz, foff, fsz = sec(secs, ".pdata")
    funcs = []  # (begin_rva, end_rva)
    n = vsz // 12
    for i in range(n):
        b, e, u = struct.unpack_from("<III", data, foff + i * 12)
        if b == 0 and e == 0:
            continue
        funcs.append((b, e))
    funcs.sort()
    return funcs

def func_containing(funcs, rva):
    begins = [f[0] for f in funcs]
    i = bisect.bisect_right(begins, rva) - 1
    if 0 <= i < len(funcs) and funcs[i][0] <= rva < funcs[i][1]:
        return funcs[i]
    return None

def cmd_enum():
    pe, base, data, secs = load()
    funcs = read_pdata(data, secs)
    print(f"functions in .pdata: {len(funcs)}")
    print(f"first: {hex(funcs[0][0])}  last: {hex(funcs[-1][0])}")

def cmd_func(arg):
    pe, base, data, secs = load()
    funcs = read_pdata(data, secs)
    rva = int(arg, 16)
    f = func_containing(funcs, rva)
    print(f"RVA {hex(rva)} (VA {hex(base+rva)}) -> "
          + (f"func [begin={hex(f[0])} end={hex(f[1])}] VA {hex(base+f[0])} size={f[1]-f[0]}" if f else "NOT in .pdata (leaf?)"))

def cmd_strings(substr, limit=40):
    pe, base, data, secs = load()
    needle = substr.encode("latin1")
    hits = []
    for name in (".rdata", ".rodata", ".text"):
        s = sec(secs, name)
        if not s: continue
        va, vsz, foff, fsz = s
        blob = data[foff:foff+fsz]
        # ASCII
        start = 0
        while True:
            i = blob.find(needle, start)
            if i < 0: break
            # extend to a printable run
            a = i
            while a > 0 and 0x20 <= blob[a-1] < 0x7f: a -= 1
            b = i
            while b < len(blob) and 0x20 <= blob[b] < 0x7f: b += 1
            hits.append((name, va + a, "ascii", blob[a:b].decode("latin1", "replace")[:80]))
            start = b
        # UTF-16LE
        nl = "\x00".join(substr) .encode("latin1")  # naive utf16 needle
        u = substr.encode("utf-16-le")
        start = 0
        while True:
            i = blob.find(u, start)
            if i < 0: break
            hits.append((name, va + i, "utf16", substr[:80]))
            start = i + 2
    for name, rva, kind, txt in hits[:limit]:
        print(f"{name:7} RVA={hex(rva)} VA={hex(base+rva)} {kind}: {txt!r}")
    print(f"({len(hits)} hits)")

def cmd_xref(arg, maxhits=40):
    pe, base, data, secs = load()
    funcs = read_pdata(data, secs)
    target_rva = int(arg, 16)
    tva, tvsz, tfoff, tfsz = sec(secs, ".text")
    blob = data[tfoff:tfoff+tfsz]
    found = 0
    i = 0
    L = len(blob)
    while i < L - 7 and found < maxhits:
        c = blob[i]
        if (c == 0x48 or c == 0x4C or c == 0x49 or c == 0x4D) and blob[i+1] == 0x8D and (blob[i+2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", blob, i+3)[0]
            instr_rva = tva + i
            tgt = instr_rva + 7 + disp
            if tgt == target_rva:
                f = func_containing(funcs, instr_rva)
                fstr = f"func[begin={hex(f[0])} end={hex(f[1])}]" if f else "no-pdata-fn"
                print(f"xref @ RVA={hex(instr_rva)} VA={hex(base+instr_rva)} -> {fstr}")
                found += 1
            i += 1
        else:
            i += 1
    print(f"({found} rip-lea xrefs)")

def cmd_bytes(arg, n):
    pe, base, data, secs = load()
    rva = int(arg, 16); n = int(n)
    foff = rva_to_foff(secs, rva)
    if foff is None: print("RVA not mapped"); return
    b = data[foff:foff+n]
    print(" ".join(f"{x:02x}" for x in b))

def cmd_sig(arg, n=16):
    pe, base, data, secs = load()
    rva = int(arg, 16); n = int(n)
    foff = rva_to_foff(secs, rva)
    if foff is None: print("RVA not mapped"); return
    b = data[foff:foff+n]
    print("pattern:", " ".join(f"{x:02x}" for x in b))
    print("mask   :", " ".join("ff" for _ in b), "  (set 00 over rip-disp/call-rel bytes after disasm)")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    cmd = sys.argv[1]; a = sys.argv[2:]
    {"enum": lambda: cmd_enum(),
     "func": lambda: cmd_func(a[0]),
     "strings": lambda: cmd_strings(a[0], int(a[1]) if len(a) > 1 else 40),
     "xref": lambda: cmd_xref(a[0], int(a[1]) if len(a) > 1 else 40),
     "bytes": lambda: cmd_bytes(a[0], a[1]),
     "sig": lambda: cmd_sig(a[0], int(a[1]) if len(a) > 1 else 16),
     }.get(cmd, lambda: print("unknown cmd; see --help"))()
