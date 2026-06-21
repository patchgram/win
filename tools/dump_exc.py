"""Minimal minidump exception extractor: prints exception code, faulting instruction RVA
(relative to Telegram.exe base) and the dereferenced bad address. No deps."""
import struct, sys

def u32(b,o): return struct.unpack_from('<I',b,o)[0]
def u64(b,o): return struct.unpack_from('<Q',b,o)[0]

path = sys.argv[1]
data = open(path,'rb').read()
assert data[:4] == b'MDMP', 'not a minidump'
nstreams = u32(data, 8)
dirrva   = u32(data, 12)

exc = None
modbase = None
modname_target = 'telegram.exe'
modules = []
for i in range(nstreams):
    off = dirrva + i*12
    stype = u32(data, off); dsize = u32(data, off+4); rva = u32(data, off+8)
    if stype == 6:   # ExceptionStream
        # MINIDUMP_EXCEPTION_STREAM: ThreadId u32, align u32, then MINIDUMP_EXCEPTION
        e = rva + 8
        code   = u32(data, e+0)
        flags  = u32(data, e+4)
        addr   = u64(data, e+16)            # ExceptionAddress
        nparam = u32(data, e+24)
        info0  = u64(data, e+32)            # rw flag for AV
        info1  = u64(data, e+40)            # faulting/dereferenced address for AV
        exc = (code, flags, addr, nparam, info0, info1)
    if stype == 4:   # ModuleListStream
        n = u32(data, rva)
        p = rva + 4
        for m in range(n):
            base = u64(data, p+0); size = u32(data, p+8); nameRva = u32(data, p+0x20)
            try:
                ln = u32(data, nameRva)
                nm = data[nameRva+4:nameRva+4+ln].decode('utf-16-le', 'replace')
            except Exception:
                nm = '?'
            modules.append((base, size, nm))
            p += 108  # sizeof(MINIDUMP_MODULE)

# find Telegram.exe base
for base, size, nm in modules:
    if nm.lower().endswith(modname_target):
        modbase = (base, size, nm); break

print("modules:", len(modules))
if modbase:
    print(f"Telegram.exe base=0x{modbase[0]:x} size=0x{modbase[1]:x}")
if exc:
    code, flags, addr, nparam, info0, info1 = exc
    print(f"exception code = 0x{code:08x}")
    print(f"exception (faulting instr) address = 0x{addr:x}")
    if modbase and modbase[0] <= addr < modbase[0]+modbase[1]:
        print(f"  -> Telegram.exe RVA = 0x{addr - modbase[0]:x}")
    else:
        for base,size,nm in modules:
            if base <= addr < base+size:
                print("  -> in", (nm.split('\\')[-1]).encode('ascii','replace').decode(), f"+0x{addr-base:x}"); break
    if code == 0xC0000005:
        print(f"access-violation: op={'write' if info0==1 else 'read' if info0==0 else info0} "
              f"dereferenced bad address = 0x{info1:x}")
else:
    print("no exception stream")
