import re, sys, os

path = os.environ.get("PATCHGRAM_TL_SCHEMA") or os.path.join(os.path.dirname(__file__), "..", "dll", "tl_schema.c.inc")
data = open(path, encoding="utf-8", errors="replace").read()

m = re.search(r'g_tl_strpool\[\]\s*=\s*(.*?);', data, re.S)
spool_src = m.group(1)
strs = re.findall(r'"((?:[^"\\]|\\.)*)"', spool_src)

def unescape(s):
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        if c == '\\' and i + 1 < len(s):
            n = s[i+1]
            mp = {'0': '\x00', 'n': '\n', 't': '\t', '"': '"', '\\': '\\'}
            out.append(mp.get(n, n))
            i += 2
        else:
            out.append(c)
            i += 1
    return ''.join(out)

buf = bytearray()
for s in strs:
    buf += unescape(s).encode('latin1')
    # NOTE: each literal already ends with an explicit \0; do NOT add another.

def name_at(off):
    end = buf.find(0, off)
    return buf[off:end].decode('latin1')

assert name_at(44952) == "starGiftUnique", repr(name_at(44952))

ctors = {}
for mm in re.finditer(r'\{0x([0-9a-fA-F]+)u,(\d+),(\d+),(\d+)\}', data):
    cid = int(mm.group(1), 16)
    ctors[cid] = (int(mm.group(2)), int(mm.group(3)), int(mm.group(4)))

m2 = re.search(r'g_tl_params\[\]\s*=\s*\{(.*?)\};', data, re.S)
psrc = m2.group(1)
params = []
for mm in re.finditer(r'\{(\d+),(\d+|0x[0-9a-fA-F]+),(\d+),(\d+),(\d+)\}', psrc):
    def num(x): return int(x, 16) if x.startswith('0x') else int(x)
    params.append((int(mm.group(1)), num(mm.group(2)), num(mm.group(3)), num(mm.group(4)), num(mm.group(5))))

OPS = {0: 'int', 1: 'long', 2: 'double', 3: 'string', 4: 'bytes', 5: 'int128',
       6: 'int256', 7: '#flags', 8: 'true', 9: 'boxed', 10: 'complex'}

def dump(cid):
    if cid not in ctors:
        print("  NOT FOUND: 0x%08x" % cid)
        return
    noff, pstart, pcount = ctors[cid]
    print("=== %s#%08x  (pstart=%d pcount=%d) ===" % (name_at(noff), cid, pstart, pcount))
    for i in range(pcount):
        noff_p, fidx, fbit, vec, op = params[pstart + i]
        pname = name_at(noff_p)
        vecs = ('Vector<' if vec == 1 else ('vec(bare)<' if vec == 2 else ''))
        flag = '' if fidx == 0xFF else (' [flags%d.bit%d]' % (fidx, fbit))
        opn = OPS.get(op, '?%d' % op)
        print("  [%2d] %-26s %s%s%s" % (i, pname, vecs, opn, flag))

targets = [
    ("payments.savedStarGifts", 0x95f389b1),
    ("payments.starGifts", 0x2ed82995),
    ("savedStarGift", 0x41df43fc),
    ("starGift", 0x313a9547),
    ("starGiftUnique", 0x85f0a9cd),
]
for name, cid in targets:
    dump(cid)
    print()

for nm in ["starGiftAttributeModel", "starGiftAttributePattern", "starGiftAttributeBackdrop",
           "starGiftAttributeOriginalDetails", "starGiftAttributeCounter",
           "starGiftAttributeRarity", "starsAmount", "starsTonAmount"]:
    found = None
    for cid, (noff, ps, pc) in ctors.items():
        if name_at(noff) == nm:
            found = cid
            break
    if found:
        dump(found)
        print()
    else:
        print("no ctor for", nm)
        print()
