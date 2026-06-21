import re, codecs, sys

path = r"E:\patchgram\win\dll\tl_schema.c.inc"
lines = open(path, "r", encoding="utf-8", errors="replace").read().splitlines()

# Reconstruct g_tl_strpool bytes from its C string-literal lines.
pool = bytearray()
inpool = False
seg_re = re.compile(r'"((?:[^"\\]|\\.)*)"')
for ln in lines:
    if "g_tl_strpool[]" in ln:
        inpool = True
    if inpool:
        for s in seg_re.findall(ln):
            pool += codecs.escape_decode(s.encode())[0]
        if ln.rstrip().endswith(";") and "g_tl_strpool[]" not in ln:
            break
pool = bytes(pool)

# Map nameOffset -> ctor id from the {0x..u,off,...} entries.
ent = {}
ent_re = re.compile(r"\s*\{0x([0-9a-fA-F]+)u,(\d+),")
for ln in lines:
    m = ent_re.match(ln)
    if m:
        ent[int(m.group(2))] = int(m.group(1), 16)

def off(name):
    return pool.find(name.encode() + b"\x00")

for nm in sys.argv[1:] or ["messages.getSponsoredMessages", "help.getPromoData"]:
    o = off(nm)
    idv = hex(ent[o]) if o in ent else "??"
    print("%-34s nameOff=%-7s id=%s" % (nm, o, idv))
