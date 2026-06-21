import re, sys
name = sys.argv[1] if len(sys.argv) > 1 else 'messages.saveDraft'
src = open('dll/tl_schema.c.inc', 'r', encoding='utf-8', errors='replace').read()
m = re.search(r'g_tl_strpool\[\]\s*=\s*(.*?);', src, re.S)
seg = m.group(1)
parts = re.findall(r'"((?:[^"\\]|\\.)*)"', seg)
pool = ''
for p in parts:
    pool += bytes(p, 'utf-8').decode('unicode_escape', 'ignore')
off = pool.find(name + '\x00')
print('name_off =', off)
ents = re.findall(r'\{\s*(0x[0-9a-fA-F]+)u?,\s*(\d+),\s*(\d+),\s*(\d+)\s*\}', src)
found = False
for cid, no, ps, pc in ents:
    if int(no) == off:
        print('ctor id =', cid, 'pcount =', pc); found = True
if not found:
    print('no ctor entry with that name_off (off=%d)' % off)
