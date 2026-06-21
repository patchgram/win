import time, idapro
t = time.time()
# open WITHOUT auto-analysis first — just confirm idalib loads this 208 MB PE.
rc = idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
print("open rc:", rc, "in %.1fs" % (time.time() - t))
import ida_segment, ida_funcs
print("segments:", ida_segment.get_segm_qty(), "funcs(pre-analysis):", ida_funcs.get_func_qty())
import ida_bytes, ida_search
# does the option id string exist + at what EA?
ea = ida_bytes.find_bytes(b"unlimited-recent-stickers", 0) if hasattr(ida_bytes, "find_bytes") else idapro.BADADDR
print("string EA:", hex(ea) if ea not in (None, 0xffffffffffffffff) else "n/a (need search api)")
idapro.close_database(save=False)
print("closed OK")
