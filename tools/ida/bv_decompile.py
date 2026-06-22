import time, sys, os
t0=time.time()
import idapro
EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "..", "Telegram", "Telegram.exe")
rc=idapro.open_database(EXE, run_auto_analysis=False)
print("open rc:", rc, "in %.1fs"%(time.time()-t0), flush=True)
import ida_hexrays, ida_funcs, idc
ida_hexrays.init_hexrays_plugin()
BASE=0x140000000
def dec(rva, tag):
    ea=BASE+rva
    fn=ida_funcs.get_func(ea)
    print("\n\n===== %s  FN rva=0x%x VA=0x%x bounds 0x%x..0x%x ====="%(
        tag, rva, ea, (fn.start_ea-BASE) if fn else 0, (fn.end_ea-BASE) if fn else 0), flush=True)
    try:
        cf=ida_hexrays.decompile(ea)
        print(str(cf), flush=True)
    except Exception as e:
        print("decompile failed:", e, flush=True)
# ApplyUserUpdate
dec(0x1402fa0, "ApplyUserUpdate")
idapro.close_database(save=False)
print("\ndone in %.1fs"%(time.time()-t0), flush=True)
