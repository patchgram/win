import time, sys
t0=time.time()
import idapro
rc=idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
print("open rc:", rc, "in %.1fs"%(time.time()-t0), flush=True)
import ida_hexrays, ida_funcs, idc
ida_hexrays.init_hexrays_plugin()
BASE=0x140000000

cands=[int(x,16) for x in sys.argv[1:]]
for rva in cands:
    ea=BASE+rva
    fn=ida_funcs.get_func(ea)
    print("\n\n=================== FN %08x  (VA %x)  bounds %x..%x ==================="%(
        rva, ea, (fn.start_ea-BASE) if fn else 0, (fn.end_ea-BASE) if fn else 0), flush=True)
    try:
        cf=ida_hexrays.decompile(ea)
        print(str(cf), flush=True)
    except Exception as e:
        print("decompile failed:", e, flush=True)
idapro.close_database(save=False)
print("\ndone in %.1fs"%(time.time()-t0), flush=True)
