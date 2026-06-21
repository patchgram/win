import time, sys
t0=time.time()
import idapro
rc=idapro.open_database(r"E:\patchgram\patchgramtest\Telegram.exe", run_auto_analysis=False)
print("open rc:", rc, "in %.1fs"%(time.time()-t0), flush=True)
import ida_hexrays, ida_funcs, ida_auto, ida_bytes, idc
ida_hexrays.init_hexrays_plugin()
BASE=0x140000000
def dec(rva, tag):
    ea=BASE+rva
    # ensure a function exists & is analyzed
    f=ida_funcs.get_func(ea)
    if not f:
        ida_funcs.add_func(ea)
    ida_auto.plan_and_wait(ea, ea+0x400)
    f=ida_funcs.get_func(ea)
    print("\n\n===== %s rva=0x%x bounds 0x%x..0x%x ====="%(tag, rva,
        (f.start_ea-BASE) if f else 0,(f.end_ea-BASE) if f else 0), flush=True)
    try:
        cf=ida_hexrays.decompile(ea)
        print(str(cf), flush=True)
    except Exception as e:
        print("decompile failed:", e, flush=True)
# setBotVerifyDetails + its helpers
dec(0x1402d80, "UserData::setBotVerifyDetails")
# the new/delete/dtor helpers to characterize CRT
dec(0x3fc250, "helper_0x3fc250 (description dtor?)")
dec(0x41ff70, "helper_0x41ff70 (TextWithEntities copy-ctor?)")
idapro.close_database(save=False)
print("\ndone in %.1fs"%(time.time()-t0), flush=True)
