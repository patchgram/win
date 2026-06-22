import os, idapro
EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "..", "Telegram", "Telegram.exe")
idapro.open_database(EXE, run_auto_analysis=False)
import ida_funcs, ida_auto, ida_hexrays, idc, ida_bytes, idautils

ida_hexrays.init_hexrays_plugin()
REG = 0x140354f10   # the "unlimited-recent-stickers" option registration fn (from the string xref)
f = ida_funcs.get_func(REG)
print("reg fn:", hex(f.start_ea), "-", hex(f.end_ea))
ida_auto.plan_and_wait(f.start_ea, f.end_ea)
try:
    cf = ida_hexrays.decompile(REG)
    print("==== PSEUDOCODE ====")
    print(str(cf))
except Exception as e:
    print("decompile failed:", e)
    print("==== DISASM ====")
    ea = f.start_ea
    while ea < f.end_ea:
        print("%08x  %s" % (ea - 0x140000000, idc.GetDisasm(ea)))
        ea = idc.next_head(ea, f.end_ea)
idapro.close_database(save=False)
