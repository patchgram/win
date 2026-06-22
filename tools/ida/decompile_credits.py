import time, os
import idapro
EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "..", "Telegram", "Telegram.exe")
rc=idapro.open_database(EXE, run_auto_analysis=False)
print("open rc:", rc, flush=True)
import ida_hexrays, ida_funcs, ida_bytes, idc
ida_hexrays.init_hexrays_plugin()
BASE=0x140000000
for rva in (0x115c470, 0x115c5b0):
    ea=BASE+rva
    fn=ida_funcs.get_func(ea)
    print("="*70, flush=True)
    print(f"FUNC RVA={hex(rva)} VA={hex(ea)} bounds=[{hex(fn.start_ea-BASE)},{hex(fn.end_ea-BASE)}] size={fn.end_ea-fn.start_ea}", flush=True)
    try:
        cf=ida_hexrays.decompile(ea)
        print(str(cf), flush=True)
    except Exception as e:
        print("decompile failed:", e, flush=True)
idapro.close_database(save=False)
