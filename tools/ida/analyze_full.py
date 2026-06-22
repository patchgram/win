import time, os, idapro
EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "..", "Telegram", "Telegram.exe")
t = time.time()
# Full auto-analysis, then save Telegram.i64 next to the exe so later investigations reopen it fast.
idapro.open_database(EXE, run_auto_analysis=True)
import ida_auto, ida_funcs
ida_auto.auto_wait()
print("ANALYSIS DONE funcs=%d in %.0fs" % (ida_funcs.get_func_qty(), time.time() - t))
idapro.close_database(save=True)   # writes Telegram.i64
print("SAVED .i64 in %.0fs total" % (time.time() - t))
