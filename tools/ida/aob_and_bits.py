import time, struct, os
t0=time.time()
import idapro
EXE = os.environ.get("PATCHGRAM_EXE") or os.path.join(os.path.dirname(__file__), "..", "..", "Telegram", "Telegram.exe")
rc=idapro.open_database(EXE, run_auto_analysis=False)
print("open rc:", rc, flush=True)
import ida_segment, idautils, ida_bytes
BASE=0x140000000
text_start=text_end=None
for s in idautils.Segments():
    seg=ida_segment.getseg(s)
    if ida_segment.get_segm_name(seg)==".text":
        text_start, text_end=seg.start_ea, seg.end_ea
data=ida_bytes.get_bytes(text_start, text_end-text_start)
print("text bytes:", len(data), flush=True)

def count(sig_hex):
    b=bytes(int(x,16) for x in sig_hex.split())
    c=0; pos=0
    while True:
        i=data.find(b,pos)
        if i<0: break
        c+=1; pos=i+1
    return c

# UserData::setFlags entry (first 17 bytes through 'sub rsp,0x28; mov ebx,edx; mov r15,rcx')
user_sig="40 53 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 28 8b da 4c 8b f9"
chan_sig="48 89 4c 24 08 55 53 56 57 41 54 41 55 41 56 41 57 48 8b ec 48 83 ec 58 48 8b da 4c 8b e9"
print("UserData::setFlags  AOB (22B) count in .text:", count(user_sig), flush=True)
print("ChannelData::setFlags AOB (30B) count in .text:", count(chan_sig), flush=True)
# shorter user variants
print("  user 17B prefix count:", count("40 53 55 56 57 41 54 41 55 41 56 41 57 48 83 ec 28"), flush=True)

idapro.close_database(save=False)
print("done in %.1fs"%(time.time()-t0), flush=True)
