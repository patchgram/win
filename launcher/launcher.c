// Patchgram persistence launcher. Installed by the patcher AS "Telegram.exe" (the real client is renamed
// to "Telegram_real.exe" next to it). Telegram hardens its DLL search path, so app-dir DLL sideloading is
// blocked — instead we BECOME the exe: any launch of Telegram.exe (shortcut, double-click, tg:// link) runs
// this, which starts the real client SUSPENDED, injects Patchgram.dll, then resumes — so the runtime patches
// are in place from the very first instruction, no separate patcher run needed. Command-line args (e.g. a
// tg:// URL) are forwarded verbatim. If anything fails, we still resume the client so it never hangs.
#include <windows.h>

static int inject(HANDLE proc, const wchar_t *dll) {
    if (!proc) return 0;
    SIZE_T bytes = (lstrlenW(dll) + 1) * sizeof(wchar_t);
    void *remote = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) return 0;
    int ok = 0;
    if (WriteProcessMemory(proc, remote, dll, bytes, NULL)) {
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC loadLib = GetProcAddress(k32, "LoadLibraryW");
        if (loadLib) {
            HANDLE th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)loadLib, remote, 0, NULL);
            if (th) { WaitForSingleObject(th, 15000); CloseHandle(th); ok = 1; }
        }
    }
    VirtualFreeEx(proc, remote, 0, MEM_RELEASE);
    return ok;
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, LPWSTR cmd, int show) {
    (void)inst; (void)prev; (void)cmd; (void)show;
    wchar_t self[MAX_PATH];
    DWORD n = GetModuleFileNameW(NULL, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return 1;
    wchar_t *slash = wcsrchr(self, L'\\');
    if (!slash) return 1;
    *slash = 0;                                         // self = own directory
    wchar_t real[MAX_PATH], dll[MAX_PATH];
    wsprintfW(real, L"%s\\Telegram_real.exe", self);
    wsprintfW(dll,  L"%s\\Patchgram.dll", self);

    // Forward our args (everything after argv0) to the real client.
    LPWSTR full = GetCommandLineW();
    LPWSTR rest = full;
    if (*rest == L'"') { rest++; while (*rest && *rest != L'"') rest++; if (*rest == L'"') rest++; }
    else { while (*rest && *rest != L' ' && *rest != L'\t') rest++; }
    while (*rest == L' ' || *rest == L'\t') rest++;     // rest = trailing args (may be empty)

    static wchar_t cmdline[32768];
    if (*rest) wsprintfW(cmdline, L"\"%s\" %s", real, rest);
    else       wsprintfW(cmdline, L"\"%s\"", real);

    STARTUPINFOW si; ZeroMemory(&si, sizeof si); si.cb = sizeof si;
    PROCESS_INFORMATION pi; ZeroMemory(&pi, sizeof pi);
    if (!CreateProcessW(real, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, self, &si, &pi))
        return 1;                                       // real client missing → nothing to do
    inject(pi.hProcess, dll);                           // best-effort; resume regardless
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
