// Native in-process DLL injection via Win32 (CreateRemoteThread + LoadLibraryW), so the GUI injects
// Patchgram.dll itself — no separate loader .exe is shipped. Mirrors the old patchgram-loader.exe logic:
//   - injectIntoPid: attach to an already-running Telegram.
//   - launchSuspendedAndInject: start Telegram suspended, inject, then resume (so the DLL is loaded before
//     any Telegram code runs → byte-patches + hooks are in place from the very start).
import 'dart:ffi';
import 'package:ffi/ffi.dart';

final DynamicLibrary _k32 = DynamicLibrary.open('kernel32.dll');

final _OpenProcess = _k32.lookupFunction<IntPtr Function(Uint32, Int32, Uint32),
    int Function(int, int, int)>('OpenProcess');
final _VirtualAllocEx = _k32.lookupFunction<Pointer Function(IntPtr, Pointer, IntPtr, Uint32, Uint32),
    Pointer Function(int, Pointer, int, int, int)>('VirtualAllocEx');
final _WriteProcessMemory = _k32.lookupFunction<Int32 Function(IntPtr, Pointer, Pointer, IntPtr, Pointer<IntPtr>),
    int Function(int, Pointer, Pointer, int, Pointer<IntPtr>)>('WriteProcessMemory');
final _GetModuleHandleW = _k32.lookupFunction<IntPtr Function(Pointer<Utf16>),
    int Function(Pointer<Utf16>)>('GetModuleHandleW');
final _GetProcAddress = _k32.lookupFunction<Pointer Function(IntPtr, Pointer<Utf8>),
    Pointer Function(int, Pointer<Utf8>)>('GetProcAddress');
final _CreateRemoteThread = _k32.lookupFunction<
    IntPtr Function(IntPtr, Pointer, IntPtr, Pointer, Pointer, Uint32, Pointer<Uint32>),
    int Function(int, Pointer, int, Pointer, Pointer, int, Pointer<Uint32>)>('CreateRemoteThread');
final _WaitForSingleObject = _k32.lookupFunction<Uint32 Function(IntPtr, Uint32),
    int Function(int, int)>('WaitForSingleObject');
final _VirtualFreeEx = _k32.lookupFunction<Int32 Function(IntPtr, Pointer, IntPtr, Uint32),
    int Function(int, Pointer, int, int)>('VirtualFreeEx');
final _CloseHandle = _k32.lookupFunction<Int32 Function(IntPtr), int Function(int)>('CloseHandle');
final _CreateProcessW = _k32.lookupFunction<
    Int32 Function(Pointer<Utf16>, Pointer<Utf16>, Pointer, Pointer, Int32, Uint32, Pointer, Pointer<Utf16>, Pointer, Pointer),
    int Function(Pointer<Utf16>, Pointer<Utf16>, Pointer, Pointer, int, int, Pointer, Pointer<Utf16>, Pointer, Pointer)>('CreateProcessW');
final _ResumeThread = _k32.lookupFunction<Uint32 Function(IntPtr), int Function(int)>('ResumeThread');

const int _PROCESS_ALL_ACCESS = 0x1F0FFF;
const int _MEM_COMMIT_RESERVE = 0x3000;
const int _PAGE_READWRITE = 0x4;
const int _MEM_RELEASE = 0x8000;
const int _CREATE_SUSPENDED = 0x4;

// Write `dllPath` (UTF-16) into the target and run LoadLibraryW(thatPath) via a remote thread.
bool _injectHandle(int hProcess, String dllPath) {
  if (hProcess == 0) return false;
  final pathW = dllPath.toNativeUtf16();
  final bytes = (dllPath.length + 1) * 2;
  bool ok = false;
  final remote = _VirtualAllocEx(hProcess, nullptr, bytes, _MEM_COMMIT_RESERVE, _PAGE_READWRITE);
  if (remote != nullptr) {
    if (_WriteProcessMemory(hProcess, remote, pathW.cast(), bytes, nullptr) != 0) {
      final k32 = 'kernel32.dll'.toNativeUtf16();
      final ll = 'LoadLibraryW'.toNativeUtf8();
      final loadLib = _GetProcAddress(_GetModuleHandleW(k32), ll);
      malloc.free(k32);
      malloc.free(ll);
      if (loadLib != nullptr) {
        final thread = _CreateRemoteThread(hProcess, nullptr, 0, loadLib, remote, 0, nullptr);
        if (thread != 0) {
          _WaitForSingleObject(thread, 15000);
          _CloseHandle(thread);
          ok = true;
        }
      }
    }
    _VirtualFreeEx(hProcess, remote, 0, _MEM_RELEASE);
  }
  malloc.free(pathW);
  return ok;
}

/// Inject [dllPath] into an already-running process [pid]. Returns true on success.
bool injectIntoPid(int pid, String dllPath) {
  final h = _OpenProcess(_PROCESS_ALL_ACCESS, 0, pid);
  if (h == 0) return false;
  final ok = _injectHandle(h, dllPath);
  _CloseHandle(h);
  return ok;
}

/// Launch [exePath] SUSPENDED, inject [dllPath], then resume — the DLL loads before any host code runs.
bool launchSuspendedAndInject(String exePath, String dllPath) {
  final si = calloc<Uint8>(104);          // STARTUPINFOW (x64 sizeof 104)
  si.cast<Uint32>().value = 104;          //   .cb = 104
  final pi = calloc<Uint8>(24);           // PROCESS_INFORMATION (hProcess@0, hThread@8)
  final app = exePath.toNativeUtf16();
  bool ok = false;
  final created = _CreateProcessW(app, nullptr, nullptr, nullptr, 0, _CREATE_SUSPENDED, nullptr, nullptr, si.cast(), pi.cast());
  if (created != 0) {
    final hProcess = pi.cast<IntPtr>()[0];
    final hThread = pi.cast<IntPtr>()[1];
    ok = _injectHandle(hProcess, dllPath);
    _ResumeThread(hThread);               // always resume — even if inject failed, don't leave it frozen
    _CloseHandle(hThread);
    _CloseHandle(hProcess);
  }
  malloc.free(app);
  calloc.free(si);
  calloc.free(pi);
  return ok;
}
