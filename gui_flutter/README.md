# Patchgram GUI — Flutter (macOS-styled)

A Flutter desktop rewrite of the patcher, styled to match the original macOS (SwiftUI) Patchgram:
dark theme, top bar (Logs / Rescan / Choose App), sidebar stats, sections → patch-detail master/detail,
patch cards with **Available** / `dylib`·`binary` / **Enabled** badges + toggles, search, a **Filters**
popover (Type + Sort), collapsible subpatches, and **Settings** modals (Gift spoof, Show hidden gifts).

Like the macOS app it does **not** patch anything itself — it edits `PatchgramRuntime.json` (read by
`Patchgram.dll` at load). On **Apply** it installs persistence into the Telegram folder (renames the real
client to `Telegram_real.exe`, drops the bundled `pg_launcher.exe` as `Telegram.exe` + `Patchgram.dll`
beside it) and restarts it — so every launch of Telegram is patched, no patcher run required. All patch
logic lives in the DLL; no per-apply compiler.

## Status
**Built + verified live** with Flutter 3.44.2 / Dart 3.12.2 → `build\windows\x64\runner\Release\patchgram_gui.exe`.
On launch it reads the real Telegram.exe size and loads the existing `PatchgramRuntime.json`. See
`screenshot-sections.png` and `screenshot-accounts.png` for the rendered UI.

## Build / run
Needs the [Flutter SDK](https://docs.flutter.dev/get-started/install/windows) on PATH (Dart is bundled).
```
gui_flutter\build.bat          REM first run scaffolds windows\, then builds Release
REM or, manually:
flutter create --platforms=windows .   REM once (generates the native runner; keeps lib\ + pubspec.yaml)
flutter pub get
flutter run -d windows                  REM dev    |   flutter build windows --release   REM ship
```
Output: `build\windows\x64\runner\Release\patchgram_gui.exe` (+ the `data\` folder beside it).

## Files
- `lib/theme.dart` — the macOS-dark palette + text styles.
- `lib/models.dart` — the patch catalog (5 sections; `available:true` = wired to the Windows DLL).
- `lib/app_state.dart` — selected app + `PatchgramRuntime.json` read/write + loader launch (`Process.start`).
- `lib/patches_view.dart` — sections list, patch detail, cards, badges, search, Filters popover, subpatches.
- `lib/settings_modals.dart` — Gift-spoof + hidden-gifts config dialogs (Save / Save & Apply / Cancel).
- `lib/main.dart` — the app shell (top bar, sidebar, status, bottom bar).

## Mapping to the DLL
Toggles write the same config keys the DLL reads: `alwaysOfflineEnabled`, `noPhoneOnAddEnabled`,
`accountFreezeEnabled`, `messageSettingsEnabled`+`messageNoForwardsCopyEnabled`, `blockTypingEnabled`,
`blockReadMessagesEnabled`, `giftSpoofEnabled`(+`giftSpoof*`), `giftShowHiddenEnabled`(+`giftHiddenPayload`),
`mtprotoLoggerEnabled`. Patches marked **Needs RE** (999 accounts, recent stickers, monetization, …) are
shown for parity with the macOS app but their toggle is disabled until the byte-patch AOB lands in the DLL.

> This Flutter app supersedes the lightweight WinForms `gui/PatchgramGui.exe`; both edit the same JSON, so
> either works. Keep whichever you prefer.
