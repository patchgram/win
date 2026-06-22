# Changelog

All notable changes to Patchgram for Windows are documented here. Add a new
`## v<version>` section per release; the release workflow uses the matching
section as the GitHub Release body.

## v1.0.0

Initial Windows release — a runtime DLL patcher for Telegram Desktop x64
(6.9.3 / Qt5).

- **Patch engine** (`Patchgram.dll`): in-process patches across categories —
  accounts, messages, optimizations, gifts, and misc.
- **Persistent launcher** (`pg_launcher.exe`): keeps watch so every Telegram
  launch is patched automatically, not just the first one.
- **macOS-styled GUI** (Flutter): toggle patch sections, point at your Telegram
  install, and apply — no command line required.
