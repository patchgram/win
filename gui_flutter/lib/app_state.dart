import 'dart:convert';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:file_selector/file_selector.dart';
import 'models.dart';

/// Owns the selected app, the PatchgramRuntime.json config, and drives the loader. The Flutter GUI never
/// patches anything itself — it edits the JSON (read by Patchgram.dll at load) and runs patchgram-loader.exe.
class AppState extends ChangeNotifier {
  String telegramPath = '';
  String dllPath = '';
  String launcherPath = '';   // bundled pg_launcher.exe — installed AS Telegram.exe for persistent patching
  String status = 'Pick Telegram.exe, toggle patches, then Apply.';
  double progress = 0;       // top bar fill 0..1 (driven during Apply / Disable All)
  bool applying = false;     // an Apply/Disable operation is in flight (isWorking)
  Map<String, Object> _applied = {};   // snapshot of the last saved/applied config (for pending detection)

  // Pending changes = current config differs from what was last applied/loaded (drives Apply enablement).
  bool get dirty {
    if (cfg.length != _applied.length) return true;
    for (final e in cfg.entries) { if ('${_applied[e.key]}' != '${e.value}') return true; }
    return false;
  }

  // pulled from Telegram.exe's file properties + icon (shown next to "Selected app")
  String productName = 'Telegram Desktop';
  String productVersion = '';
  String iconPath = '';

  // config: bool flags + gift numeric fields + payload string. Defaults mirror the DLL.
  final Map<String, Object> cfg = {'mtprotoLoggerEnabled': true};

  bool autoCheckUpdates = true;   // "check for updates on launch" (default on, like macOS), persisted
  // Patcher version + build — keep in sync with pubspec.yaml `version: 1.0.0+10`. Shown in About + the
  // GitHub update check, so it's a real version (not decoration): "Version 1.0.0 (10)".
  static const appVersion = '1.0.0';
  static const appBuild = '10';
  static const _version = appVersion;

  AppState() { _guessPaths(); _loadSettings(); load(); _readAppInfo();
    if (autoCheckUpdates) checkForUpdates(user: false); }

  String get _settingsPath => '${File(Platform.resolvedExecutable).parent.path}\\patchgram_gui_settings.json';
  void _loadSettings() {
    try { final f = File(_settingsPath); if (f.existsSync()) {
      final m = jsonDecode(f.readAsStringSync());
      if (m is Map && m['autoCheckUpdates'] is bool) autoCheckUpdates = m['autoCheckUpdates'] as bool;
    } } catch (_) {}
  }
  void _saveSettings() {
    try { File(_settingsPath).writeAsStringSync(jsonEncode({'autoCheckUpdates': autoCheckUpdates})); } catch (_) {}
  }
  void setAutoCheck(bool v) { autoCheckUpdates = v; _saveSettings(); notifyListeners(); }

  /// Manual / launch update check against the patchgram/win GitHub releases (mirrors the macOS check).
  Future<void> checkForUpdates({bool user = true}) async {
    if (user) { status = 'Checking GitHub for updates…'; notifyListeners(); }
    try {
      final c = HttpClient()..connectionTimeout = const Duration(seconds: 8);
      final req = await c.getUrl(Uri.parse('https://api.github.com/repos/patchgram/win/releases/latest'));
      req.headers.set('User-Agent', 'PatchgramGui');
      final resp = await req.close();
      final body = await resp.transform(const Utf8Decoder()).join();
      c.close();
      if (resp.statusCode == 404) { if (user) status = 'No releases published yet (you are on $_version).'; }
      else if (resp.statusCode == 200) {
        final m = jsonDecode(body);
        final tag = ('${m['tag_name'] ?? ''}').replaceAll('v', '');
        if (tag.isEmpty) { if (user) status = 'Up to date ($_version).'; }
        else if (tag != _version) { status = 'Update available: $tag (you have $_version).'; }
        else { if (user) status = "You're on the latest version ($_version)."; }
      } else if (user) { status = 'Update check failed (HTTP ${resp.statusCode}).'; }
    } catch (e) { if (user) status = 'Update check failed: $e'; }
    notifyListeners();
  }

  // ---- gift field parsing (ported from macOS BinaryPatchRule) -----------------------------------
  /// Bot-API sender id → (internal peer id, peer type 0=user/1=channel/2=chat).
  static (int, int) parseSenderId(String s) {
    s = s.trim();
    final v = int.tryParse(s) ?? 0;
    if (v >= 0) return (v, 0);
    if (s.startsWith('-100')) { final r = int.tryParse(s.substring(4)); if (r != null) return (r, 1); }
    return (-v, 2);
  }
  /// "0"/empty → 0 (keep); a plain integer → unix; else "HH:mm:ss dd.MM.yyyy" (local) → unix; bad → 0.
  static int parseDateUnix(String s) {
    s = s.trim();
    if (s.isEmpty) return 0;
    final v = int.tryParse(s);
    if (v != null && v >= 0 && v <= 2147483647) return v;
    final m = RegExp(r'^(\d{1,2}):(\d{2}):(\d{2})\s+(\d{1,2})\.(\d{1,2})\.(\d{4})$').firstMatch(s);
    if (m == null) return 0;
    final dt = DateTime(int.parse(m[6]!), int.parse(m[5]!), int.parse(m[4]!),
        int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!));
    final ts = dt.millisecondsSinceEpoch ~/ 1000;
    return (ts >= 0 && ts <= 2147483647) ? ts : 0;
  }

  /// Read ProductName + ProductVersion from Telegram.exe's version info and extract its icon to a PNG
  /// (shown next to "Selected app"). Done via PowerShell so no native FFI is needed.
  Future<void> _readAppInfo() async {
    final exe = realExePath;   // the real client (post-install it's Telegram_real.exe), not our launcher
    if (exe.isEmpty || !File(exe).existsSync()) return;
    final png = '${File(exe).parent.path}\\.patchgram_telegram_icon.png';
    final pEsc = exe.replaceAll("'", "''");
    final pngEsc = png.replaceAll("'", "''");
    final ps = "\$ErrorActionPreference='SilentlyContinue';"
        "\$vi=(Get-Item '$pEsc').VersionInfo;"
        "Add-Type -AssemblyName System.Drawing;"
        "try { ([System.Drawing.Icon]::ExtractAssociatedIcon('$pEsc')).ToBitmap()"
        ".Save('$pngEsc',[System.Drawing.Imaging.ImageFormat]::Png) } catch {};"
        "Write-Output (\$vi.ProductName + '|' + \$vi.ProductVersion)";
    try {
      final r = await Process.run('powershell', ['-NoProfile', '-NonInteractive', '-Command', ps]);
      final out = '${r.stdout}'.trim().split('\n').where((l) => l.contains('|')).toList();
      if (out.isNotEmpty) {
        final parts = out.last.trim().split('|');
        if (parts[0].trim().isNotEmpty) productName = parts[0].trim();
        if (parts.length > 1 && parts[1].trim().isNotEmpty) {
          final v = parts[1].trim().split('.');
          productVersion = v.length >= 3 ? '${v[0]}.${v[1]}.${v[2]}' : parts[1].trim();
        }
      }
      if (File(png).existsSync()) iconPath = png;
    } catch (_) {}
    notifyListeners();
  }

  void _guessPaths() {
    final exeDir = File(Platform.resolvedExecutable).parent.path;
    for (final p in [
      r'E:\patchgram\patchgramtest\Telegram.exe',
      '${Platform.environment['APPDATA']}\\Telegram Desktop\\Telegram.exe',
    ]) { if (File(p).existsSync()) { telegramPath = p; break; } }
    // Patchgram.dll is BUNDLED inside the app (as a flutter asset → data/flutter_assets/assets/), so the
    // release ships no loose .dll and no loader .exe — the GUI injects it natively (see native_inject.dart).
    for (final p in [_rel(exeDir, r'data\flutter_assets\assets\Patchgram.dll'),
        r'E:\patchgram\win\dll\Patchgram.dll']) { if (File(p).existsSync()) { dllPath = p; break; } }
    // The persistence launcher (installed AS Telegram.exe) is bundled the same way.
    for (final p in [_rel(exeDir, r'data\flutter_assets\assets\pg_launcher.exe'),
        r'E:\patchgram\win\launcher\pg_launcher.exe']) { if (File(p).existsSync()) { launcherPath = p; break; } }
  }
  static String _rel(String base, String rel) {
    try { return File('$base\\$rel').absolute.path; } catch (_) { return rel; }
  }

  String get telegramDir => telegramPath.isEmpty ? '' : File(telegramPath).parent.path;
  // After persistence is installed, Telegram.exe is our launcher and the real client lives as
  // Telegram_real.exe; the exe-size / version / icon readouts should reflect the real client.
  String get realExePath {
    if (telegramDir.isEmpty) return telegramPath;
    final r = '$telegramDir\\Telegram_real.exe';
    return File(r).existsSync() ? r : telegramPath;
  }
  bool get persistenceInstalled =>
      telegramDir.isNotEmpty && File('$telegramDir\\Telegram_real.exe').existsSync();

  String get _configPath => telegramPath.isEmpty ? '' : '${File(telegramPath).parent.path}\\PatchgramRuntime.json';
  String get _logPath => telegramPath.isEmpty ? '' : '${File(telegramPath).parent.path}\\PatchgramHook.log';

  // ---- patch state ------------------------------------------------------------------------------
  bool boolKey(String k) => cfg[k] == true;
  void setBool(String k, bool v) { cfg[k] = v; notifyListeners(); }
  void setInt(String k, int v) { cfg[k] = v; notifyListeners(); }
  void setStr(String k, String v) { cfg[k] = v; notifyListeners(); }
  int intKey(String k) => (cfg[k] is int) ? cfg[k] as int : int.tryParse('${cfg[k]}') ?? 0;
  String strKey(String k) => '${cfg[k] ?? ''}';

  // Same as above but with an explicit fallback when the key is absent (used by settings modals
  // to seed their fields with the macOS defaults the first time the modal is opened).
  int intKeyOr(String k, int def) {
    if (!cfg.containsKey(k)) return def;
    return (cfg[k] is int) ? cfg[k] as int : int.tryParse('${cfg[k]}') ?? def;
  }
  String strKeyOr(String k, String def) => cfg.containsKey(k) ? '${cfg[k]}' : def;
  bool boolKeyOr(String k, bool def) => cfg.containsKey(k) ? cfg[k] == true : def;

  // Any wired patch or subpatch currently enabled (gates Disable All / Apply). The always-on MTProto
  // logger toggle is a diagnostic, not a "patch", so it doesn't count.
  bool get hasEnabledPatch {
    for (final s in catalog) {
      for (final p in s.patches) {
        final keys = p.keys.where((k) => k != 'mtprotoLoggerEnabled');
        if (p.available && keys.isNotEmpty && keys.every(boolKey)) return true;
        for (final sp in p.subs) { if (sp.key.isNotEmpty && boolKey(sp.key)) return true; }
      }
    }
    return false;
  }
  // Apply is enabled when there are pending changes OR persistence isn't installed yet but patches are on
  // (so a first Apply can install the persistent launcher even when the saved config already matches).
  bool get canApply => telegramPath.isNotEmpty && !applying
      && (dirty || (!persistenceInstalled && hasEnabledPatch));
  bool get canDisableAll => !applying && hasEnabledPatch;

  bool isEnabled(Patch p) => p.keys.isNotEmpty && p.keys.every(boolKey);

  // ---- unified patch on/off (leaf patches AND grouping patches with subpatches) ------------------
  // Mirrors macOS grouping semantics: a GROUPING patch (has subpatches) reads as ON when ANY keyed
  // subpatch is on; toggling the parent cascades to ALL subpatches (ON = enable all, OFF = disable all).
  // A LEAF patch is on when its own keys are all on. This is what makes the "Custom account settings"
  // master switch interactive + flip every child together.
  bool patchOn(Patch p) {
    if (p.subs.isNotEmpty) return p.subs.any((s) => s.key.isNotEmpty && boolKey(s.key));
    return p.keys.isNotEmpty && p.keys.every(boolKey);
  }
  // A patch is togglable if it's a grouping patch (always — cascades to children) or an available leaf.
  bool canToggle(Patch p) => p.subs.isNotEmpty || (p.available && p.keys.isNotEmpty);
  // Set a patch on/off; cascades to every subpatch (the parent = "enable/disable all" switch).
  void setPatch(Patch p, bool on) {
    if (!canToggle(p)) return;
    for (final k in p.keys) cfg[k] = on;
    for (final s in p.subs) { if (s.key.isNotEmpty) cfg[s.key] = on; }
    if (on && p.id != 'inject') cfg['dllInjectionEnabled'] = true;  // every patch runs through the DLL
    notifyListeners();
  }
  void toggle(Patch p, bool on) => setPatch(p, on);
  // Subpatch toggle (parent-aware): enabling a child also turns on the group MASTER key (e.g.
  // messageSettingsEnabled / disableMonetizationEnabled) that the engine gates on; disabling the last
  // child turns the master back off. Account freeze ↔ Bot verification are mutually exclusive (macOS).
  void setSubpatch(Patch parent, String key, bool on) {
    cfg[key] = on;
    if (on) {
      cfg['dllInjectionEnabled'] = true;
      if (key == 'botVerifyEnabled') cfg['accountFreezeEnabled'] = false;
      if (key == 'accountFreezeEnabled') cfg['botVerifyEnabled'] = false;
    }
    // Group master keys = the parent's own keys that are NOT themselves subpatch keys.
    final subKeys = parent.subs.map((s) => s.key).toSet();
    final masters = parent.keys.where((k) => !subKeys.contains(k));
    if (on) {
      for (final k in masters) cfg[k] = true;
    } else {
      final anyOn = parent.subs.any((s) => s.key.isNotEmpty && cfg[s.key] == true);
      if (!anyOn) for (final k in masters) cfg[k] = false;
    }
    notifyListeners();
  }

  // Count of enabled wired patches + subpatches (excluding the logger), for the sidebar + status.
  int get enabledRules {
    var n = 0;
    for (final s in catalog) {
      for (final p in s.patches) {
        final keys = p.keys.where((k) => k != 'mtprotoLoggerEnabled');
        if (p.available && keys.isNotEmpty && keys.every(boolKey)) n++;
        for (final sp in p.subs) { if (sp.key.isNotEmpty && boolKey(sp.key)) n++; }
      }
    }
    return n;
  }
  int get availableCount {
    var n = 0;
    for (final s in catalog) { for (final p in s.patches) { if (p.available) n++; } }
    return n;
  }
  int get totalCount { var n = 0; for (final s in catalog) n += s.patches.length; return n; }

  // Disable All (after the GUI confirmation alert): turn EVERYTHING off — every patch AND the DLL
  // injection AND the logger — write the clean config, then RESTART Telegram without the DLL so the
  // client comes back fully unpatched (a live drop can't undo an already-injected DLL or in-memory
  // byte-patches; a clean relaunch with no injection is the only way to get a pristine client).
  Future<void> disableAll() async {
    if (applying) return;
    for (final k in cfg.keys.toList()) { if (cfg[k] is bool) cfg[k] = false; }
    notifyListeners();
    await _runDisableAllRestart();
  }

  Future<void> _runDisableAllRestart() async {
    if (applying) return;
    if (telegramPath.isEmpty) { status = 'Set Telegram.exe first.'; notifyListeners(); return; }
    applying = true;
    Future<void> step(double p, String m) async { progress = p; status = m; notifyListeners(); await Future.delayed(const Duration(milliseconds: 220)); }
    await step(0.10, 'Disabling all patches…');
    await step(0.32, 'Writing clean config…');
    final wrote = _writeConfig();
    await step(0.55, 'Removing the patcher + closing Telegram…');
    // Uninstall persistence too (restore the original Telegram.exe, delete the launcher + DLL) so the client
    // comes back completely pristine — otherwise launching it would still load the DLL via the launcher.
    await uninstallPersistence();
    await Future.delayed(const Duration(milliseconds: 400));
    await step(0.80, 'Restarting Telegram (clean, no DLL)…');
    if (File(telegramPath).existsSync()) {
      try { await Process.start(telegramPath, const [], mode: ProcessStartMode.detached); } catch (_) {}
    }
    await step(0.95, 'Client restarted unpatched.');
    progress = 1.0;
    status = wrote ? 'All patches disabled — original Telegram.exe restored, restarted clean.' : 'Disable failed: could not write config.';
    notifyListeners();
    await Future.delayed(const Duration(milliseconds: 1100));
    progress = 0; applying = false; notifyListeners();
    _readAppInfo();
  }

  // ---- IO ---------------------------------------------------------------------------------------
  bool _writeConfig() {
    final p = _configPath;
    if (p.isEmpty) return false;
    try { File(p).writeAsStringSync(const JsonEncoder.withIndent('  ').convert(cfg)); _applied = Map.of(cfg); return true; }
    catch (_) { return false; }
  }

  Future<void> load() async {
    final p = _configPath;
    if (p.isEmpty || !File(p).existsSync()) { notifyListeners(); return; }
    try {
      final m = jsonDecode(File(p).readAsStringSync());
      if (m is Map) { cfg.clear(); m.forEach((k, v) => cfg['$k'] = v as Object); }
      _applied = Map.of(cfg); status = 'Loaded config from $p';
    } catch (e) { status = 'Config read failed: $e'; }
    notifyListeners();
  }

  Future<bool> save() async {
    if (_configPath.isEmpty) { status = 'Set Telegram.exe first.'; notifyListeners(); return false; }
    final ok = _writeConfig();
    status = ok ? 'Saved config.' : 'Save failed.'; notifyListeners(); return ok;
  }

  // Apply = the macOS-style operation: animate the top bar in steps while writing the runtime config and
  // (re)injecting, so it's obvious the patches activated. Live (the DLL re-reads the JSON via its watcher).
  Future<void> apply() async { if (!canApply) return; await _runApply('Runtime patches updated live.'); }

  Future<void> _runApply(String doneMsg) async {
    if (applying) return;
    if (telegramPath.isEmpty) { status = 'Set Telegram.exe first.'; notifyListeners(); return; }
    applying = true;
    Future<void> step(double p, String m) async { progress = p; status = m; notifyListeners(); await Future.delayed(const Duration(milliseconds: 200)); }
    await step(0.08, 'Applying patches…');
    await step(0.24, 'Writing runtime config…');
    final wrote = _writeConfig();
    bool installOk = persistenceInstalled;
    if (launcherPath.isNotEmpty && dllPath.isNotEmpty && File(telegramPath).existsSync()) {
      final running = await _telegramRunning();
      final patched = running && persistenceInstalled && await _dllInjected();
      if (patched) {
        // Already patched + persistent: the DLL's config watcher reloads the JSON live (~1s). Nothing to launch.
        await step(0.72, 'Reloading patches live…');
      } else {
        if (running) {
          await step(0.5, 'Closing Telegram…');
          await _killTelegram();
          await Future.delayed(const Duration(milliseconds: 900));
        }
        await step(0.66, 'Installing persistent patcher…');
        installOk = _installPersistence();   // make Telegram.exe our launcher so every launch is patched
        await step(0.84, 'Starting Telegram…');
        if (installOk) { try { await Process.start(telegramPath, const [], mode: ProcessStartMode.detached); } catch (_) {} }
      }
    }
    await step(0.95, 'Runtime config updated.');
    progress = 1.0;
    status = !wrote ? 'Apply failed: could not write config.'
        : !installOk ? 'Config saved, but could not install into the Telegram folder (is it writable?).'
        : '$doneMsg  ($enabledRules patch(es) active · every launch is patched)';
    notifyListeners();
    await Future.delayed(const Duration(milliseconds: 1100));
    progress = 0; applying = false; notifyListeners();
    _readAppInfo();   // the real client may have just been renamed → refresh size/version/icon
  }

  Future<void> _killTelegram() async {
    for (final n in const ['Telegram.exe', 'Telegram_real.exe']) {
      try { await Process.run('taskkill', ['/F', '/IM', n]); } catch (_) {}
    }
  }

  // Install persistence so launching Telegram.exe ANY way (shortcut, double-click, tg:// link) is patched —
  // no patcher run needed. Telegram hardens its DLL search path, so a sideloaded DLL won't load; instead we
  // REPLACE the exe: the real client becomes Telegram_real.exe and our small launcher takes its place as
  // Telegram.exe (it starts the real client suspended, injects Patchgram.dll, resumes). Telegram must be
  // closed first (the exe rename needs the file unlocked). Idempotent; also recovers after Telegram updates
  // (which overwrite Telegram.exe with a fresh real client).
  bool _installPersistence() {
    try {
      final dir = telegramDir;
      if (dir.isEmpty || launcherPath.isEmpty || !File(launcherPath).existsSync()) return false;
      final mainExe = '$dir\\Telegram.exe';
      final realExe = '$dir\\Telegram_real.exe';
      final mf = File(mainExe);
      // Telegram.exe being large = the real client (first install, or an update replaced our launcher) →
      // promote it to Telegram_real.exe. Small = already our launcher → keep the existing Telegram_real.exe.
      if (mf.existsSync() && mf.lengthSync() > 50 * 1024 * 1024) {
        if (File(realExe).existsSync()) File(realExe).deleteSync();
        mf.renameSync(realExe);
      }
      if (!File(realExe).existsSync()) return false;          // no real client to wrap
      File(launcherPath).copySync(mainExe);                   // launcher → Telegram.exe
      if (dllPath.isNotEmpty && File(dllPath).existsSync()) File(dllPath).copySync('$dir\\Patchgram.dll');
      return File(mainExe).existsSync();
    } catch (_) { return false; }
  }

  // Restore the original client: remove the launcher + DLL, rename Telegram_real.exe back to Telegram.exe.
  Future<bool> uninstallPersistence() async {
    if (!persistenceInstalled) return true;
    await _killTelegram();
    await Future.delayed(const Duration(milliseconds: 900));
    try {
      final dir = telegramDir;
      final mainExe = '$dir\\Telegram.exe';
      final realExe = '$dir\\Telegram_real.exe';
      if (File(mainExe).existsSync()) File(mainExe).deleteSync();      // delete the launcher
      File(realExe).renameSync(mainExe);                               // restore the real client
      final dll = File('$dir\\Patchgram.dll'); if (dll.existsSync()) dll.deleteSync();
      _readAppInfo();
      return true;
    } catch (_) { return false; }
  }

  // "Launch" button: start Telegram patched (installing persistence first if needed).
  Future<void> launchPatched() async {
    if (telegramPath.isEmpty) return;
    if (await _telegramRunning()) {
      if (persistenceInstalled && await _dllInjected()) { status = 'Telegram already running (patched).'; notifyListeners(); return; }
      await _killTelegram();
      await Future.delayed(const Duration(milliseconds: 900));
    }
    final ok = persistenceInstalled || _installPersistence();
    if (ok) { try { await Process.start(telegramPath, const [], mode: ProcessStartMode.detached); } catch (_) {} }
    status = ok ? 'Launched Telegram (patched).' : 'Could not install into the Telegram folder.';
    notifyListeners();
  }
  // "Logs" opens the folder where Telegram.exe lives (PatchgramHook.log + logs sit there).
  Future<void> openLog() async {
    if (telegramPath.isEmpty) { status = 'Set Telegram.exe first.'; notifyListeners(); return; }
    await _run('explorer.exe', [File(telegramPath).parent.path], 'Opened Telegram folder.');
  }

  // Is Telegram.exe running at all?
  Future<bool> _telegramRunning() async {
    try { final r = await Process.run('tasklist', ['/fo', 'csv', '/nh']);
      return RegExp(r'"telegram(_real)?\.exe"', caseSensitive: false).hasMatch(r.stdout.toString()); }
    catch (_) { return false; }
  }
  // Does a running Telegram (or our renamed Telegram_real) have Patchgram.dll loaded (already patched)?
  Future<bool> _dllInjected() async {
    try { final r = await Process.run('tasklist', ['/m', 'Patchgram.dll', '/fo', 'csv', '/nh']);
      return RegExp(r'"telegram(_real)?\.exe"', caseSensitive: false).hasMatch(r.stdout.toString()); }
    catch (_) { return false; }
  }

  // Restore Backup = revert the binary (byte) patches: it's only meaningful when a binary patch is on
  // (the in-memory .text edits exist). Turns off every PatchType.binary patch's keys, then applies so the
  // DLL restores the original instructions. Gated by canRestoreBackup so the button greys out otherwise.
  bool get canRestoreBackup {
    if (applying) return false;
    for (final s in catalog) {
      for (final p in s.patches) {
        if (p.type == PatchType.binary && p.available && p.keys.isNotEmpty && p.keys.every(boolKey)) return true;
      }
    }
    return false;
  }
  Future<void> restoreBackup() async {
    if (!canRestoreBackup) return;
    for (final s in catalog) {
      for (final p in s.patches) {
        if (p.type == PatchType.binary) { for (final k in p.keys) cfg[k] = false; }
      }
    }
    notifyListeners();
    await _runApply('Binary patches reverted (backup restored).');
  }

  bool _ok(String p, String what) {
    if (p.isEmpty || !File(p).existsSync()) { status = 'Missing $what: $p'; notifyListeners(); return false; }
    return true;
  }
  Future<void> _run(String exe, List<String> args, String ok) async {
    try { await Process.start(exe, args, mode: ProcessStartMode.detached); status = ok; }
    catch (e) { status = 'Run failed: $e'; }
    notifyListeners();
  }

  // ---- pickers ----------------------------------------------------------------------------------
  Future<void> chooseApp() async {
    final f = await openFile(acceptedTypeGroups: [const XTypeGroup(label: 'Telegram', extensions: ['exe'])]);
    if (f != null) { telegramPath = f.path; await load(); await _readAppInfo(); status = 'Selected $telegramPath'; notifyListeners(); }
  }
}
