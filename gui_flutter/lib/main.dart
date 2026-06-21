import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'package:url_launcher/url_launcher.dart';
import 'theme.dart';
import 'models.dart';
import 'app_state.dart';
import 'patches_view.dart';

void main() => runApp(const PatchgramApp());

class PatchgramApp extends StatelessWidget {
  const PatchgramApp({super.key});
  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'Patchgram',
        debugShowCheckedModeBanner: false,
        theme: PG.theme(),
        home: const Shell(),
      );
}

class Shell extends StatefulWidget {
  const Shell({super.key});
  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  final state = AppState();
  Section? open; // null = sections list

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: state,
      builder: (_, __) => Scaffold(
        body: Column(children: [
          _topBar(),
          _pathRow(),
          _progress(),
          Expanded(child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            SizedBox(width: 290, child: _sidebar()),
            const VerticalDivider(width: 1, color: PG.border),
            Expanded(child: Padding(
              padding: const EdgeInsets.fromLTRB(24, 18, 24, 12),
              child: AnimatedSwitcher(
                duration: const Duration(milliseconds: 240),
                switchInCurve: Curves.easeOutCubic, switchOutCurve: Curves.easeInCubic,
                transitionBuilder: (child, anim) {
                  // entering a section slides in from the right + fades; going back slides from the left.
                  final fromRight = child.key == const ValueKey('detail');
                  final begin = Offset(fromRight ? 0.06 : -0.06, 0);
                  return FadeTransition(opacity: anim,
                      child: SlideTransition(position: Tween(begin: begin, end: Offset.zero).animate(anim), child: child));
                },
                child: open == null
                    ? KeyedSubtree(key: const ValueKey('sections'),
                        child: SectionsView(onOpen: (s) => setState(() => open = s)))
                    : KeyedSubtree(key: const ValueKey('detail'),
                        child: PatchDetail(state: state, section: open!, onBack: () => setState(() => open = null))),
              ),
            )),
          ])),
          _bottomBar(),
        ]),
      ),
    );
  }

  // ---- top bar ----------------------------------------------------------------------------------
  Widget _topBar() => Container(
        padding: const EdgeInsets.fromLTRB(22, 16, 22, 6),
        child: Row(children: [
          SvgPicture.asset('assets/PatchgramLogo.svg', width: 28, height: 28,
              colorFilter: const ColorFilter.mode(Colors.white, BlendMode.srcIn)),
          const SizedBox(width: 10),
          Text('Patchgram', style: PG.t(22, w: FontWeight.w700)),
          const SizedBox(width: 8),
          MouseRegion(cursor: SystemMouseCursors.click, child: GestureDetector(
            onTap: _showSettings,
            child: Icon(Icons.settings_rounded, color: PG.textDim, size: 17))),
          const Spacer(),
          _pill(Icons.description_outlined, 'Logs', state.openLog),
          const SizedBox(width: 8),
          _pill(Icons.refresh_rounded, 'Rescan', state.load),
          const SizedBox(width: 8),
          _pill(Icons.folder_open_rounded, 'Choose App', state.chooseApp, primary: true),
        ]),
      );

  Widget _pathRow() => Padding(
        padding: const EdgeInsets.fromLTRB(22, 2, 22, 6),
        child: Row(children: [
          Icon(Icons.verified_rounded, color: state.telegramPath.isEmpty ? PG.textDim : PG.green, size: 18),
          const SizedBox(width: 8),
          Expanded(child: Text(state.telegramPath.isEmpty ? 'No app selected' : state.telegramPath,
              style: PG.t(14, color: PG.mono, mono: true), overflow: TextOverflow.ellipsis)),
        ]),
      );

  Widget _progress() => Padding(
        padding: const EdgeInsets.fromLTRB(22, 0, 22, 10),
        child: Row(children: [
          SizedBox(width: 520, child: ClipRRect(borderRadius: BorderRadius.circular(3),
              child: TweenAnimationBuilder<double>(
                tween: Tween(begin: 0, end: state.progress),
                duration: const Duration(milliseconds: 220), curve: Curves.easeOut,
                builder: (_, v, __) => LinearProgressIndicator(
                    value: state.applying ? v : 0.0,
                    minHeight: 4, backgroundColor: PG.card, color: PG.blue)))),
          const SizedBox(width: 14),
          Text(state.applying ? 'Working…'
                  : state.dirty ? 'Pending changes — press Apply to activate.'
                  : 'Patch ready. Runtime config applied live.',
              style: PG.t(12, color: PG.textDim)),
        ]),
      );

  // ---- sidebar ----------------------------------------------------------------------------------
  Widget _sidebar() => Container(
        color: PG.panel,
        padding: const EdgeInsets.fromLTRB(20, 16, 16, 16),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          _stat(Icons.terminal_rounded, 'Executable', _exeSize()),
          const SizedBox(height: 18),
          _stat(Icons.checklist_rounded, 'Enabled rules', '${state.enabledRules}'),
          const SizedBox(height: 18),
          _stat(Icons.move_to_inbox_rounded, 'Pending', state.dirty ? 'Yes' : 'No'),
          const _Div(),
          Row(children: [
            (state.iconPath.isNotEmpty && File(state.iconPath).existsSync())
                ? Image.file(File(state.iconPath), width: 20, height: 20, gaplessPlayback: true)
                : const Icon(Icons.send_rounded, color: PG.blue, size: 18),
            const SizedBox(width: 8),
            Text('Selected app', style: PG.t(14, w: FontWeight.w600))]),
          const SizedBox(height: 8),
          Text(state.telegramPath.isEmpty ? '—'
                  : '${state.productName}${state.productVersion.isEmpty ? '' : ' ${state.productVersion}'}',
              style: PG.t(13, color: PG.mono, mono: true)),
          const SizedBox(height: 6),
          Text('${state.availableCount} of ${state.totalCount} patches wired for this client version',
              style: PG.t(12, color: PG.green)),
          const SizedBox(height: 6),
          Text('The selected bundle must be writable before patching.', style: PG.t(12, color: PG.textDim)),
          const _Div(),
          Row(children: [const Icon(Icons.description_outlined, color: PG.text, size: 16), const SizedBox(width: 8),
            Text('Changed targets', style: PG.t(14, w: FontWeight.w600))]),
          const SizedBox(height: 6),
          Text(state.dirty ? 'Pending config write' : 'No changes', style: PG.t(13, color: PG.textDim)),
        ]),
      );

  Widget _stat(IconData i, String label, String value) => Row(children: [
        Icon(i, color: PG.blue, size: 22), const SizedBox(width: 10),
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label, style: PG.t(12, color: PG.textDim)),
          Text(value, style: PG.t(18, w: FontWeight.w700)),
        ]),
      ]);

  String _exeSize() {
    try {
      if (state.telegramPath.isEmpty) return '—';
      final mb = File(state.realExePath).lengthSync() / (1024 * 1024);  // the real client, not our launcher
      return '${mb.toStringAsFixed(1).replaceAll('.', ',')} MB';
    } catch (_) { return '—'; }
  }

  // ---- bottom bar -------------------------------------------------------------------------------
  Widget _bottomBar() => Container(
        decoration: const BoxDecoration(border: Border(top: BorderSide(color: PG.border))),
        padding: const EdgeInsets.fromLTRB(22, 10, 16, 10),
        child: Row(children: [
          Expanded(child: Text(state.status, style: PG.t(13, color: PG.textDim), overflow: TextOverflow.ellipsis)),
          _pill(Icons.info_outline_rounded, 'About', _showAbout),
          const SizedBox(width: 8),
          _pill(Icons.settings_backup_restore_rounded, 'Restore Backup', state.restoreBackup, enabled: state.canRestoreBackup),
          const SizedBox(width: 8),
          _pill(Icons.power_settings_new_rounded, 'Disable All', _confirmDisableAll, enabled: state.canDisableAll),
          const SizedBox(width: 8),
          _pill(Icons.check_circle_outline_rounded, 'Apply', state.apply, primary: true, enabled: state.canApply),
        ]),
      );

  Widget _pill(IconData icon, String label, VoidCallback onTap, {bool primary = false, bool enabled = true}) =>
      _PillButton(icon: icon, label: label, onTap: onTap, primary: primary, enabled: enabled);

  // ---- dialogs ----------------------------------------------------------------------------------
  void _dialog(String title, IconData icon, Widget body) => showDialog(
        context: context, barrierColor: Colors.black54,
        builder: (ctx) => Dialog(
          backgroundColor: PG.panel,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16), side: const BorderSide(color: PG.border)),
          child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 520),
            child: Padding(padding: const EdgeInsets.all(20), child: Column(mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [Icon(icon, color: PG.blue, size: 20), const SizedBox(width: 10),
                  Expanded(child: Text(title, style: PG.t(18, w: FontWeight.w700))),
                  _PillButton(icon: Icons.close_rounded, label: 'Close', onTap: () => Navigator.pop(ctx))]),
                const SizedBox(height: 14), body,
              ]))),
        ),
      );

  // Confirmation alert before disabling everything (mirrors the macOS "Disable all patches?" alert).
  void _confirmDisableAll() => showDialog(context: context, barrierColor: Colors.black54, builder: (ctx) => Dialog(
        backgroundColor: PG.panel,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16), side: const BorderSide(color: PG.border)),
        child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 420),
          child: Padding(padding: const EdgeInsets.all(22), child: Column(mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [const Icon(Icons.power_settings_new_rounded, color: PG.orange, size: 20),
                const SizedBox(width: 10), Text('Disable all patches?', style: PG.t(17, w: FontWeight.w700))]),
              const SizedBox(height: 10),
              Text('Are you sure? This turns off every patch and DLL injection, then restarts Telegram clean '
                  '(unpatched). Your chats are unaffected.', style: PG.t(13, color: PG.text.withOpacity(0.85))),
              const SizedBox(height: 18),
              Row(mainAxisAlignment: MainAxisAlignment.end, children: [
                _PillButton(icon: Icons.close_rounded, label: 'Cancel', onTap: () => Navigator.pop(ctx)),
                const SizedBox(width: 8),
                _PillButton(icon: Icons.power_settings_new_rounded, label: 'Disable All', primary: true,
                    onTap: () { Navigator.pop(ctx); state.disableAll(); }),
              ]),
            ])))),
      );

  void _showAbout() => _dialog('About Patchgram', Icons.info_outline_rounded, Center(child: Column(
        mainAxisSize: MainAxisSize.min, children: [
          const SizedBox(height: 4),
          SvgPicture.asset('assets/PatchgramLogo.svg', width: 76, height: 76,
              colorFilter: const ColorFilter.mode(Colors.white, BlendMode.srcIn)),
          const SizedBox(height: 14),
          Text('Patchgram for Windows', style: PG.t(20, w: FontWeight.w700)),
          const SizedBox(height: 4),
          Text('Telegram Desktop runtime patcher (Qt5 / x64)', style: PG.t(13, color: PG.textDim)),
          const SizedBox(height: 6),
          Text('Version ${AppState.appVersion} (${AppState.appBuild})', style: PG.t(12, color: PG.textDim, mono: true)),
          const SizedBox(height: 18),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            _linkBtn('assets/github.svg', 'GitHub', 'https://github.com/patchgram/win'),
            const SizedBox(width: 12),
            _linkBtn('assets/TelegramLogo.svg', 'Telegram', 'https://t.me/patchgram'),
          ]),
          const SizedBox(height: 4),
        ])));

  Widget _linkBtn(String svg, String label, String url) => _Hover((h) => GestureDetector(
        onTap: () => launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication),
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
          decoration: BoxDecoration(color: h ? PG.cardHi : PG.card, borderRadius: BorderRadius.circular(9),
              border: Border.all(color: PG.border)),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            SvgPicture.asset(svg, width: 16, height: 16,
                colorFilter: const ColorFilter.mode(Colors.white, BlendMode.srcIn)),
            const SizedBox(width: 8), Text(label, style: PG.t(13, w: FontWeight.w600)),
          ]),
        ),
      ));

  void _showSettings() => showDialog(context: context, barrierColor: Colors.black54, builder: (ctx) =>
      StatefulBuilder(builder: (ctx, setLocal) => Dialog(
        backgroundColor: PG.panel,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16), side: const BorderSide(color: PG.border)),
        child: ConstrainedBox(constraints: const BoxConstraints(maxWidth: 540),
          child: Padding(padding: const EdgeInsets.all(20), child: Column(mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [const Icon(Icons.settings_rounded, color: PG.blue, size: 20), const SizedBox(width: 10),
                Expanded(child: Text('Settings', style: PG.t(18, w: FontWeight.w700))),
                _PillButton(icon: Icons.close_rounded, label: 'Close', onTap: () => Navigator.pop(ctx))]),
              const SizedBox(height: 16),
              Text('UPDATES', style: PG.t(11, color: PG.textDim, w: FontWeight.w700)),
              const SizedBox(height: 8),
              Row(children: [
                Expanded(child: Text('Check for updates on launch', style: PG.t(14))),
                Switch(value: state.autoCheckUpdates, activeColor: PG.blue,
                    onChanged: (v) { state.setAutoCheck(v); setLocal(() {}); }),
              ]),
              const SizedBox(height: 8),
              _PillButton(icon: Icons.system_update_alt_rounded, label: 'Check for updates now',
                  onTap: () { state.checkForUpdates(); }),
            ])))),
      ));
}

class _Div extends StatelessWidget {
  const _Div();
  @override
  Widget build(BuildContext c) => const Padding(
      padding: EdgeInsets.symmetric(vertical: 16), child: Divider(color: PG.border, height: 1));
}

class _Hover extends StatefulWidget {
  final Widget Function(bool) builder;
  const _Hover(this.builder);
  @override
  State<_Hover> createState() => _HoverState();
}

class _HoverState extends State<_Hover> {
  bool h = false;
  @override
  Widget build(BuildContext c) => MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => h = true),
        onExit: (_) => setState(() => h = false),
        child: widget.builder(h));
}

class _PillButton extends StatefulWidget {
  final IconData icon; final String label; final VoidCallback onTap; final bool primary; final bool enabled;
  const _PillButton({required this.icon, required this.label, required this.onTap, this.primary = false, this.enabled = true});
  @override
  State<_PillButton> createState() => _PillButtonState();
}

class _PillButtonState extends State<_PillButton> {
  bool hover = false;
  @override
  Widget build(BuildContext context) {
    final on = widget.enabled;
    final bg = !on ? PG.window : widget.primary ? PG.blue : (hover ? PG.cardHi : PG.card);
    final fg = !on ? PG.textDim.withOpacity(0.5) : widget.primary ? Colors.white : PG.text;
    final border = !on ? PG.border : (widget.primary ? PG.blue : PG.border);
    return MouseRegion(
      cursor: on ? SystemMouseCursors.click : SystemMouseCursors.basic,
      onEnter: (_) { if (on) setState(() => hover = true); },
      onExit: (_) => setState(() => hover = false),
      child: GestureDetector(
        onTap: on ? widget.onTap : null,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 9),
          decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(9), border: Border.all(color: border)),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Icon(widget.icon, size: 15, color: fg), const SizedBox(width: 7),
            Text(widget.label, style: PG.t(13, color: fg, w: FontWeight.w600)),
          ]),
        ),
      ),
    );
  }
}
