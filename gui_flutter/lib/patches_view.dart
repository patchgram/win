import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';
import 'theme.dart';
import 'models.dart';
import 'app_state.dart';
import 'settings_modals.dart';

/// A section's white-line SVG inside the blue gradient tile (matches the macOS SectionIcon).
Widget sectionTile(String icon, double size, double inset) => Container(
      width: size, height: size,
      decoration: BoxDecoration(gradient: const LinearGradient(colors: [Color(0xFF0A84FF), Color(0xFF0066CC)]),
          borderRadius: BorderRadius.circular(size * 0.23)),
      child: Padding(padding: EdgeInsets.all(inset),
          child: SvgPicture.asset('assets/section-$icon.svg',
              colorFilter: const ColorFilter.mode(Colors.white, BlendMode.srcIn))),
    );

/// Sections list (the landing grid in the macOS app).
class SectionsView extends StatelessWidget {
  final void Function(Section) onOpen;
  const SectionsView({super.key, required this.onOpen});
  @override
  Widget build(BuildContext context) {
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        const Icon(Icons.grid_view_rounded, size: 18, color: PG.text), const SizedBox(width: 8),
        Text('Patches', style: PG.t(17, w: FontWeight.w700)),
      ]),
      const SizedBox(height: 14),
      Expanded(child: ListView.separated(
        itemCount: catalog.length,
        separatorBuilder: (_, __) => const SizedBox(height: 12),
        itemBuilder: (_, i) => _sectionRow(catalog[i]),
      )),
    ]);
  }

  Widget _sectionRow(Section s) => _Hoverable(builder: (hover) => GestureDetector(
        onTap: () => onOpen(s),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(color: hover ? PG.cardHi : PG.card,
              borderRadius: BorderRadius.circular(12), border: Border.all(color: PG.border)),
          child: Row(children: [
            sectionTile(s.icon, 48, 11),
            const SizedBox(width: 16),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(s.title, style: PG.t(17, w: FontWeight.w700)),
              const SizedBox(height: 3),
              Text(s.subtitle, style: PG.t(13, color: PG.textDim)),
            ])),
            Text('${s.patches.length}', style: PG.t(15, color: PG.textDim)),
            const SizedBox(width: 8),
            const Icon(Icons.chevron_right_rounded, color: PG.textDim),
          ]),
        ),
      ));
}

class PatchDetail extends StatefulWidget {
  final AppState state; final Section section; final VoidCallback onBack;
  const PatchDetail({super.key, required this.state, required this.section, required this.onBack});
  @override
  State<PatchDetail> createState() => _PatchDetailState();
}

class _PatchDetailState extends State<PatchDetail> {
  String query = '';
  PatchType? typeFilter; // null = all
  int sort = 0; // 0 default, 1 A-Z, 2 Z-A
  bool filtersOpen = false;

  @override
  Widget build(BuildContext context) {
    var items = widget.section.patches.where((p) {
      final q = query.toLowerCase();
      final hit = q.isEmpty || p.title.toLowerCase().contains(q) || p.subtitle.toLowerCase().contains(q);
      final tf = typeFilter == null || p.type == typeFilter;
      return hit && tf;
    }).toList();
    if (sort == 1) items.sort((a, b) => a.title.compareTo(b.title));
    if (sort == 2) items.sort((a, b) => b.title.compareTo(a.title));

    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        _chip(Icons.chevron_left_rounded, 'Sections', widget.onBack),
        const SizedBox(width: 12),
        sectionTile(widget.section.icon, 26, 6),
        const SizedBox(width: 8),
        Text(widget.section.title, style: PG.t(16, w: FontWeight.w700)),
        const SizedBox(width: 14),
        Expanded(child: _search()),
        const SizedBox(width: 10),
        _chip(Icons.filter_list_rounded, 'Filters', () => setState(() => filtersOpen = !filtersOpen)),
      ]),
      const SizedBox(height: 14),
      Expanded(child: Stack(children: [
        ListView.separated(
          itemCount: items.length,
          separatorBuilder: (_, __) => const SizedBox(height: 12),
          itemBuilder: (_, i) => PatchCard(state: widget.state, patch: items[i]),
        ),
        if (filtersOpen) Positioned(right: 0, top: 0, child: _filtersPopover()),
      ])),
    ]);
  }

  Widget _search() => Container(
        height: 36,
        decoration: BoxDecoration(color: PG.card, borderRadius: BorderRadius.circular(9), border: Border.all(color: PG.border)),
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Center(child: TextField(
          style: PG.t(13), cursorColor: PG.blue,
          decoration: InputDecoration(isDense: true, border: InputBorder.none,
              hintText: 'Search method or constructor', hintStyle: PG.t(13, color: PG.textDim)),
          onChanged: (v) => setState(() => query = v),
        )),
      );

  Widget _chip(IconData i, String t, VoidCallback onTap) => _Hoverable(builder: (h) => GestureDetector(
        onTap: onTap,
        child: Container(padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          decoration: BoxDecoration(color: h ? PG.cardHi : PG.card, borderRadius: BorderRadius.circular(9), border: Border.all(color: PG.border)),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            Icon(i, size: 15, color: PG.text), const SizedBox(width: 6), Text(t, style: PG.t(13, w: FontWeight.w600))])),
      ));

  Widget _filtersPopover() => Container(
        width: 320, padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: PG.cardHi, borderRadius: BorderRadius.circular(12),
            border: Border.all(color: PG.border), boxShadow: const [BoxShadow(color: Colors.black54, blurRadius: 24)]),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          Text('Type', style: PG.t(12, color: PG.textDim)), const SizedBox(height: 6),
          _seg(['All', 'dll', 'binary'], typeFilter == null ? 0 : (typeFilter == PatchType.dylib ? 1 : 2),
              (i) => setState(() => typeFilter = i == 0 ? null : (i == 1 ? PatchType.dylib : PatchType.binary))),
          const SizedBox(height: 14),
          Text('Sort', style: PG.t(12, color: PG.textDim)), const SizedBox(height: 6),
          _seg(['Default', 'A-Z', 'Z-A'], sort, (i) => setState(() => sort = i)),
        ]),
      );

  Widget _seg(List<String> labels, int sel, void Function(int) onSel) => Container(
        decoration: BoxDecoration(color: PG.window, borderRadius: BorderRadius.circular(8)),
        padding: const EdgeInsets.all(3),
        child: Row(children: [
          for (var i = 0; i < labels.length; i++)
            Expanded(child: GestureDetector(onTap: () => onSel(i), child: Container(
              padding: const EdgeInsets.symmetric(vertical: 7), alignment: Alignment.center,
              decoration: BoxDecoration(color: sel == i ? PG.blue : Colors.transparent, borderRadius: BorderRadius.circular(6)),
              child: Text(labels[i], style: PG.t(12, color: sel == i ? Colors.white : PG.text, w: FontWeight.w600))))),
        ]),
      );
}

class PatchCard extends StatefulWidget {
  final AppState state; final Patch patch;
  const PatchCard({super.key, required this.state, required this.patch});
  @override
  State<PatchCard> createState() => _PatchCardState();
}

class _PatchCardState extends State<PatchCard> {
  bool subsOpen = false;
  @override
  Widget build(BuildContext context) {
    final p = widget.patch; final st = widget.state;
    final enabled = st.patchOn(p);
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(color: PG.card, borderRadius: BorderRadius.circular(12), border: Border.all(color: PG.border)),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Expanded(child: Wrap(spacing: 8, runSpacing: 6, crossAxisAlignment: WrapCrossAlignment.center, children: [
            Text(p.title, style: PG.t(16, w: FontWeight.w700)),
            _Badge(p.available ? 'Available' : 'Needs RE', p.available ? PG.green : PG.textDim),
            _Badge(p.type.label, p.type == PatchType.dylib ? PG.purple : PG.orange),
            if (p.keys.isNotEmpty || p.subs.isNotEmpty) _Badge(enabled ? 'Enabled' : 'Disabled', enabled ? PG.green : PG.textDim),
          ])),
          if (p.settings != Settings.none) ...[
            _settingsBtn(), const SizedBox(width: 10),
          ],
          Switch(value: enabled, activeColor: PG.blue,
              onChanged: st.canToggle(p) ? (v) => st.setPatch(p, v) : null),
        ]),
        const SizedBox(height: 6),
        Text(p.subtitle, style: PG.t(12, color: PG.mono, mono: true)),
        const SizedBox(height: 8),
        Text(p.desc, style: PG.t(13, color: PG.text.withOpacity(0.85))),
        if (p.subs.isNotEmpty) ...[
          const SizedBox(height: 12), const Divider(color: PG.border, height: 1), const SizedBox(height: 8),
          MouseRegion(cursor: SystemMouseCursors.click, child: GestureDetector(
            onTap: () => setState(() => subsOpen = !subsOpen), child: Row(children: [
              AnimatedRotation(turns: subsOpen ? 0.25 : 0, duration: const Duration(milliseconds: 200),
                  child: const Icon(Icons.chevron_right_rounded, color: PG.textDim, size: 18)),
              const SizedBox(width: 4),
              Text('Subpatches', style: PG.t(14, w: FontWeight.w600)),
              const SizedBox(width: 8),
              Text('${p.subs.where((s) => s.key.isNotEmpty && st.boolKey(s.key)).length}/${p.subs.length} subpatches',
                  style: PG.t(12, color: PG.textDim)),
            ]))),
          AnimatedSize(duration: const Duration(milliseconds: 220), curve: Curves.easeInOut,
            alignment: Alignment.topCenter,
            child: ClipRect(child: Align(alignment: Alignment.topCenter, heightFactor: subsOpen ? 1 : 0,
              child: Column(children: p.subs.map((s) => Padding(
                padding: const EdgeInsets.only(top: 8),
                child: Row(children: [
                  Expanded(child: Text(s.title, style: PG.t(14, color: s.key.isEmpty ? PG.textDim : PG.text))),
                  if (s.settings != Settings.none) ...[
                    _subSettingsBtn(s), const SizedBox(width: 10),
                  ],
                  Switch(value: s.key.isNotEmpty && st.boolKey(s.key), activeColor: PG.blue,
                      onChanged: s.key.isEmpty ? null : (v) => st.setSubpatch(p, s.key, v)),
                ]))).toList())))),
        ],
      ]),
    );
  }

  Widget _settingsBtn() => _Hoverable(builder: (h) => GestureDetector(
        onTap: () => openSettings(context, widget.state, widget.patch.settings),
        child: Container(padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
          decoration: BoxDecoration(color: h ? PG.cardHi : PG.window, borderRadius: BorderRadius.circular(8), border: Border.all(color: PG.border)),
          child: Row(mainAxisSize: MainAxisSize.min, children: [
            const Icon(Icons.settings_rounded, size: 14, color: PG.text), const SizedBox(width: 6),
            Text('Settings', style: PG.t(13, w: FontWeight.w600))])),
      ));

  // Compact gear shown next to a subpatch's Switch when the subpatch carries its own settings modal.
  Widget _subSettingsBtn(Subpatch s) => _Hoverable(builder: (h) => GestureDetector(
        onTap: () => openSettings(context, widget.state, s.settings),
        child: Container(padding: const EdgeInsets.all(7),
          decoration: BoxDecoration(color: h ? PG.cardHi : PG.window, borderRadius: BorderRadius.circular(8), border: Border.all(color: PG.border)),
          child: const Icon(Icons.settings_rounded, size: 14, color: PG.text)),
      ));
}

class _Badge extends StatelessWidget {
  final String text; final Color color;
  const _Badge(this.text, this.color);
  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(color: color.withOpacity(0.16), borderRadius: BorderRadius.circular(6)),
        child: Text(text, style: PG.t(11, color: color, w: FontWeight.w700)),
      );
}

class _Hoverable extends StatefulWidget {
  final Widget Function(bool hover) builder;
  const _Hoverable({required this.builder});
  @override
  State<_Hoverable> createState() => _HoverableState();
}

class _HoverableState extends State<_Hoverable> {
  bool hover = false;
  @override
  Widget build(BuildContext context) => MouseRegion(
        cursor: SystemMouseCursors.click,
        onEnter: (_) => setState(() => hover = true),
        onExit: (_) => setState(() => hover = false),
        child: widget.builder(hover),
      );
}
