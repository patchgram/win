import 'dart:convert';
import 'package:flutter/material.dart';
import 'theme.dart';
import 'models.dart';
import 'app_state.dart';
import 'gift_api.dart';

void openSettings(BuildContext context, AppState state, Settings kind) {
  showDialog(context: context, barrierColor: Colors.black54, builder: (_) => switch (kind) {
        Settings.giftSpoof => _GiftSpoofModal(state: state),
        Settings.giftSpoofUnique => _GiftUniqueModal(state: state),
        Settings.customStars => _CustomStarsModal(state: state),
        Settings.customTon => _CustomTonModal(state: state),
        Settings.customLevelRating => _CustomLevelRatingModal(state: state),
        Settings.peerBadge => _PeerBadgeModal(state: state),
        Settings.botVerification => _BotVerificationModal(state: state),
        Settings.customPhone => _CustomPhoneModal(state: state),
        Settings.customUserId => _CustomUserIdModal(state: state),
        Settings.localChannel => _LocalChannelModal(state: state),
        Settings.fragmentPhone => _FragmentPhoneModal(state: state),
        Settings.customUsernames => _CustomUsernamesModal(state: state),
        Settings.factCheck => _FactCheckModal(state: state),
        Settings.none => const SizedBox.shrink(),
      });
}

/// Target-mode picker shared by several account-customization modals (matches the macOS
/// BotVerificationTargetMode: All / All except me / Only me, persisted as the canonical strings).
const _targetModeLabels = ['All', 'All except me', 'Only me'];
const _targetModeKeys = ['all', 'allExceptSelf', 'onlySelf'];
int _targetModeIndex(String s) { final i = _targetModeKeys.indexOf(s); return i < 0 ? 0 : i; }

/// Standard Save / Save & Apply / Cancel actions for the settings modals: `commit` writes cfg. When
/// `enableKey` is given (a togglable subpatch), Save/Apply also flip that key on so the subpatch switch
/// turns on — otherwise saving settings would leave the toggle off (looks like nothing happened).
List<Widget> _saveActions(BuildContext context, AppState state, void Function() commit, {String enableKey = ''}) {
      void go(bool apply) {
        commit();
        // Turn the subpatch on (via setBool so it notifies) — leaving the change STAGED. "Save" used to
        // call state.save(), which rewrites the config AND resets the applied-snapshot, so the main Apply
        // button immediately greyed out (the reported bug). Now Save only stages: Apply lights up, exactly
        // like toggling the patch in the list; "Save & Apply" persists + (re)injects in one step.
        if (enableKey.isNotEmpty) { state.setBool(enableKey, true); state.setBool('dllInjectionEnabled', true); }
        if (apply) state.apply();
        Navigator.pop(context);
      }
      return [
        _action('Save', Icons.check_rounded, () => go(false)),
        _action('Save & Apply', Icons.bolt_rounded, () => go(true), primary: true),
        _action('Cancel', Icons.close_rounded, () => Navigator.pop(context)),
      ];
    }

/// A labelled dropdown styled to match the modal fields.
Widget _dropdown<T>(T value, List<DropdownMenuItem<T>> items, void Function(T?) onChanged) => Container(
      decoration: BoxDecoration(color: PG.window, borderRadius: BorderRadius.circular(8), border: Border.all(color: PG.border)),
      padding: const EdgeInsets.symmetric(horizontal: 12),
      child: DropdownButtonHideUnderline(child: DropdownButton<T>(
        value: value, isExpanded: true, isDense: true, dropdownColor: PG.card,
        style: PG.t(14), iconEnabledColor: PG.textDim,
        items: items, onChanged: onChanged)),
    );

DropdownMenuItem<int> _dItem(int v, String label) =>
    DropdownMenuItem(value: v, child: Text(label, style: PG.t(14)));

Widget _intRow(TextEditingController c, {String? hint}) => _field(c, hint: hint);

int _parseInt(String s, int fallback, {int min = 0, int? max}) {
  final v = int.tryParse(s.trim());
  if (v == null) return fallback;
  if (v < min) return min;
  if (max != null && v > max) return max;
  return v;
}

class _Shell extends StatelessWidget {
  final String title; final IconData icon; final List<Widget> actions; final Widget body;
  const _Shell({required this.title, required this.icon, required this.actions, required this.body});
  @override
  Widget build(BuildContext context) => Dialog(
        backgroundColor: PG.panel, insetPadding: const EdgeInsets.all(40),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16), side: const BorderSide(color: PG.border)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 640, maxHeight: 720),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Padding(padding: const EdgeInsets.fromLTRB(20, 16, 16, 12), child: Row(children: [
              Icon(icon, color: PG.blue, size: 20), const SizedBox(width: 10),
              Expanded(child: Text(title, style: PG.t(18, w: FontWeight.w700))),
              ...actions,
            ])),
            const Divider(color: PG.border, height: 1),
            Flexible(child: SingleChildScrollView(padding: const EdgeInsets.all(20), child: body)),
          ]),
        ),
      );
}

Widget _action(String t, IconData i, VoidCallback onTap, {bool primary = false}) => Padding(
      padding: const EdgeInsets.only(left: 8),
      child: GestureDetector(onTap: onTap, child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        decoration: BoxDecoration(color: primary ? PG.blue : PG.card, borderRadius: BorderRadius.circular(9),
            border: Border.all(color: primary ? PG.blue : PG.border)),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(i, size: 15, color: primary ? Colors.white : PG.text), const SizedBox(width: 6),
          Text(t, style: PG.t(13, color: primary ? Colors.white : PG.text, w: FontWeight.w600))]))));

Widget _label(String t) => Padding(padding: const EdgeInsets.only(bottom: 6, top: 14), child: Text(t, style: PG.t(13, w: FontWeight.w600)));

// A macOS-style checkbox + trailing label row (used by the gift modals' Badges section).
Widget _check(String label, bool value, void Function(bool) onChanged) => Padding(
      padding: const EdgeInsets.only(top: 6),
      child: Row(children: [
        Checkbox(value: value, activeColor: PG.blue, onChanged: (v) => onChanged(v ?? false)),
        Text(label, style: PG.t(14)),
      ]));

Widget _field(TextEditingController c, {String? hint}) => Container(
      decoration: BoxDecoration(color: PG.window, borderRadius: BorderRadius.circular(8), border: Border.all(color: PG.border)),
      padding: const EdgeInsets.symmetric(horizontal: 12),
      child: TextField(controller: c, style: PG.t(14, mono: true), cursorColor: PG.blue,
          decoration: InputDecoration(isDense: true, border: InputBorder.none, contentPadding: const EdgeInsets.symmetric(vertical: 11),
              hintText: hint, hintStyle: PG.t(13, color: PG.textDim))));

Widget _seg(List<String> labels, int sel, void Function(int) onSel) => Container(
      decoration: BoxDecoration(color: PG.window, borderRadius: BorderRadius.circular(8)), padding: const EdgeInsets.all(3),
      child: Row(children: [
        for (var i = 0; i < labels.length; i++)
          Expanded(child: GestureDetector(onTap: () => onSel(i), child: Container(
            padding: const EdgeInsets.symmetric(vertical: 9), alignment: Alignment.center,
            decoration: BoxDecoration(color: sel == i ? PG.blue : Colors.transparent, borderRadius: BorderRadius.circular(6)),
            child: Text(labels[i], style: PG.t(13, color: sel == i ? Colors.white : PG.text, w: FontWeight.w600))))),
      ]));

// ---- Gift spoof ---------------------------------------------------------------------------------
class _GiftSpoofModal extends StatefulWidget {
  final AppState state;
  const _GiftSpoofModal({required this.state});
  @override
  State<_GiftSpoofModal> createState() => _GiftSpoofModalState();
}

class _GiftSpoofModalState extends State<_GiftSpoofModal> {
  // sender + date are TEXT (Bot-API id / unix or "HH:mm:ss dd.MM.yyyy"); the rest are numeric.
  late final sender = TextEditingController(text: _initSender());
  late final date = TextEditingController(text: _initDate());
  late final c = <String, TextEditingController>{
    for (final k in ['giftSpoofGiftId', 'giftSpoofStickerId', 'giftSpoofStars', 'giftSpoofConvertStars',
      'giftSpoofAvailable', 'giftSpoofTotal', 'giftSpoofGiftNum'])
      k: TextEditingController(text: '${widget.state.intKey(k)}'),
  };
  bool limited = false, refunded = false;
  bool forceUpgrade = false, forceAuction = false;
  late int target = _targetModeIndex(widget.state.strKeyOr('giftSpoofTargetMode', 'onlySelf'));
  late final caption = TextEditingController(text: widget.state.strKeyOr('giftSpoofCaption', ''));
  late final upgradePrice = TextEditingController(text: '${widget.state.intKey('giftSpoofUpgradePrice')}');
  late final auctionTitle = TextEditingController(text: widget.state.strKeyOr('giftSpoofAuctionTitle', ''));
  bool resolving = false; String stickerNote = '';

  Future<void> _getIdFromGift() async {
    setState(() { resolving = true; stickerNote = ''; });
    final id = await GiftApi.resolveStickerEmojiId(c['giftSpoofGiftId']!.text);
    setState(() {
      resolving = false;
      if (id != null) { c['giftSpoofStickerId']!.text = '$id'; stickerNote = ''; }
      else { stickerNote = 'No emoji for that gift id on the API.'; }
    });
  }

  String _initSender() {
    final raw = widget.state.strKey('giftSpoofSenderText');
    if (raw.isNotEmpty) return raw;
    final id = widget.state.intKey('giftSpoofSenderId');
    return id == 0 ? '0' : '$id';
  }
  String _initDate() {
    final raw = widget.state.strKey('giftSpoofDateText');
    if (raw.isNotEmpty) return raw;
    final d = widget.state.intKey('giftSpoofDate');
    return d == 0 ? '0' : '$d';
  }

  @override
  void initState() {
    super.initState();
    limited = widget.state.boolKey('giftSpoofLimited');
    refunded = widget.state.boolKey('giftSpoofWasRefunded');
    forceUpgrade = widget.state.boolKey('giftSpoofUpgrade');
    forceAuction = widget.state.boolKey('giftSpoofAuction');
  }
  void _commit() {
    final s = widget.state;
    final (sid, stype) = AppState.parseSenderId(sender.text);
    s.setStr('giftSpoofSenderText', sender.text.trim());
    s.setInt('giftSpoofSenderId', sid);
    s.setInt('giftSpoofSenderPeerType', stype);
    s.setStr('giftSpoofDateText', date.text.trim());
    s.setInt('giftSpoofDate', AppState.parseDateUnix(date.text));
    c.forEach((k, v) => s.setInt(k, int.tryParse(v.text.trim()) ?? 0));
    s.setBool('giftSpoofLimited', limited);
    s.setBool('giftSpoofWasRefunded', refunded);
    s.setStr('giftSpoofTargetMode', _targetModeKeys[target]);
    s.setStr('giftSpoofCaption', caption.text);
    s.setBool('giftSpoofUpgrade', forceUpgrade);
    s.setInt('giftSpoofUpgradePrice', int.tryParse(upgradePrice.text.trim()) ?? 0);
    s.setBool('giftSpoofAuction', forceAuction);
    s.setStr('giftSpoofAuctionTitle', auctionTitle.text);
    s.setBool('giftSpoofEnabled', true);
    s.setBool('dllInjectionEnabled', true);   // gift spoof runs through the DLL
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Spoof Profile Gifts', icon: Icons.auto_awesome_rounded,
        actions: [
          _action('Save', Icons.check_rounded, () { _commit(); Navigator.pop(context); }),   // stage → Apply lights up
          _action('Save & Apply', Icons.bolt_rounded, () { _commit(); widget.state.apply(); Navigator.pop(context); }, primary: true),
          _action('Cancel', Icons.close_rounded, () => Navigator.pop(context)),
        ],
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Rewrite the star gifts shown on a profile. Leave a numeric field at 0 to keep the original '
              'value; an empty caption keeps the original message. "Save & Apply" updates a running Telegram '
              'live — re-open the profile to refresh.', style: PG.t(13, color: PG.textDim)),
          _label('Whose profile'),
          _seg(_targetModeLabels, target, (i) => setState(() => target = i)),
          _label('Sender id'), _field(sender, hint: '0 = keep · user id · -100… = channel'),
          _label('Date'), _field(date, hint: '0 = keep · unix · HH:mm:ss dd.MM.yyyy'),
          _label('Gift id'), _field(c['giftSpoofGiftId']!, hint: '0 = keep original id'),
          _label('Sticker emoji id'),
          Row(children: [
            Expanded(child: _field(c['giftSpoofStickerId']!, hint: 'required — the gift\'s custom emoji id')),
            const SizedBox(width: 8),
            _action(resolving ? 'Looking up…' : 'Get id from gift', Icons.search_rounded,
                resolving ? () {} : _getIdFromGift),
          ]),
          Padding(padding: const EdgeInsets.only(top: 6), child: Text(
              stickerNote.isNotEmpty ? stickerNote
                  : 'Required to apply. Use an animated (TGS/WEBM) custom emoji so it renders inside the gift, '
                    'not just in the list. "Get id from gift" resolves it from the Gift id.',
              style: PG.t(12, color: stickerNote.isNotEmpty ? PG.orange : PG.textDim))),
          _label('Stars price'), _field(c['giftSpoofStars']!, hint: '0 = keep original price'),
          _label('Convert (Stars)'), _field(c['giftSpoofConvertStars']!, hint: '0 = keep · the "convert to N Stars" value'),
          _label('Badges'),
          _check('Limited', limited, (v) => setState(() => limited = v)),
          if (limited) Padding(padding: const EdgeInsets.only(left: 20), child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Supply available'), _field(c['giftSpoofAvailable']!, hint: 'availability_remains (0 = sold out)')])),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Supply total'), _field(c['giftSpoofTotal']!, hint: 'availability_total')])),
          ])),
          _check('Can upgrade', forceUpgrade, (v) => setState(() => forceUpgrade = v)),
          if (forceUpgrade) Padding(padding: const EdgeInsets.only(left: 20),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                _label('Upgrade price'), _field(upgradePrice, hint: '0 = default (25⭐) · upgrade_stars')])),
          _check('Auction', forceAuction, (v) => setState(() => forceAuction = v)),
          if (forceAuction) Padding(padding: const EdgeInsets.only(left: 20),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                _label('Auction title'), _field(auctionTitle, hint: 'gift name (starGift.title)'),
                _label('Gift number'), _field(c['giftSpoofGiftNum']!, hint: '0 = none · savedStarGift.gift_num')])),
          _check('Was refunded', refunded, (v) => setState(() => refunded = v)),
          Padding(padding: const EdgeInsets.only(top: 8), child: Text(
              'Supply lives under Limited and is written exactly as entered. Badges/caption make room by clearing '
              'the sticker preview; if a gift can\'t fit, that gift is left unchanged (no crash).',
              style: PG.t(12, color: PG.textDim))),
          _label('Caption'), _field(caption, hint: 'Empty = keep original message'),
          Padding(padding: const EdgeInsets.only(top: 6), child: Text(
              'Adding a caption clears the sticker preview to free room, and only applies when it fits the existing response.',
              style: PG.t(12, color: PG.textDim))),
          const SizedBox(height: 16),
          Text(GiftApi.attribution, style: PG.t(11, color: PG.textDim)),
        ]),
      );
}

// ---- Spoof profile UNIQUE gifts -----------------------------------------------------------------
// GUI parity with the macOS unique-gift window. Saves giftUnique* config keys; the engine unique-rebuild
// (realloc/RE tier) is the deferred functional half, so this configures-ahead.
class _GiftUniqueModal extends StatefulWidget {
  final AppState state;
  const _GiftUniqueModal({required this.state});
  @override
  State<_GiftUniqueModal> createState() => _GiftUniqueModalState();
}

class _GiftUniqueModalState extends State<_GiftUniqueModal> {
  late int target = _targetModeIndex(widget.state.strKeyOr('giftUniqueTargetMode', 'onlySelf'));
  late final t = <String, TextEditingController>{
    for (final k in ['giftUniqueName', 'giftUniqueTitle', 'giftUniqueModelName', 'giftUniqueModelEmojiId',
      'giftUniqueSymbolName', 'giftUniqueSymbolEmojiId', 'giftUniqueBackdropName', 'giftUniqueSender',
      'giftUniqueOwner', 'giftUniqueHost', 'giftUniqueOwnerAddress', 'giftUniqueDate', 'giftUniqueValueCurrency',
      'giftUniqueLastResaleCurrency'])
      k: TextEditingController(text: widget.state.strKeyOr(k,
          (k == 'giftUniqueValueCurrency' || k == 'giftUniqueLastResaleCurrency') ? 'TON' : '')),
  };
  late final n = <String, TextEditingController>{
    for (final k in ['giftUniqueNum', 'giftUniqueIssued', 'giftUniqueTotal', 'giftUniqueValueAmount',
      'giftUniqueValueUsdAmount', 'giftUniqueModelRarity', 'giftUniqueSymbolRarity', 'giftUniqueBackdropRarity',
      'giftUniqueLastResaleAmount', 'giftUniqueLastResaleDate'])
      k: TextEditingController(text: '${widget.state.intKey(k)}'),
  };
  // Backdrop colors stored as raw RGB ints in the engine keys; edited here as #RRGGBB hex.
  late final col = <String, TextEditingController>{
    for (final k in ['giftUniqueBackdropCenter', 'giftUniqueBackdropEdge', 'giftUniqueBackdropPattern', 'giftUniqueBackdropText'])
      k: TextEditingController(text: _hex(widget.state.intKey(k))),
  };
  static String _hex(int v) => v == 0 ? '' : '#${(v & 0xFFFFFF).toRadixString(16).padLeft(6, '0')}';
  static int _parseColor(String s) {
    s = s.trim().replaceFirst('#', '');
    if (s.isEmpty) return 0;
    return int.tryParse(s, radix: 16) ?? 0;
  }

  void _commit() {
    final s = widget.state;
    s.setStr('giftUniqueTargetMode', _targetModeKeys[target]);
    t.forEach((k, v) => s.setStr(k, v.text.trim()));
    n.forEach((k, v) => s.setInt(k, int.tryParse(v.text.trim()) ?? 0));
    col.forEach((k, v) => s.setInt(k, _parseColor(v.text)));
    // Map the GUI supply fields onto the engine keys (availability_issued / availability_total).
    s.setInt('giftUniqueTotalUpgraded', _parseInt(n['giftUniqueIssued']!.text, 0));
    s.setInt('giftUniqueMaxUpgraded', _parseInt(n['giftUniqueTotal']!.text, 0));
    // Owner / Host: parse the Bot-API id into the engine's peer id + peer type.
    final (oid, otype) = AppState.parseSenderId(t['giftUniqueOwner']!.text);
    s.setInt('giftUniqueOwnerId', oid); s.setInt('giftUniqueOwnerPeerType', otype);
    final (hid, htype) = AppState.parseSenderId(t['giftUniqueHost']!.text);
    s.setInt('giftUniqueHostId', hid); s.setInt('giftUniqueHostPeerType', htype);
  }

  // ---- live gift catalog (GiftChanges API — the same source the Spoof-Gifts "Get id" button uses) ----
  List<String> _giftNames = [];
  List<GiftAttr> _models = [], _symbols = [];
  List<GiftBackdrop> _backdrops = [];
  bool _loading = false;
  String _apiNote = '';

  @override
  void initState() {
    super.initState();
    _loadNames();
  }
  Future<void> _loadNames({bool refresh = false}) async {
    setState(() { _loading = true; _apiNote = ''; });
    final names = await GiftApi.giftNames(refresh: refresh);
    if (!mounted) return;
    setState(() { _giftNames = names; _loading = false; _apiNote = names.isEmpty ? 'Could not reach the gift API.' : ''; });
    final g = t['giftUniqueName']!.text.trim();
    if (g.isNotEmpty && g != '__empty__') _loadCatalog(g);
  }
  Future<void> _loadCatalog(String gift) async {
    setState(() => _loading = true);
    final ms = await GiftApi.modelsAndSymbols(gift);
    final bd = await GiftApi.backdrops(gift);
    if (!mounted) return;
    setState(() { _models = ms.$1; _symbols = ms.$2; _backdrops = bd; _loading = false; });
  }
  void _pickModel(GiftAttr a) => setState(() {
    t['giftUniqueModelName']!.text = a.name;
    t['giftUniqueModelEmojiId']!.text = a.emojiId == 0 ? '' : '${a.emojiId}';
    n['giftUniqueModelRarity']!.text = '${a.rarityPermille}';
  });
  void _pickSymbol(GiftAttr a) => setState(() {
    t['giftUniqueSymbolName']!.text = a.name;
    t['giftUniqueSymbolEmojiId']!.text = a.emojiId == 0 ? '' : '${a.emojiId}';
    n['giftUniqueSymbolRarity']!.text = '${a.rarityPermille}';
  });
  void _pickBackdrop(GiftBackdrop b) => setState(() {
    t['giftUniqueBackdropName']!.text = b.name;
    col['giftUniqueBackdropCenter']!.text = _hex(b.center);
    col['giftUniqueBackdropEdge']!.text = _hex(b.edge);
    col['giftUniqueBackdropPattern']!.text = _hex(b.pattern);
    col['giftUniqueBackdropText']!.text = _hex(b.text);
    n['giftUniqueBackdropRarity']!.text = '${b.rarityPermille}';
  });
  static String _rar(int permille) => '${(permille / 10).toStringAsFixed(1)}%';
  // A "pick from catalog" dropdown that resets to its hint after each selection (an action picker).
  Widget _pick(String hint, List<String> labels, void Function(int) onSel) => Container(
        height: 40, padding: const EdgeInsets.symmetric(horizontal: 12),
        decoration: BoxDecoration(color: PG.window, borderRadius: BorderRadius.circular(8), border: Border.all(color: PG.border)),
        child: DropdownButtonHideUnderline(child: DropdownButton<int>(
            isExpanded: true, value: null, isDense: true,
            hint: Text(hint, style: PG.t(13, color: PG.textDim)), dropdownColor: PG.cardHi, style: PG.t(13),
            items: [for (var i = 0; i < labels.length; i++) DropdownMenuItem(value: i, child: Text(labels[i], style: PG.t(13)))],
            onChanged: (i) { if (i != null) onSel(i); })));

  // A small live colour swatch + #RRGGBB hex field (one of the four backdrop colours).
  Widget _colorBox(TextEditingController c) {
    final v = _parseColor(c.text) & 0xFFFFFF;
    return Expanded(child: Row(children: [
      Container(width: 18, height: 18, decoration: BoxDecoration(
          color: c.text.trim().isEmpty ? Colors.transparent : Color(0xFF000000 | v),
          borderRadius: BorderRadius.circular(4), border: Border.all(color: PG.border))),
      const SizedBox(width: 6),
      Expanded(child: Container(
          decoration: BoxDecoration(color: PG.window, borderRadius: BorderRadius.circular(8), border: Border.all(color: PG.border)),
          padding: const EdgeInsets.symmetric(horizontal: 8),
          child: TextField(controller: c, style: PG.t(13, mono: true), cursorColor: PG.blue,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(isDense: true, border: InputBorder.none,
                  contentPadding: const EdgeInsets.symmetric(vertical: 10),
                  hintText: '#RRGGBB', hintStyle: PG.t(12, color: PG.textDim))))),
    ]));
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Spoof Profile Unique Gifts', icon: Icons.diamond_outlined,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'giftUniqueEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Rebuild the first regular gift on the profile into an upgraded (unique) gift. Pick a gift to pull '
              'its real models, symbols and backdrops (with ids + colours) from the @GiftChanges API, or type '
              'fully-custom values. The rebuild is validated and reverts on any failure, so it never destabilises '
              'the client. Open the profile\'s gifts to see it.', style: PG.t(13, color: PG.textDim)),
          _label('Whose profile'),
          _dropdown<int>(target, [
            for (var i = 0; i < _targetModeLabels.length; i++)
              DropdownMenuItem(value: i, child: Text(_targetModeLabels[i], style: PG.t(13))),
          ], (v) => setState(() => target = v ?? target)),
          _label('Gift name'),
          Row(children: [
            Expanded(child: _field(t['giftUniqueName']!, hint: 'e.g. Plush Pepe')),
            const SizedBox(width: 8),
            _action(_loading ? 'Loading…' : 'Update lists', Icons.refresh_rounded,
                _loading ? () {} : () => _loadNames(refresh: true)),
          ]),
          if (_giftNames.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8),
              child: _pick('Pick a gift from the API…', _giftNames, (i) {
                t['giftUniqueName']!.text = _giftNames[i]; _loadCatalog(_giftNames[i]); })),
          if (_apiNote.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 6),
              child: Text(_apiNote, style: PG.t(12, color: PG.orange))),
          _label('Title'), _field(t['giftUniqueTitle']!, hint: 'collectible title'),
          _label('Unique number'), _field(n['giftUniqueNum']!, hint: '0 = keep · the "#N" shown on the gift'),
          Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Issued'), _field(n['giftUniqueIssued']!, hint: '0')])),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Total'), _field(n['giftUniqueTotal']!, hint: '0')])),
          ]),
          _label('Model (name · emoji id)'),
          Row(children: [
            Expanded(child: _field(t['giftUniqueModelName']!, hint: 'model name')),
            const SizedBox(width: 8),
            Expanded(child: _field(t['giftUniqueModelEmojiId']!, hint: 'custom emoji id')),
          ]),
          if (_models.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8),
              child: _pick('Pick model from the API…', [for (final m in _models) '${m.name} · ${_rar(m.rarityPermille)}'],
                  (i) => _pickModel(_models[i]))),
          _label('Symbol (name · emoji id)'),
          Row(children: [
            Expanded(child: _field(t['giftUniqueSymbolName']!, hint: 'symbol name')),
            const SizedBox(width: 8),
            Expanded(child: _field(t['giftUniqueSymbolEmojiId']!, hint: 'custom emoji id')),
          ]),
          if (_symbols.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8),
              child: _pick('Pick symbol from the API…', [for (final m in _symbols) '${m.name} · ${_rar(m.rarityPermille)}'],
                  (i) => _pickSymbol(_symbols[i]))),
          _label('Backdrop'), _field(t['giftUniqueBackdropName']!, hint: 'backdrop name'),
          if (_backdrops.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 8),
              child: _pick('Pick backdrop from the API (fills colours)…',
                  [for (final b in _backdrops) '${b.name} · ${_rar(b.rarityPermille)}'], (i) => _pickBackdrop(_backdrops[i]))),
          _label('Backdrop colors (center · edge · pattern · text)'),
          Row(children: [
            _colorBox(col['giftUniqueBackdropCenter']!), const SizedBox(width: 8),
            _colorBox(col['giftUniqueBackdropEdge']!), const SizedBox(width: 8),
            _colorBox(col['giftUniqueBackdropPattern']!), const SizedBox(width: 8),
            _colorBox(col['giftUniqueBackdropText']!),
          ]),
          _label('Rarity ‰ (model · symbol · backdrop)'),
          Row(children: [
            Expanded(child: _field(n['giftUniqueModelRarity']!, hint: '0 = default')),
            const SizedBox(width: 8),
            Expanded(child: _field(n['giftUniqueSymbolRarity']!, hint: '0 = default')),
            const SizedBox(width: 8),
            Expanded(child: _field(n['giftUniqueBackdropRarity']!, hint: '0 = default')),
          ]),
          _label('Sender'), _field(t['giftUniqueSender']!, hint: '0 = keep · Bot-API id'),
          _label('Owner'), _field(t['giftUniqueOwner']!, hint: '0 = keep · Bot-API id'),
          _label('Host'), _field(t['giftUniqueHost']!, hint: '0 = none · Bot-API id'),
          _label('Owner address'), _field(t['giftUniqueOwnerAddress']!, hint: 'TON address (empty = none)'),
          _label('Date'), _field(t['giftUniqueDate']!, hint: '0 = keep · unix · HH:mm:ss dd.MM.yyyy'),
          _label('Value (currency · amount)'),
          Row(children: [
            Expanded(child: _field(t['giftUniqueValueCurrency']!, hint: 'TON')),
            const SizedBox(width: 8),
            Expanded(child: _field(n['giftUniqueValueAmount']!, hint: '0')),
          ]),
          _label('Value USD amount'), _field(n['giftUniqueValueUsdAmount']!, hint: '0 = keep · raw long'),
          _label('Last resale (currency · amount)'),
          Row(children: [
            Expanded(child: _field(t['giftUniqueLastResaleCurrency']!, hint: 'TON')),
            const SizedBox(width: 8),
            Expanded(child: _field(n['giftUniqueLastResaleAmount']!, hint: '0 = none')),
          ]),
          _label('Last resale date (unix)'), _field(n['giftUniqueLastResaleDate']!, hint: '0 = none'),
          const SizedBox(height: 8),
          Text('Last resale shows on a unique gift that already has resale history.', style: PG.t(12, color: PG.textDim)),
          const SizedBox(height: 16),
          Text(GiftApi.attribution, style: PG.t(11, color: PG.textDim)),
        ]),
      );
}

// ---- Custom Stars -------------------------------------------------------------------------------
class _CustomStarsModal extends StatelessWidget {
  final AppState state;
  _CustomStarsModal({required this.state});
  late final TextEditingController v = TextEditingController(text: '${state.intKeyOr('customStarsValue', 999)}');

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom Stars', icon: Icons.star_rounded,
        actions: _saveActions(context, state, () {
          state.setInt('customStarsValue', _parseInt(v.text, 999, max: 4294967295));
        }, enableKey: 'customStarsEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Enter the Stars amount to show in My Stars and transaction status responses.',
              style: PG.t(13, color: PG.textDim)),
          _label('Stars value'),
          Row(children: [
            Expanded(child: _field(v, hint: '999')),
            const SizedBox(width: 10),
            Text('Stars', style: PG.t(14, color: PG.textDim)),
          ]),
        ]),
      );
}

// ---- Custom TON ---------------------------------------------------------------------------------
class _CustomTonModal extends StatelessWidget {
  final AppState state;
  _CustomTonModal({required this.state});
  late final TextEditingController v = TextEditingController(text: '${state.intKeyOr('customTonValue', 999)}');

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom TON', icon: Icons.diamond_rounded,
        actions: _saveActions(context, state, () {
          state.setInt('customTonValue', _parseInt(v.text, 999, max: 9000000000));
        }, enableKey: 'customTonEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Enter the TON amount to show in My TON and transaction status responses.',
              style: PG.t(13, color: PG.textDim)),
          _label('TON value'),
          Row(children: [
            Expanded(child: _field(v, hint: '999')),
            const SizedBox(width: 10),
            Text('TON', style: PG.t(14, color: PG.textDim)),
          ]),
        ]),
      );
}

// ---- Custom level rating ------------------------------------------------------------------------
class _CustomLevelRatingModal extends StatefulWidget {
  final AppState state;
  const _CustomLevelRatingModal({required this.state});
  @override
  State<_CustomLevelRatingModal> createState() => _CustomLevelRatingModalState();
}

class _CustomLevelRatingModalState extends State<_CustomLevelRatingModal> {
  late int target = _targetModeIndex(widget.state.strKeyOr('customLevelRatingTargetMode', 'all'));
  late final level = TextEditingController(text: '${widget.state.intKeyOr('customLevelRatingLevel', 1)}');
  late final rating = TextEditingController(text: '${widget.state.intKeyOr('customLevelRatingRating', 1000)}');
  late final current = TextEditingController(text: '${widget.state.intKeyOr('customLevelRatingCurrentLevelRating', 0)}');
  late final next = TextEditingController(text: '${widget.state.intKeyOr('customLevelRatingNextLevelRating', 2000)}');

  void _commit() {
    final s = widget.state;
    s.setStr('customLevelRatingTargetMode', _targetModeKeys[target]);
    s.setInt('customLevelRatingLevel', _parseInt(level.text, 1));
    s.setInt('customLevelRatingRating', _parseInt(rating.text, 1000));
    s.setInt('customLevelRatingCurrentLevelRating', _parseInt(current.text, 0));
    s.setInt('customLevelRatingNextLevelRating', _parseInt(next.text, 2000));
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom level rating', icon: Icons.bar_chart_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'customLevelRatingEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Override the local Stars rating / level shown on a profile.', style: PG.t(13, color: PG.textDim)),
          _label('Target'),
          _dropdown<int>(target, [for (var i = 0; i < _targetModeLabels.length; i++) _dItem(i, _targetModeLabels[i])],
              (i) => setState(() => target = i ?? 0)),
          _label('Level'), _intRow(level, hint: '1'),
          _label('Rating'), _intRow(rating, hint: '1000'),
          _label('Current level rating'), _intRow(current, hint: '0'),
          _label('Next level rating'), _intRow(next, hint: '2000'),
        ]),
      );
}

// ---- Visual peer badge --------------------------------------------------------------------------
class _PeerBadgeModal extends StatefulWidget {
  final AppState state;
  const _PeerBadgeModal({required this.state});
  @override
  State<_PeerBadgeModal> createState() => _PeerBadgeModalState();
}

class _PeerBadgeModalState extends State<_PeerBadgeModal> {
  // Mode: All=0, All except me=10, Only me=20.  Badge: Verified=1, Scam=2, Fake=3.
  late int mode = widget.state.intKeyOr('peerBadgeMode', 0);
  late int badge = widget.state.intKeyOr('peerBadgeType', 1);

  void _commit() {
    widget.state.setInt('peerBadgeMode', mode);
    widget.state.setInt('peerBadgeType', badge);
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Visual peer badge', icon: Icons.verified_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'peerBadgeEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Show a Verified / Scam / Fake badge next to peers locally.', style: PG.t(13, color: PG.textDim)),
          _label('Mode'),
          _dropdown<int>(mode, [_dItem(0, 'All'), _dItem(10, 'All except me'), _dItem(20, 'Only me')],
              (v) => setState(() => mode = v ?? 0)),
          _label('Badge'),
          _dropdown<int>(badge, [_dItem(1, 'Verified'), _dItem(2, 'Scam'), _dItem(3, 'Fake')],
              (v) => setState(() => badge = v ?? 1)),
        ]),
      );
}

// ---- Bot verification ---------------------------------------------------------------------------
class _BotVerificationModal extends StatefulWidget {
  final AppState state;
  const _BotVerificationModal({required this.state});
  @override
  State<_BotVerificationModal> createState() => _BotVerificationModalState();
}

class _BotVerificationModalState extends State<_BotVerificationModal> {
  // Built-in preset (the only one macOS ships). sel: 0 = Scared Cat, 1..N = user preset, N+1 = Custom.
  static const _scaredCatEmojiId = '5222202915040555254';
  static const _scaredCatDescription = 'Meow';
  late int target = _targetModeIndex(widget.state.strKeyOr('botVerifyTargetMode', 'all'));
  late List<Map<String, String>> presets;   // user presets: {title, emojiId, description}
  late int sel;
  late final emojiId = TextEditingController(text: widget.state.strKeyOr('botVerifyCustomEmojiId', ''));
  late final description = TextEditingController(text: widget.state.strKeyOr('botVerifyDescription', ''));
  final addName = TextEditingController(), addEmoji = TextEditingController(), addDesc = TextEditingController();
  String addError = '';
  bool manageOpen = false;

  int get _customIdx => presets.length + 1;

  @override
  void initState() {
    super.initState();
    presets = _loadPresets();
    final p = widget.state.intKeyOr('botVerifyPreset', 0);
    if (p == 0) { sel = 0; }
    else {
      final eid = widget.state.strKeyOr('botVerifyCustomEmojiId', '');
      final d = widget.state.strKeyOr('botVerifyDescription', '');
      final idx = presets.indexWhere((pr) => pr['emojiId'] == eid && pr['description'] == d);
      sel = idx >= 0 ? idx + 1 : _customIdx;
    }
  }

  List<Map<String, String>> _loadPresets() {
    try {
      final list = jsonDecode(widget.state.strKeyOr('botVerifyPresets', '[]'));
      if (list is List) return list.whereType<Map>().map((e) => {
        'title': '${e['title'] ?? ''}', 'emojiId': '${e['emojiId'] ?? ''}', 'description': '${e['description'] ?? ''}',
      }).toList();
    } catch (_) {}
    return [];
  }
  void _savePresets() => widget.state.setStr('botVerifyPresets', jsonEncode(presets));

  void _addPreset() {
    final name = addName.text.trim(), eid = addEmoji.text.trim(), desc = addDesc.text.trim();
    final eidVal = BigInt.tryParse(eid);
    setState(() {
      if (name.isEmpty) { addError = 'Enter a verification preset name.'; return; }
      if (eidVal == null || eidVal <= BigInt.zero) { addError = 'Enter a valid custom_emoji_id.'; return; }
      if (desc.isEmpty) { addError = 'Enter a bot verification description.'; return; }
      if (eid == _scaredCatEmojiId && desc == _scaredCatDescription) { addError = 'Scared Cat already exists as a built-in preset.'; return; }
      if (presets.any((p) => p['emojiId'] == eid && p['description'] == desc)) { addError = 'This verification preset already exists.'; return; }
      presets.add({'title': name, 'emojiId': eid, 'description': desc});
      _savePresets();
      addName.clear(); addEmoji.clear(); addDesc.clear(); addError = '';
    });
  }
  void _deletePreset(int i) => setState(() {
    presets.removeAt(i);
    _savePresets();
    if (sel == i + 1) sel = _customIdx;
    else if (sel > i + 1 && sel <= presets.length + 1) sel -= 1;
  });

  void _commit() {
    final s = widget.state;
    s.setStr('botVerifyTargetMode', _targetModeKeys[target]);
    _savePresets();
    if (sel == 0) {
      s.setInt('botVerifyPreset', 0);
      s.setStr('botVerifyCustomEmojiId', _scaredCatEmojiId);
      s.setStr('botVerifyDescription', _scaredCatDescription);
    } else if (sel == _customIdx) {
      s.setInt('botVerifyPreset', 1);
      s.setStr('botVerifyCustomEmojiId', emojiId.text.trim());
      s.setStr('botVerifyDescription', description.text);
    } else {
      final p = presets[sel - 1];
      s.setInt('botVerifyPreset', 1);
      s.setStr('botVerifyCustomEmojiId', p['emojiId']!);
      s.setStr('botVerifyDescription', p['description']!);
    }
  }

  List<DropdownMenuItem<int>> get _presetItems => [
    _dItem(0, 'Scared Cat (built-in)'),
    for (var i = 0; i < presets.length; i++) _dItem(i + 1, presets[i]['title']!.isEmpty ? 'Preset ${i + 1}' : presets[i]['title']!),
    _dItem(_customIdx, 'Custom…'),
  ];

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Bot verification', icon: Icons.shield_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'botVerifyEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Show a fake bot-verification icon + description on profiles locally.', style: PG.t(13, color: PG.textDim)),
          _label('Target'),
          _dropdown<int>(target, [for (var i = 0; i < _targetModeLabels.length; i++) _dItem(i, _targetModeLabels[i])],
              (i) => setState(() => target = i ?? 0)),
          _label('Verification preset'),
          _dropdown<int>(sel, _presetItems, (v) => setState(() => sel = v ?? 0)),
          if (sel == 0) Padding(padding: const EdgeInsets.only(top: 10),
              child: Text('Built-in "Scared Cat": emoji $_scaredCatEmojiId, description "$_scaredCatDescription".',
                  style: PG.t(12, color: PG.textDim)))
          else if (sel == _customIdx) ...[
            _label('Custom emoji id'), _field(emojiId, hint: 'custom emoji id (uint64)'),
            _label('Description'), _field(description, hint: 'verification description'),
          ] else Padding(padding: const EdgeInsets.only(top: 10),
              child: Text('emoji ${presets[sel - 1]['emojiId']}, description "${presets[sel - 1]['description']}".',
                  style: PG.t(12, color: PG.textDim))),
          const SizedBox(height: 6),
          const Divider(color: PG.border, height: 24),
          MouseRegion(cursor: SystemMouseCursors.click, child: GestureDetector(
            onTap: () => setState(() => manageOpen = !manageOpen),
            child: Row(children: [
              AnimatedRotation(turns: manageOpen ? 0.25 : 0, duration: const Duration(milliseconds: 200),
                  child: const Icon(Icons.chevron_right_rounded, color: PG.textDim, size: 18)),
              const SizedBox(width: 4),
              Text('Manage presets', style: PG.t(14, w: FontWeight.w600)),
              const SizedBox(width: 8),
              Text('${presets.length} saved', style: PG.t(12, color: PG.textDim)),
            ]))),
          if (manageOpen) ...[
            for (var i = 0; i < presets.length; i++) Padding(padding: const EdgeInsets.only(top: 8), child: Row(children: [
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(presets[i]['title']!, style: PG.t(13, w: FontWeight.w600)),
                Text('emoji ${presets[i]['emojiId']} · "${presets[i]['description']}"', style: PG.t(11, color: PG.textDim, mono: true)),
              ])),
              GestureDetector(onTap: () => _deletePreset(i),
                  child: const Icon(Icons.delete_outline_rounded, color: PG.textDim, size: 20)),
            ])),
            const SizedBox(height: 10),
            _label('Add preset'),
            _field(addName, hint: 'Name'),
            const SizedBox(height: 6), _field(addEmoji, hint: 'custom_emoji_id'),
            const SizedBox(height: 6), _field(addDesc, hint: 'description'),
            if (addError.isNotEmpty) Padding(padding: const EdgeInsets.only(top: 6),
                child: Text(addError, style: PG.t(12, color: PG.orange))),
            Padding(padding: const EdgeInsets.only(top: 8),
                child: _action('Add preset', Icons.add_rounded, _addPreset)),
          ],
        ]),
      );
}

// ---- Custom phone number ------------------------------------------------------------------------
class _CustomPhoneModal extends StatefulWidget {
  final AppState state;
  const _CustomPhoneModal({required this.state});
  @override
  State<_CustomPhoneModal> createState() => _CustomPhoneModalState();
}

class _CustomPhoneModalState extends State<_CustomPhoneModal> {
  late final phone = TextEditingController(text: widget.state.strKeyOr('customPhone', '+10000000000'));
  late int target = _targetModeIndex(widget.state.strKeyOr('customPhoneTargetMode', 'onlySelf'));

  void _commit() {
    widget.state.setStr('customPhone', phone.text.trim());
    widget.state.setStr('customPhoneTargetMode', _targetModeKeys[target]);
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom phone number', icon: Icons.phone_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'customPhoneEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Show a custom phone number on the chosen profiles locally.', style: PG.t(13, color: PG.textDim)),
          _label('Phone'), _field(phone, hint: '+10000000000'),
          _label('Target'),
          _dropdown<int>(target, [for (var i = 0; i < _targetModeLabels.length; i++) _dItem(i, _targetModeLabels[i])],
              (i) => setState(() => target = i ?? 0)),
        ]),
      );
}

// ---- Custom userID ------------------------------------------------------------------------------
class _CustomUserIdModal extends StatefulWidget {
  final AppState state;
  const _CustomUserIdModal({required this.state});
  @override
  State<_CustomUserIdModal> createState() => _CustomUserIdModalState();
}

class _CustomUserIdModalState extends State<_CustomUserIdModal> {
  late final userId = TextEditingController(text: widget.state.strKeyOr('customUserId', ''));
  late int target = _targetModeIndex(widget.state.strKeyOr('customUserIdTargetMode', 'onlySelf'));

  void _commit() {
    widget.state.setStr('customUserId', userId.text.trim());
    widget.state.setStr('customUserIdTargetMode', _targetModeKeys[target]);
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom userID', icon: Icons.badge_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'customUserIdEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Show a custom user id on the chosen profiles locally.', style: PG.t(13, color: PG.textDim)),
          _label('User id'), _field(userId, hint: 'empty = keep original'),
          _label('Target'),
          _dropdown<int>(target, [for (var i = 0; i < _targetModeLabels.length; i++) _dItem(i, _targetModeLabels[i])],
              (i) => setState(() => target = i ?? 0)),
        ]),
      );
}

// ---- Local attached channel ---------------------------------------------------------------------
class _LocalChannelModal extends StatefulWidget {
  final AppState state;
  const _LocalChannelModal({required this.state});
  @override
  State<_LocalChannelModal> createState() => _LocalChannelModalState();
}

class _LocalChannelModalState extends State<_LocalChannelModal> {
  late final reference = TextEditingController(text: widget.state.strKeyOr('localChannelReference', ''));
  late final messageId = TextEditingController(text: '${widget.state.intKeyOr('localChannelMessageId', 0)}');
  late int target = _targetModeIndex(widget.state.strKeyOr('localChannelTargetMode', 'onlySelf'));

  void _commit() {
    widget.state.setStr('localChannelReference', reference.text.trim());
    widget.state.setInt('localChannelMessageId', _parseInt(messageId.text, 0));
    widget.state.setStr('localChannelTargetMode', _targetModeKeys[target]);
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Local attached channel', icon: Icons.link_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'localChannelEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Attach a personal channel to the chosen profiles locally. Open the channel once first so the '
              'client has it loaded, otherwise the profile can\'t render it.', style: PG.t(13, color: PG.textDim)),
          _label('Channel reference'), _field(reference, hint: 'channel id, e.g. -1001234567890 (empty = off)'),
          _label('Message id'), _intRow(messageId, hint: '0'),
          _label('Target'),
          _dropdown<int>(target, [for (var i = 0; i < _targetModeLabels.length; i++) _dItem(i, _targetModeLabels[i])],
              (i) => setState(() => target = i ?? 0)),
        ]),
      );
}

// ---- Fragment phone -----------------------------------------------------------------------------
class _FragmentPhoneModal extends StatefulWidget {
  final AppState state;
  const _FragmentPhoneModal({required this.state});
  @override
  State<_FragmentPhoneModal> createState() => _FragmentPhoneModalState();
}

class _FragmentPhoneModalState extends State<_FragmentPhoneModal> {
  late int target = _targetModeIndex(widget.state.strKeyOr('fragmentPhoneTargetMode', 'onlySelf'));
  late final purchaseDate = TextEditingController(text: widget.state.strKeyOr('fragmentPhonePurchaseDateText', '0'));
  late final currency = TextEditingController(text: widget.state.strKeyOr('fragmentPhoneCurrency', 'USD'));
  late final amount = TextEditingController(text: '${widget.state.intKeyOr('fragmentPhoneAmount', 0)}');
  late final cryptoCurrency = TextEditingController(text: widget.state.strKeyOr('fragmentPhoneCryptoCurrency', 'TON'));
  late final cryptoAmount = TextEditingController(text: '${widget.state.intKeyOr('fragmentPhoneCryptoAmount', 0)}');
  late final url = TextEditingController(text: widget.state.strKeyOr('fragmentPhoneUrl', ''));

  // Accept "0"/empty (=none), a raw unix int, or "HH:mm:ss dd.MM.yyyy"; the DLL reads the unix int.
  static int _parsePurchaseDate(String t) {
    t = t.trim();
    if (t.isEmpty || t == '0') return 0;
    final asInt = int.tryParse(t);
    if (asInt != null) return asInt;
    final m = RegExp(r'^(\d{1,2}):(\d{2}):(\d{2})\s+(\d{1,2})\.(\d{1,2})\.(\d{4})$').firstMatch(t);
    if (m != null) {
      final dt = DateTime.utc(int.parse(m[6]!), int.parse(m[5]!), int.parse(m[4]!),
          int.parse(m[1]!), int.parse(m[2]!), int.parse(m[3]!));
      return dt.millisecondsSinceEpoch ~/ 1000;
    }
    return 0;
  }

  void _commit() {
    final s = widget.state;
    s.setStr('fragmentPhoneTargetMode', _targetModeKeys[target]);
    s.setStr('fragmentPhonePurchaseDateText', purchaseDate.text.trim());      // keep raw text for round-trip
    s.setInt('fragmentPhonePurchaseDate', _parsePurchaseDate(purchaseDate.text)); // unix int the DLL reads
    s.setStr('fragmentPhoneCurrency', currency.text.trim());
    s.setInt('fragmentPhoneAmount', _parseInt(amount.text, 0));
    s.setStr('fragmentPhoneCryptoCurrency', cryptoCurrency.text.trim());
    s.setInt('fragmentPhoneCryptoAmount', _parseInt(cryptoAmount.text, 0));
    s.setStr('fragmentPhoneUrl', url.text.trim());
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Fragment phone', icon: Icons.sim_card_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'fragmentPhoneEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Show a Fragment anonymous-number "bought on Fragment" panel locally.', style: PG.t(13, color: PG.textDim)),
          _label('Target'),
          _dropdown<int>(target, [for (var i = 0; i < _targetModeLabels.length; i++) _dItem(i, _targetModeLabels[i])],
              (i) => setState(() => target = i ?? 0)),
          _label('Purchase date'), _field(purchaseDate, hint: '0 = none · unix · HH:mm:ss dd.MM.yyyy'),
          Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Currency'), _field(currency, hint: 'USD')])),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Amount'), _intRow(amount, hint: '0')])),
          ]),
          Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Crypto currency'), _field(cryptoCurrency, hint: 'TON')])),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              _label('Crypto amount'), _intRow(cryptoAmount, hint: '0')])),
          ]),
          _label('URL'), _field(url, hint: 'fragment.com/… (empty = none)'),
        ]),
      );
}

// ---- Custom Fact Check --------------------------------------------------------------------------
class _FactCheckModal extends StatefulWidget {
  final AppState state;
  const _FactCheckModal({required this.state});
  @override
  State<_FactCheckModal> createState() => _FactCheckModalState();
}

class _FactCheckModalState extends State<_FactCheckModal> {
  late final text = TextEditingController(text: widget.state.strKeyOr('factCheckText', 'Fact checked locally'));
  late final country = TextEditingController(text: widget.state.strKeyOr('factCheckCountry', ''));
  late final hash = TextEditingController(text: '${widget.state.intKeyOr('factCheckHash', 0)}');
  late bool needCheck = widget.state.boolKeyOr('factCheckNeedCheck', false);

  void _commit() {
    final s = widget.state;
    s.setStr('factCheckText', text.text);
    s.setStr('factCheckCountry', country.text.trim());
    s.setInt('factCheckHash', _parseInt(hash.text, 0));
    s.setBool('factCheckNeedCheck', needCheck);
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom Fact Check', icon: Icons.fact_check_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'factCheckEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Attach a local "fact check" note to messages.', style: PG.t(13, color: PG.textDim)),
          _label('Text'), _field(text, hint: 'Fact checked locally'),
          _label('Country'), _field(country, hint: 'ISO country code (optional)'),
          _label('Hash'), _intRow(hash, hint: '0'),
          Padding(padding: const EdgeInsets.only(top: 14), child: Row(children: [
            Checkbox(value: needCheck, activeColor: PG.blue, onChanged: (v) => setState(() => needCheck = v ?? false)),
            Text('Need check', style: PG.t(14)),
          ])),
        ]),
      );
}

// ---- Custom list usernames ----------------------------------------------------------------------
// Simplified vs macOS: a flat add/remove list of {username, status, isPrimary} rows plus the shared
// collectible-info block; persisted as a compact JSON payload under customUsernames* keys.
class _UsernameRow {
  final TextEditingController username;
  int status; // 0 = Default, 1 = Collectible
  bool isPrimary;
  _UsernameRow(String name, this.status, this.isPrimary) : username = TextEditingController(text: name);
}

class _CustomUsernamesModal extends StatefulWidget {
  final AppState state;
  const _CustomUsernamesModal({required this.state});
  @override
  State<_CustomUsernamesModal> createState() => _CustomUsernamesModalState();
}

class _CustomUsernamesModalState extends State<_CustomUsernamesModal> {
  final List<_UsernameRow> rows = [];
  late bool useShared = widget.state.boolKeyOr('customUsernamesUseSharedCollectibleInfo', true);
  late final purchaseDate = TextEditingController(text: widget.state.strKeyOr('customUsernamesPurchaseDateText', '0'));
  late final currency = TextEditingController(text: widget.state.strKeyOr('customUsernamesCurrency', 'USD'));
  late final amount = TextEditingController(text: '${widget.state.intKeyOr('customUsernamesAmount', 0)}');
  late final cryptoCurrency = TextEditingController(text: widget.state.strKeyOr('customUsernamesCryptoCurrency', 'TON'));
  late final cryptoAmount = TextEditingController(text: '${widget.state.intKeyOr('customUsernamesCryptoAmount', 0)}');
  late final url = TextEditingController(text: widget.state.strKeyOr('customUsernamesUrl', ''));

  @override
  void initState() {
    super.initState();
    final raw = widget.state.strKeyOr('customUsernamesList', '');
    if (raw.isNotEmpty) {
      try {
        final list = jsonDecode(raw);
        if (list is List) {
          for (final e in list) {
            if (e is Map) {
              rows.add(_UsernameRow('${e['username'] ?? ''}',
                  (e['status'] is int) ? e['status'] as int : 0, e['isPrimary'] == true));
            }
          }
        }
      } catch (_) {}
    }
    if (rows.isEmpty) rows.add(_UsernameRow('', 0, false));
  }

  void _commit() {
    final list = rows
        .where((r) => r.username.text.trim().isNotEmpty)
        .map((r) => {'username': r.username.text.trim(), 'status': r.status, 'isPrimary': r.isPrimary})
        .toList();
    final s = widget.state;
    s.setStr('customUsernamesList', jsonEncode(list));   // GUI round-trip form
    s.setBool('customUsernamesUseSharedCollectibleInfo', useShared);
    s.setStr('customUsernamesPurchaseDateText', purchaseDate.text.trim());
    s.setStr('customUsernamesCurrency', currency.text.trim());
    s.setInt('customUsernamesAmount', _parseInt(amount.text, 0));
    s.setStr('customUsernamesCryptoCurrency', cryptoCurrency.text.trim());
    s.setInt('customUsernamesCryptoAmount', _parseInt(cryptoAmount.text, 0));
    s.setStr('customUsernamesUrl', url.text.trim());
    // Engine payload (path B): 8-field pipe lines, primary first (the DLL makes entry 0 editable/primary),
    // "username|collectible|purchaseDateUnix|currency|amount|cryptoCurrency|cryptoAmount|url". The DLL reads
    // field 0; the rest is parity for the per-username collectible follow-up.
    final ordered = [...list]..sort((a, b) =>
        ((b['isPrimary'] == true) ? 1 : 0) - ((a['isPrimary'] == true) ? 1 : 0));
    final pd = _FragmentPhoneModalState._parsePurchaseDate(purchaseDate.text);
    final cur = currency.text.trim(), ccur = cryptoCurrency.text.trim(), u = url.text.trim();
    final amt = _parseInt(amount.text, 0), camt = _parseInt(cryptoAmount.text, 0);
    final lines = ordered.map((e) {
      final name = '${e['username']}'.replaceAll('|', '').replaceAll('\n', '');
      final st = (e['status'] == 1) ? 1 : 0;
      return '$name|$st|$pd|$cur|$amt|$ccur|$camt|$u';
    }).toList();
    s.setStr('customListUsernamesPayload', lines.join('\n'));
  }

  Widget _row(int i) {
    final r = rows[i];
    return Padding(padding: const EdgeInsets.only(top: 8), child: Row(children: [
      Expanded(flex: 3, child: _field(r.username, hint: 'username')),
      const SizedBox(width: 8),
      SizedBox(width: 150, child: _dropdown<int>(r.status,
          [_dItem(0, 'Default'), _dItem(1, 'Collectible')], (v) => setState(() => r.status = v ?? 0))),
      const SizedBox(width: 8),
      // Exactly one username can be Primary (the editable @username). Checking one clears the rest.
      Tooltip(message: 'Primary', child: Checkbox(value: r.isPrimary, activeColor: PG.blue,
          onChanged: (v) => setState(() {
                if (v == true) { for (final o in rows) o.isPrimary = false; r.isPrimary = true; }
                else { r.isPrimary = false; }
              }))),
      GestureDetector(onTap: () => setState(() => rows.removeAt(i)),
          child: const Icon(Icons.remove_circle_outline_rounded, color: PG.textDim, size: 20)),
    ]));
  }

  @override
  Widget build(BuildContext context) => _Shell(
        title: 'Custom list usernames', icon: Icons.alternate_email_rounded,
        actions: _saveActions(context, widget.state, _commit, enableKey: 'customListUsernamesEnabled'),
        body: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Show a custom set of usernames on your profile locally. Mark one as Primary; '
              'Collectible usernames use the shared info below.', style: PG.t(13, color: PG.textDim)),
          _label('Usernames'),
          for (var i = 0; i < rows.length; i++) _row(i),
          Padding(padding: const EdgeInsets.only(top: 10),
              child: _action('Add username', Icons.add_rounded, () => setState(() => rows.add(_UsernameRow('', 0, false))))),
          const SizedBox(height: 4),
          const Divider(color: PG.border, height: 24),
          Row(children: [
            Checkbox(value: useShared, activeColor: PG.blue, onChanged: (v) => setState(() => useShared = v ?? true)),
            Text('Use shared collectible info', style: PG.t(14)),
          ]),
          if (useShared) ...[
            _label('Purchase date'), _field(purchaseDate, hint: '0 = none · unix · HH:mm:ss dd.MM.yyyy'),
            Row(children: [
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                _label('Currency'), _field(currency, hint: 'USD')])),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                _label('Amount'), _intRow(amount, hint: '0')])),
            ]),
            Row(children: [
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                _label('Crypto currency'), _field(cryptoCurrency, hint: 'TON')])),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                _label('Crypto amount'), _intRow(cryptoAmount, hint: '0')])),
            ]),
            _label('URL'), _field(url, hint: 'fragment.com/… (empty = none)'),
          ],
        ]),
      );
}
