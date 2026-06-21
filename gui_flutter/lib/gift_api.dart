import 'dart:convert';
import 'dart:io';

/// Gift data from the free, unauthenticated @GiftChanges API (api.changes.tg). Ported from the macOS
/// GiftChangesAPI.swift. The attribution credit is REQUIRED by the API — surface it in the gift UIs.
class GiftAttr {
  final String name; final int emojiId; final int rarityPermille;
  const GiftAttr(this.name, this.emojiId, this.rarityPermille);
}

class GiftBackdrop {
  final String name; final int center, edge, pattern, text, rarityPermille;
  const GiftBackdrop(this.name, this.center, this.edge, this.pattern, this.text, this.rarityPermille);
}

class GiftApi {
  static const attribution = 'Gift data: thanks to @GiftChanges (api.changes.tg)';
  static const _base = 'https://api.changes.tg';

  static Future<dynamic> _get(String path, {int timeout = 8}) async {
    try {
      final c = HttpClient()..connectionTimeout = Duration(seconds: timeout);
      final req = await c.getUrl(Uri.parse(_base + path));
      req.headers.set('User-Agent', 'PatchgramGui');
      final resp = await req.close().timeout(Duration(seconds: timeout));
      final body = await resp.transform(const Utf8Decoder()).join();
      c.close();
      return resp.statusCode == 200 ? jsonDecode(body) : null;
    } catch (_) { return null; }
  }

  // GET /emoji → { "<giftId>": "<emojiId>", … }. Cached. Backs "Get id from gift".
  static Map<String, int>? _emojiMap;
  static Future<Map<String, int>> emojiMap() async {
    if (_emojiMap != null) return _emojiMap!;
    final j = await _get('/emoji', timeout: 6);
    final m = <String, int>{};
    if (j is Map) { j.forEach((k, v) { final n = int.tryParse('$v'); if (n != null) m['$k'] = n; }); }
    if (m.isNotEmpty) _emojiMap = m;
    return m;
  }
  /// Resolve a gift id (string) → its sticker custom-emoji id, or null if unknown.
  static Future<int?> resolveStickerEmojiId(String giftIdText) async {
    final v = int.tryParse(giftIdText.trim());
    if (v == null || v == 0) return null;
    return (await emojiMap())['$v'];   // normalized key (no leading zeros / whitespace)
  }

  // GET /gifts → names of all upgradable gifts, sorted A→Z.
  static List<String>? _names;
  static Future<List<String>> giftNames({bool refresh = false}) async {
    if (_names != null && !refresh) return _names!;
    final j = await _get('/gifts');
    if (j is List) {
      final l = j.map((e) => '$e').toList()..sort((a, b) => a.toLowerCase().compareTo(b.toLowerCase()));
      _names = l; return l;
    }
    return _names ?? [];
  }

  // GET /emoji/:gift → (models, symbols), each {name, customEmojiId, rarity%→permille}, sorted A→Z.
  static Future<(List<GiftAttr>, List<GiftAttr>)> modelsAndSymbols(String gift) async {
    if (gift.trim().isEmpty) return (<GiftAttr>[], <GiftAttr>[]);
    final j = await _get('/emoji/${Uri.encodeComponent(gift.trim())}');
    List<GiftAttr> canon(dynamic raw) {
      if (raw is! List) return [];
      final l = raw.whereType<Map>().map((m) => GiftAttr('${m['name'] ?? ''}',
          int.tryParse('${m['customEmojiId'] ?? 0}') ?? 0,
          (((m['rarity'] as num?) ?? 0) * 10).round())).toList();
      l.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
      return l;
    }
    if (j is Map) return (canon(j['models']), canon(j['patterns']));
    return (<GiftAttr>[], <GiftAttr>[]);
  }

  // GET /backdrops[/:gift] → backdrops (name + 4 colours + rarity permille), sorted A→Z.
  static Future<List<GiftBackdrop>> backdrops([String? gift]) async {
    final path = (gift == null || gift.trim().isEmpty) ? '/backdrops' : '/backdrops/${Uri.encodeComponent(gift.trim())}';
    final j = await _get(path);
    if (j is List) {
      int g(Map m, String k) => int.tryParse('${m[k] ?? 0}') ?? 0;
      final l = j.whereType<Map>().map((m) => GiftBackdrop('${m['name'] ?? ''}',
          g(m, 'centerColor'), g(m, 'edgeColor'), g(m, 'patternColor'), g(m, 'textColor'), g(m, 'rarityPermille'))).toList();
      l.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
      return l;
    }
    return [];
  }
}
