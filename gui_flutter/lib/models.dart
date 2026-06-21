import 'package:flutter/material.dart';

enum PatchType { dylib, binary }   // dylib renders as "dll" on Windows

/// A settings modal kind. `none` = no gear. One case per per-subpatch (or per-patch) modal,
/// matching the macOS Patchgram "Custom account settings" / "Message settings" customizations.
enum Settings {
  none,
  giftSpoof,
  giftSpoofUnique,
  customStars,
  customTon,
  customLevelRating,
  peerBadge,
  botVerification,
  customPhone,
  customUserId,
  localChannel,
  fragmentPhone,
  customUsernames,
  factCheck,
}

extension PatchTypeLabel on PatchType {
  String get label => this == PatchType.dylib ? 'dll' : 'binary';
}

class Subpatch {
  final String title;
  final String key; // config bool key ("" = not wired to the Windows DLL yet)
  final Settings settings; // a per-subpatch settings modal (Settings.none = no gear)
  const Subpatch(this.title, [this.key = "", this.settings = Settings.none]);
}

class Patch {
  final String id;
  final String title;
  final String subtitle;   // monospace method/constructor
  final String desc;
  final PatchType type;
  final bool available;    // implemented in the Windows DLL (Qt5 build)
  final List<String> keys; // bool config keys toggled together ([] = not wired yet)
  final Settings settings;
  final List<Subpatch> subs;
  const Patch(this.id, this.title, this.subtitle, this.desc, this.type,
      {this.available = false, this.keys = const [], this.settings = Settings.none, this.subs = const []});
}

class Section {
  final String id, title, subtitle, icon; // icon = assets/section-<icon>.svg
  final List<Patch> patches;
  const Section(this.id, this.title, this.subtitle, this.icon, this.patches);
}

/// Mirrors the macOS Patchgram sections + arrangement (sections data-driven by each rule's category;
/// "Custom account settings" and "Message settings" are grouping rows with subpatches). `available:true`
/// = wired to the Windows DLL (Patchgram.dll); the rest are byte/memory patches that still need per-fn RE
/// (shown for parity with the macOS app; toggle disabled until their AOB lands in the DLL).
const catalog = <Section>[
  Section('accounts', 'Accounts', 'Offline status, account limit, identity & profile', 'accounts', [
    Patch('offline', 'Always offline', 'account.updateStatus',
        'Patches the serialized account.updateStatus request so its offline Bool is always boolTrue.',
        PatchType.dylib, available: true, keys: ['alwaysOfflineEnabled']),
    Patch('nophone', "Don't share phone when adding contacts", 'contacts.addContact',
        'Forces contacts.addContact flags to keep only f_note, preventing add_phone_privacy_exception from being sent.',
        PatchType.dylib, available: true, keys: ['noPhoneOnAddEnabled']),
    Patch('acc999', '999 accounts', 'Main::Domain / Storage::Domain',
        "Raises Telegram's local account add/menu/storage checks from the upstream 6-account cap to 999.",
        PatchType.binary, available: true, keys: ['accountLimit999Enabled']),
    Patch('hidephone', 'Hide self phone', 'Info::Profile::PhoneOrHiddenValue',
        'Returns an empty profile phone value for your own user, hiding the phone row in the self-profile.',
        PatchType.dylib, available: true, keys: ['hideSelfPhoneEnabled']),
    Patch('custacc', 'Custom account settings', 'Patchgram runtime account customizations',
        'Groups local account customization patches into one Patchgram runtime feature. The master switch '
        'turns every sub-patch below on or off together.',
        PatchType.dylib, available: true, subs: [
          Subpatch('Custom Stars', 'customStarsEnabled', Settings.customStars),
          Subpatch('Custom TON', 'customTonEnabled', Settings.customTon),
          Subpatch('Custom level rating', 'customLevelRatingEnabled', Settings.customLevelRating),
          Subpatch('Visual peer badge', 'peerBadgeEnabled', Settings.peerBadge),
          Subpatch('Bot verification', 'botVerifyEnabled', Settings.botVerification),
          Subpatch('Local Telegram Premium', 'localPremiumEnabled'),
          Subpatch('Account freeze', 'accountFreezeEnabled'),
          Subpatch('Custom phone number', 'customPhoneEnabled', Settings.customPhone),
          Subpatch('Custom userID', 'customUserIdEnabled', Settings.customUserId),
          Subpatch('Local attached channel', 'localChannelEnabled', Settings.localChannel),
          Subpatch('Fragment phone', 'fragmentPhoneEnabled', Settings.fragmentPhone),
          Subpatch('Custom list usernames', 'customListUsernamesEnabled', Settings.customUsernames),
        ]),
  ]),
  Section('messages', 'Messages', 'Read receipts, links, spoilers, bot data', 'messages', [
    Patch('msgset', 'Message settings', 'messages.setTyping / readHistory / saveDraft / getFactCheck',
        'A grouped privacy patch for typing activity, read receipts, copy/save protect and more.',
        PatchType.dylib, available: true, keys: ['messageSettingsEnabled'], subs: [
          Subpatch('Typing activity', 'blockTypingEnabled'),
          Subpatch('Read receipts', 'blockReadMessagesEnabled'),
          Subpatch('Local drafts', 'localDraftsEnabled'),
          Subpatch('Custom Fact Check', 'factCheckEnabled', Settings.factCheck),
          Subpatch('Copy/save protect content', 'messageNoForwardsCopyEnabled'),
          Subpatch('Disable TTL', 'disableTtlEnabled'),
        ]),
    Patch('callback', 'Show bot callback-data on hover', 'ReplyMarkupClickHandler::getUrlButton',
        'Treats bot callback / WebView inline buttons as URL-like so callback-data is visible on hover/copy.',
        PatchType.binary, available: true, keys: ['callbackHoverEnabled']),
    Patch('blur', 'Sensitive blur', 'HistoryItem::isMediaSensitive',
        'Runtime memory patch forcing media sensitivity checks to return false locally.',
        PatchType.binary, available: true, keys: ['sensitiveBlurEnabled']),
    Patch('recent', 'More recent stickers', 'StickersListWidget::collectRecentStickers',
        "Removes the 20-sticker recent-stickers display limit so all recent stickers show.",
        PatchType.binary, available: true, keys: ['recentStickersUnlimitedEnabled']),
    Patch('links', 'Open links without warning', 'HiddenUrlClickHandler::Open',
        'Opens hidden/external links without the extra confirmation warning.',
        PatchType.binary, available: true, keys: ['openLinksEnabled']),
    Patch('spoilers', 'Disable media spoilers', 'Data::CreateMedia / media spoilers',
        'Shows spoiler-marked photos/videos normally instead of blurring them locally.',
        PatchType.binary, available: true, keys: ['disableSpoilersEnabled']),
  ]),
  Section('opt', 'Optimizations', 'Strip Premium, ads and stories', 'optimizations', [
    Patch('monet', 'Disable Premium, Stars, TON & Gifts', 'help.getAppConfig / monetization',
        'Disables monetization UI at runtime. On Windows only Premium UI is reachable at the appConfig tier '
        '(injects premium_purchase_blocked → hides the premium buy UI); the other sub-features have no '
        'appConfig gate and are shown for macOS parity.',
        PatchType.dylib, available: true, keys: ['disableMonetizationEnabled'], subs: [
          Subpatch('App config', 'disableMonetizationAppConfigEnabled'),
          Subpatch('Premium UI', 'disableMonetizationPremiumUIEnabled'),
          Subpatch('Gifts', 'disableMonetizationGiftsEnabled'),
          Subpatch('Paid reactions', 'disableMonetizationPaidReactionsEnabled'),
          Subpatch('Emoji statuses and effects', 'disableMonetizationEmojiStatusesEnabled'),
          Subpatch('Stars, TON and collectibles', 'disableMonetizationStarsTonCollectiblesEnabled'),
          Subpatch('Boosts', 'disableMonetizationBoostsEnabled'),
          Subpatch('Read receipts fix', 'disableMonetizationReadReceiptsEnabled'),
        ]),
    Patch('preff', 'Disable premium effects', 'HistoryView::Sticker::checkPremiumEffectStart',
        'Stops Premium sticker/effect animations from starting locally.',
        PatchType.binary, available: true, keys: ['disablePremiumEffectsEnabled']),
    Patch('stories', 'Hide stories', 'stories.* / PeerData::setStoriesState',
        'Drops the stories.* fetch requests so the stories feed and per-peer story rings stay empty.',
        PatchType.dylib, available: true, keys: ['hideStoriesEnabled']),
    Patch('ads', 'Disable ads', 'messages.getSponsoredMessages',
        'Blocks Telegram Ads and proxy sponsor promotion surfaces.',
        PatchType.dylib, available: true,
        keys: ['disableAdsTelegramEnabled', 'disableAdsProxyEnabled'], subs: [
          Subpatch('Telegram Ads', 'disableAdsTelegramEnabled'),
          Subpatch('Proxy sponsor', 'disableAdsProxyEnabled'),
        ]),
  ]),
  Section('gifts', 'Gifts', 'Spoof the star gifts shown on a profile', 'gifts', [
    Patch('gspoof', 'Spoof profile gifts', 'payments.getSavedStarGifts / payments.savedStarGifts',
        "Rewrites the saved star gifts in the payments.savedStarGifts response so a profile's gifts show the sender, date, gift id and Stars price you configure.",
        PatchType.dylib, available: true, keys: ['giftSpoofEnabled'], settings: Settings.giftSpoof),
    Patch('gunique', 'Spoof profile unique gifts', 'payments.savedStarGifts (unique)',
        'Rebuilds the first regular gift on a profile into an upgraded (unique) gift with the title, model, '
        'symbol, backdrop and rarity you configure — validated + reverted on failure so it never destabilises.',
        PatchType.dylib, available: true, keys: ['giftUniqueEnabled'], settings: Settings.giftSpoofUnique),
    Patch('gtransfer', 'Fake transfer', 'payments.transferStarGift',
        'Adds a Transfer button to the spoofed gift and fakes the transfer locally (a "transferred" service '
        'message appears). Requires "Spoof profile unique gifts" enabled.',
        PatchType.dylib, available: true, keys: ['giftFakeTransferEnabled']),
    Patch('ghidden', 'Show hidden gifts', 'payments.getStarGifts / payments.starGifts',
        'Appends extra star gifts (50 Stars, not limited) to the payments.starGifts catalog so they appear in the gift menu.',
        PatchType.dylib, available: true, keys: ['giftShowHiddenEnabled']),
  ]),
  Section('misc', 'Misc', 'DLL injection and the logger', 'misc', [
    Patch('inject', 'DLL injection', 'CreateRemoteThread + LoadLibrary',
        'Injects Patchgram.dll into Telegram Desktop (the base hook every runtime patch loads through). '
        'Enabling it makes Apply inject the DLL even with no other patch selected.',
        PatchType.dylib, available: true, keys: ['dllInjectionEnabled']),
    Patch('logger', 'MTProto request/response logger', 'tryToReceive / sendPrepared',
        'Logs every MTProto request + response as fully-decoded TL to PatchgramHook.log.',
        PatchType.dylib, available: true, keys: ['mtprotoLoggerEnabled']),
  ]),
];
