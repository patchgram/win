import 'package:flutter/material.dart';

/// macOS-dark palette lifted from the original Patchgram (SwiftUI) app.
class PG {
  static const window     = Color(0xFF0E0E10);
  static const panel      = Color(0xFF121214);
  static const card       = Color(0xFF1A1A1D);
  static const cardHi     = Color(0xFF202024);
  static const border     = Color(0xFF2A2A2E);
  static const text       = Color(0xFFF2F2F5);
  static const textDim    = Color(0xFF8E8E93);
  static const mono       = Color(0xFFB8B8C0);

  static const blue       = Color(0xFF0A84FF);
  static const green      = Color(0xFF30D158);
  static const purple     = Color(0xFF5E5CE6);   // dylib
  static const orange     = Color(0xFFFF9F0A);   // binary
  static const gray       = Color(0xFF3A3A3E);

  static Color a(Color c, double o) => c.withOpacity(o);

  static const String monoFamily = 'Consolas';

  static ThemeData theme() {
    final base = ThemeData.dark(useMaterial3: true);
    return base.copyWith(
      scaffoldBackgroundColor: window,
      canvasColor: window,
      colorScheme: base.colorScheme.copyWith(
        primary: blue, secondary: blue, surface: card, background: window,
      ),
      textTheme: base.textTheme.apply(bodyColor: text, displayColor: text,
          fontFamily: 'Segoe UI'),
      tooltipTheme: const TooltipThemeData(
        decoration: BoxDecoration(color: Color(0xFF2A2A2E), borderRadius: BorderRadius.all(Radius.circular(6))),
        textStyle: TextStyle(color: text, fontSize: 12),
      ),
    );
  }

  static TextStyle t(double size, {Color? color, FontWeight? w, bool mono = false}) =>
      TextStyle(fontSize: size, color: color ?? text, fontWeight: w,
          fontFamily: mono ? monoFamily : 'Segoe UI', height: 1.25);
}
