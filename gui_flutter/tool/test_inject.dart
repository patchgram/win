// Standalone test of the native injector (dart run tool/test_inject.dart [pid]).
// No pid → launch Telegram suspended + inject + resume. With pid → inject into that running process.
import 'dart:io';
import 'package:patchgram_gui/native_inject.dart';

void main(List<String> args) {
  const dll = r'E:\patchgram\win\dll\Patchgram.dll';
  const tg = r'E:\patchgram\patchgramtest\Telegram.exe';
  if (args.isNotEmpty) {
    final pid = int.parse(args[0]);
    stdout.writeln('injectIntoPid($pid) -> ${injectIntoPid(pid, dll)}');
  } else {
    stdout.writeln('launchSuspendedAndInject -> ${launchSuspendedAndInject(tg, dll)}');
  }
}
