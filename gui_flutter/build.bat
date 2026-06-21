@echo off
REM Build the Flutter Windows patcher. Requires the Flutter SDK on PATH (https://docs.flutter.dev).
setlocal
cd /d "%~dp0"
where flutter >nul 2>&1
if errorlevel 1 ( echo ERROR: Flutter SDK not on PATH. Install: https://docs.flutter.dev/get-started/install/windows & exit /b 1 )
REM Generate the native Windows runner (windows\) the first time; keeps lib\ + pubspec.yaml.
REM NOTE: flutter is a .bat — must use CALL or control never returns to this script.
if not exist "windows" ( call flutter create --platforms=windows --project-name patchgram_gui . )
call flutter pub get || ( echo pub get failed & exit /b 1 )
call flutter build windows --release || ( echo BUILD FAILED & exit /b 1 )
echo BUILD OK: build\windows\x64\runner\Release\patchgram_gui.exe
endlocal
