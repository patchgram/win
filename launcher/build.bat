@echo off
REM Build the Patchgram persistence launcher (x64). Output: pg_launcher.exe next to this script.
setlocal
set "HERE=%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" ( echo ERROR: vswhere.exe not found & exit /b 1 )
set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" ( echo ERROR: VS with VC x64 tools not found & exit /b 1 )
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo ERROR: vcvars64 failed & exit /b 1 )
set "OBJ=%HERE%build"
if not exist "%OBJ%" mkdir "%OBJ%"
cl /nologo /O2 /MT /DNDEBUG /Fo"%OBJ%"\ "%HERE%launcher.c" ^
   /link /OUT:"%HERE%pg_launcher.exe" /SUBSYSTEM:WINDOWS user32.lib
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo BUILD OK: %HERE%pg_launcher.exe
endlocal
