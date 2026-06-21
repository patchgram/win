@echo off
REM Build Patchgram.dll (x64) with MSVC + vendored MinHook. Run from anywhere.
REM Output: Patchgram.dll next to this script.
setlocal
set "HERE=%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" ( echo ERROR: vswhere.exe not found ^(install VS Build Tools^) & exit /b 1 )
set "VSPATH="
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if "%VSPATH%"=="" ( echo ERROR: VS with VC x64 tools not found & exit /b 1 )
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 ( echo ERROR: vcvars64 failed & exit /b 1 )

set MH=%HERE%minhook
set "OBJ=%HERE%build"
if not exist "%OBJ%" mkdir "%OBJ%"
REM engine_tl.c (TL decoder + schema) and engine_patches.c (config + rewriters) are portable C -> /TC.
cl /nologo /c /TC /O2 /MT /DNDEBUG /Fo"%OBJ%"\ "%HERE%engine_tl.c" "%HERE%engine_patches.c"
if errorlevel 1 ( echo BUILD FAILED ^(engine C^) & exit /b 1 )
cl /nologo /LD /O2 /MT /std:c++17 /EHsc /DNDEBUG ^
   /I "%MH%\include" /Fo"%OBJ%"\ ^
   "%HERE%patchgram.cpp" "%OBJ%\engine_tl.obj" "%OBJ%\engine_patches.obj" ^
   "%MH%\src\buffer.c" "%MH%\src\hook.c" "%MH%\src\trampoline.c" "%MH%\src\hde\hde64.c" ^
   /link /OUT:"%HERE%Patchgram.dll" /SUBSYSTEM:WINDOWS
if errorlevel 1 ( echo BUILD FAILED & exit /b 1 )
echo BUILD OK: %HERE%Patchgram.dll
endlocal
