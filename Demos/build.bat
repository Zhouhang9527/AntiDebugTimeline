@echo off
echo Compiling all demo programs...

:: Check if MSVC compiler (cl) is in the PATH
where cl >nul 2>nul
if %errorlevel% neq 0 (
    echo [!] MSVC compiler 'cl' not found. Please run this script from a "Developer Command Prompt for VS".
    exit /b 1
)

echo.
echo --- Building all-in-one console ---
cl.exe /utf-8 /EHsc /W4 /WX- /O2 AntiDebugDemo.cpp /link user32.lib
echo.

echo --- Building individual demos ---
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\IsDebuggerPresent_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\PEB_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\HardwareBreakpoints_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\CheckRemoteDebuggerPresent_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\NtQueryInformationProcess_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\FindWindow_demo.cpp /link user32.lib
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\ThreadHideFromDebugger_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\ParentProcess_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\DebugBreak_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\TimingCheck_demo.cpp
cl.exe /utf-8 /EHsc /W4 /WX- /O2 individual\NoDebugInherit_demo.cpp

echo.
echo Compilation finished.
echo Run "AntiDebugDemo.exe" for the all-in-one console.
del *.obj 2>nul
