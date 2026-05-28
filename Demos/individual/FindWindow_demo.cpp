#include <windows.h>
#include <iostream>

int main() {
    std::cout << "Checking for common debugger windows..." << std::endl;

    // Look for common debugger window class names or titles
    const char* debuggerWindows[] = {
        "OLLYDBG",         // OllyDbg
        "x64dbg",          // x64dbg/x32dbg
        "Qt5QWindowIcon",  // Often used by x64dbg interface
        "WinDbgFrameClass" // WinDbg
    };

    for (const char* wndClass : debuggerWindows) {
        if (FindWindowA(wndClass, NULL) != NULL) {
            std::cout << "[+] Debugger window (" << wndClass << ") detected! Terminating program." << std::endl;
            return 1;
        }
    }

    std::cout << "[-] No debugger windows detected. Proceeding with normal execution." << std::endl;
    return 0;
}
