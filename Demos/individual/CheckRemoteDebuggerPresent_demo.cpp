#include <windows.h>
#include <iostream>

int main() {
    BOOL isDebuggerPresent = FALSE;
    
    std::cout << "Checking for debugger using CheckRemoteDebuggerPresent()..." << std::endl;
    
    // CheckRemoteDebuggerPresent checks if a debugger is attached to the specified process.
    // It actually calls NtQueryInformationProcess with ProcessDebugPort.
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        std::cout << "[+] Debugger detected! Terminating program." << std::endl;
        return 1;
    }
    
    std::cout << "[-] No debugger detected. Proceeding with normal execution." << std::endl;
    return 0;
}
