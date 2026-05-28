#include <windows.h>
#include <iostream>

int main() {
    std::cout << "Checking for debugger using IsDebuggerPresent()..." << std::endl;
    
    // IsDebuggerPresent() reads the BeingDebugged flag from the PEB (Process Environment Block)
    if (IsDebuggerPresent()) {
        std::cout << "[+] Debugger detected! Terminating program." << std::endl;
        return 1;
    }
    
    std::cout << "[-] No debugger detected. Proceeding with normal execution." << std::endl;
    return 0;
}
