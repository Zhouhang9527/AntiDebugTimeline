#include <windows.h>
#include <winternl.h>
#include <iostream>

bool CheckPEB_BeingDebugged() {
    // Manually read the BeingDebugged flag from the PEB
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    return pPeb->BeingDebugged == 1;
}

int main() {
    std::cout << "Checking for debugger using PEB BeingDebugged flag..." << std::endl;
    
    if (CheckPEB_BeingDebugged()) {
        std::cout << "[+] Debugger detected via PEB! Terminating program." << std::endl;
        return 1;
    }
    
    std::cout << "[-] No debugger detected. Proceeding with normal execution." << std::endl;
    return 0;
}
