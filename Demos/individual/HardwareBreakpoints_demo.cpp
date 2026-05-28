#include <windows.h>
#include <iostream>

bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    
    // Query the thread context to check if any Debug Registers (Dr0-Dr3) are set
    // These registers are used for hardware breakpoints
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true; 
        }
    }
    return false;
}

int main() {
    std::cout << "Checking for hardware breakpoints..." << std::endl;
    
    if (CheckHardwareBreakpoints()) {
        std::cout << "[+] Hardware breakpoints detected! Terminating program." << std::endl;
        return 1;
    }
    
    std::cout << "[-] No hardware breakpoints detected. Proceeding with normal execution." << std::endl;
    return 0;
}
