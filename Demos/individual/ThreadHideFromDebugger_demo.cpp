#include <windows.h>
#include <iostream>

// Define the prototype for NtSetInformationThread
typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    IN HANDLE ThreadHandle,
    IN ULONG ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
);

const ULONG ThreadHideFromDebugger = 0x11; // 17 in decimal

bool HideThread() {
    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (hNtDll) {
        pfnNtSetInformationThread NtSetInfoThread = 
            (pfnNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");

        if (NtSetInfoThread) {
            // Calling NtSetInformationThread with ThreadHideFromDebugger (0x11)
            // Detaches the debugger from receiving events for this specific thread.
            NTSTATUS status = NtSetInfoThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
            if (status == 0) {
                return true;
            }
        }
        FreeLibrary(hNtDll);
    }
    return false;
}

int main() {
    std::cout << "Attempting to hide thread from debugger using NtSetInformationThread..." << std::endl;
    
    if (HideThread()) {
        std::cout << "[+] Successfully executed ThreadHideFromDebugger." << std::endl;
        std::cout << "    If you are debugging this, the debugger will no longer receive events from this thread." << std::endl;
    } else {
        std::cout << "[-] Failed to execute ThreadHideFromDebugger." << std::endl;
    }

    std::cout << "Press Enter to trigger a breakpoint (__debugbreak)..." << std::endl;
    std::cin.get();

    // If a debugger is attached and the thread is successfully hidden, 
    // the debugger will NOT intercept this breakpoint. It will be handled by the program's SEH,
    // or it will crash the program if unhandled.
    __try {
        std::cout << "Executing __debugbreak()..." << std::endl;
        __debugbreak();
        std::cout << "[-] Debugger intercepted and continued execution." << std::endl;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        std::cout << "[+] Exception handled by program (Debugger was bypassed/hidden)!" << std::endl;
    }

    return 0;
}
