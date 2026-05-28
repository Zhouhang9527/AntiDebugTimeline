#include <windows.h>
#include <winternl.h>
#include <iostream>

// Define the prototype for NtQueryInformationProcess
typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

int main() {
    std::cout << "Checking for debugger using NtQueryInformationProcess (ProcessDebugPort)..." << std::endl;

    // Resolve NtQueryInformationProcess from ntdll.dll
    HMODULE hNtDll = LoadLibraryA("ntdll.dll");
    if (hNtDll) {
        pfnNtQueryInformationProcess NtQueryInfoProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

        if (NtQueryInfoProcess) {
            DWORD_PTR debugPort = 0;
            // ProcessDebugPort is 7
            NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), NULL);

            // If a debugger is attached, debugPort will be set to -1 (0xFFFFFFFF)
            if (status == 0 && debugPort != 0) {
                std::cout << "[+] Debugger detected via ProcessDebugPort! Terminating program." << std::endl;
                return 1;
            }
        }
        FreeLibrary(hNtDll);
    }
    
    std::cout << "[-] No debugger detected. Proceeding with normal execution." << std::endl;
    return 0;
}
