#include <windows.h>
#include <iostream>

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN ULONG ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

#define ProcessDebugFlags 0x1F

int main() {
    std::cout << "Checking ProcessDebugFlags (NoDebugInherit)..." << std::endl;

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) { std::cout << "Failed to get ntdll.dll" << std::endl; return 1; }

    pfnNtQueryInformationProcess NtQueryInfoProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProcess) { std::cout << "Failed to resolve NtQueryInformationProcess" << std::endl; return 1; }

    DWORD noDebugInherit = 0;
    NTSTATUS status = NtQueryInfoProcess(
        GetCurrentProcess(), ProcessDebugFlags, &noDebugInherit, sizeof(noDebugInherit), NULL);

    if (status != 0) {
        std::cout << "NtQueryInformationProcess failed" << std::endl;
        return 1;
    }

    std::cout << "NoDebugInherit = " << noDebugInherit << std::endl;

    if (noDebugInherit == 0) {
        std::cout << "[+] Debugger detected (NoDebugInherit == 0)!" << std::endl;
        return 1;
    }

    std::cout << "[-] No debugger detected (NoDebugInherit != 0)." << std::endl;
    return 0;
}
