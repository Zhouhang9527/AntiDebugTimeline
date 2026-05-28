#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN ULONG ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef struct _PROCESS_BASIC_INFORMATION_FULL {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_FULL;

std::string GetProcessNameByPid(DWORD pid) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return "";

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(pe);

    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                CloseHandle(hSnap);
                return std::string(pe.szExeFile);
            }
        } while (Process32Next(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return "";
}

std::string ToLower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

bool IsParentDebugger() {
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) return false;

    pfnNtQueryInformationProcess NtQueryInfoProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProcess) return false;

    PROCESS_BASIC_INFORMATION_FULL pbi = { 0 };
    NTSTATUS status = NtQueryInfoProcess(
        GetCurrentProcess(), 0, &pbi, sizeof(pbi), NULL);
    if (status != 0) return false;

    DWORD parentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
    std::string parentName = ToLower(GetProcessNameByPid(parentPid));

    std::cout << "Parent PID: " << parentPid << std::endl;
    std::cout << "Parent Name: " << parentName << std::endl;

    const char* debuggers[] = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe",
        "windbg.exe", "devenv.exe", "idaq.exe", "idaq64.exe",
        "ida.exe", "ida64.exe", "immunitydebugger.exe",
        "cheatengine-x86_64.exe", "cheatengine-i386.exe",
    };

    for (const auto& dbg : debuggers) {
        if (parentName == dbg) {
            std::cout << "[+] Parent is a known debugger: " << parentName << std::endl;
            return true;
        }
    }

    std::string normalParents[] = { "explorer.exe", "cmd.exe", "powershell.exe", "windowsterminal.exe" };
    bool isNormal = false;
    for (const auto& np : normalParents) {
        if (parentName == np) { isNormal = true; break; }
    }

    if (!isNormal) {
        std::cout << "[!] Parent is NOT a common shell: " << parentName << std::endl;
        return true;
    }

    return false;
}

int main() {
    std::cout << "Checking parent process name for debugger detection..." << std::endl;

    if (IsParentDebugger()) {
        std::cout << "[+] Debugger detected via parent process check! Terminating." << std::endl;
        return 1;
    }

    std::cout << "[-] Parent process looks normal. Proceeding." << std::endl;
    return 0;
}
