#include <windows.h>
#include <iostream>
#include <string>
#include <cstdlib>

bool InjectDll(DWORD pid, const std::wstring& dllPath)
{
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!hProcess)
    {
        std::wcout << L"OpenProcess failed: " << GetLastError() << L"\n";
        return false;
    }

    SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);

    void* remoteMem = VirtualAllocEx(
        hProcess,
        nullptr,
        bytes,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!remoteMem)
    {
        std::wcout << L"VirtualAllocEx failed: " << GetLastError() << L"\n";
        CloseHandle(hProcess);
        return false;
    }

    BOOL ok = WriteProcessMemory(
        hProcess,
        remoteMem,
        dllPath.c_str(),
        bytes,
        nullptr
    );

    if (!ok)
    {
        std::wcout << L"WriteProcessMemory failed: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(
        hProcess,
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW),
        remoteMem,
        0,
        nullptr
    );

    if (!hThread)
    {
        std::wcout << L"CreateRemoteThread failed: " << GetLastError() << L"\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);

    std::wcout << L"Inject done. LoadLibraryW return = 0x"
        << std::hex << exitCode << std::dec << L"\n";

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return exitCode != 0;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc != 3)
    {
        std::wcout << L"Usage:\n";
        std::wcout << L"Controller.exe <pid> <full-path-to-Agent.dll>\n";
        return 1;
    }

    DWORD pid = static_cast<DWORD>(wcstoul(argv[1], nullptr, 10));
    std::wstring dllPath = argv[2];

    if (!InjectDll(pid, dllPath))
    {
        std::wcout << L"Inject failed.\n";
        return 2;
    }

    std::wcout << L"Inject success.\n";
    return 0;
}