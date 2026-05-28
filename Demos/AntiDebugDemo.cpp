
#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <string>
#include <iomanip>
#include <tlhelp32.h>
#include <intrin.h>

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN HANDLE ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
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


typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    IN HANDLE ThreadHandle,
    IN ULONG ThreadInformationClass,
    IN PVOID ThreadInformation,
    IN ULONG ThreadInformationLength
);


enum ConsoleColor {
    COLOR_DEFAULT = 7,
    COLOR_GREEN   = 10,
    COLOR_RED     = 12,
    COLOR_YELLOW  = 14,
    COLOR_CYAN    = 11,
    COLOR_WHITE   = 15,
    COLOR_MAGENTA = 13,
};

void SetColor(int color) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), (WORD)color);
}

void PrintOK(const char* msg) {
    SetColor(COLOR_GREEN);
    std::cout << "  [PASS] ";
    SetColor(COLOR_DEFAULT);
    std::cout << msg << std::endl;
}

void PrintFail(const char* msg) {
    SetColor(COLOR_RED);
    std::cout << "  [DETECTED] ";
    SetColor(COLOR_DEFAULT);
    std::cout << msg << std::endl;
}

void PrintInfo(const char* msg) {
    SetColor(COLOR_CYAN);
    std::cout << "  [INFO] ";
    SetColor(COLOR_DEFAULT);
    std::cout << msg << std::endl;
}

void PrintWarn(const char* msg) {
    SetColor(COLOR_YELLOW);
    std::cout << "  [WARN] ";
    SetColor(COLOR_DEFAULT);
    std::cout << msg << std::endl;
}

void PrintTitle(const char* title) {
    SetColor(COLOR_MAGENTA);
    std::cout << "\n  ====== " << title << " ======" << std::endl;
    SetColor(COLOR_DEFAULT);
}

void PrintSeparator() {
    SetColor(COLOR_YELLOW);
    std::cout << "  --------------------------------------------------------" << std::endl;
    SetColor(COLOR_DEFAULT);
}


void Demo_IsDebuggerPresent() {
    PrintTitle("Demo 1: IsDebuggerPresent()");
    PrintInfo("原理: 读取 PEB->BeingDebugged 标志位 (kernel32.dll 导出)");
    PrintInfo("绕过: 修改 PEB->BeingDebugged = 0, 或 Hook API 返回 FALSE");
    PrintSeparator();

    if (IsDebuggerPresent()) {
        PrintFail("IsDebuggerPresent() 返回 TRUE —— 检测到调试器!");
    } else {
        PrintOK("IsDebuggerPresent() 返回 FALSE —— 未检测到调试器");
    }
}

void Demo_PEB_BeingDebugged() {
    PrintTitle("Demo 2: PEB->BeingDebugged (直接读内存)");
    PrintInfo("原理: 通过 GS:[0x60]/FS:[0x30] 直接读取 PEB, 不调用任何 API");
    PrintInfo("绕过: 直接在内存中修改 PEB->BeingDebugged = 0");
    PrintSeparator();

#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif

    if (pPeb->BeingDebugged) {
        PrintFail("PEB->BeingDebugged == 1 —— 检测到调试器!");
    } else {
        PrintOK("PEB->BeingDebugged == 0 —— 未检测到调试器");
    }
}

void Demo_CheckRemoteDebuggerPresent() {
    PrintTitle("Demo 3: CheckRemoteDebuggerPresent()");
    PrintInfo("原理: 内部调用 NtQueryInformationProcess(ProcessDebugPort)");
    PrintInfo("绕过: Hook 此 API 或底层 NtQueryInformationProcess");
    PrintSeparator();

    BOOL bDebuggerPresent = FALSE; 
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerPresent) && bDebuggerPresent) {
        PrintFail("CheckRemoteDebuggerPresent 返回 TRUE —— 检测到调试器!");
    } else {
        PrintOK("CheckRemoteDebuggerPresent 返回 FALSE —— 未检测到调试器");
    }
}

void Demo_NtQueryInformationProcess() {
    PrintTitle("Demo 4: NtQueryInformationProcess (ProcessDebugPort)");
    PrintInfo("原理: 直接调用 ntdll 未文档化 API, 查询 ProcessDebugPort(7)");
    PrintInfo("       被调试时 DebugPort = -1, 否则 = 0");
    PrintInfo("绕过: Hook NtQueryInformationProcess, 将结果缓冲区改为 0");
    PrintSeparator();

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) { PrintWarn("无法获取 ntdll.dll"); return; }

    pfnNtQueryInformationProcess NtQueryInfoProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProcess) { PrintWarn("无法解析 NtQueryInformationProcess"); return; }

    DWORD_PTR debugPort = 0;
    NTSTATUS status = NtQueryInfoProcess(GetCurrentProcess(), (PROCESSINFOCLASS)7, &debugPort, sizeof(debugPort), NULL);

    if (status == 0 && debugPort != 0) {
        std::cout << "  DebugPort = 0x" << std::hex << debugPort << std::dec << std::endl;
        PrintFail("ProcessDebugPort 非零 —— 检测到调试器!");
    } else {
        PrintOK("ProcessDebugPort == 0 —— 未检测到调试器");
    }
}

void Demo_HardwareBreakpoints() {
    PrintTitle("Demo 5: Hardware Breakpoints (Dr0-Dr3)");
    PrintInfo("原理: 通过 GetThreadContext 读取 CPU 调试寄存器 Dr0-Dr3");
    PrintInfo("       如果有硬件断点, 这些寄存器将非零");
    PrintInfo("绕过: 不使用硬件断点, 或 Hook GetThreadContext 清零调试寄存器");
    PrintSeparator();

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        std::cout << "  Dr0 = 0x" << std::hex << ctx.Dr0
                  << "  Dr1 = 0x" << ctx.Dr1
                  << "  Dr2 = 0x" << ctx.Dr2
                  << "  Dr3 = 0x" << ctx.Dr3
                  << std::dec << std::endl;

        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            PrintFail("发现非零调试寄存器 —— 硬件断点已设置!");
        } else {
            PrintOK("所有调试寄存器为零 —— 未发现硬件断点");
        }
    } else {
        PrintWarn("GetThreadContext 调用失败");
    }
}

void Demo_FindWindow() {
    PrintTitle("Demo 6: FindWindow (检测调试器窗口)");
    PrintInfo("原理: 枚举系统窗口, 查找已知调试器的窗口类名");
    PrintInfo("绕过: 修改调试器窗口类名, 或 Hook FindWindowA/W 返回 NULL");
    PrintSeparator();

    struct DebuggerInfo {
        const char* className;
        const char* displayName;
    };

    DebuggerInfo debuggers[] = {
        { "OLLYDBG",         "OllyDbg"         },
        { "x64dbg",          "x64dbg"           },
        { "x32dbg",          "x32dbg"           },
        { "Qt5QWindowIcon",  "x64dbg (Qt5)"     },
        { "WinDbgFrameClass","WinDbg"           },
        { "ID",              "Immunity Debugger" },
    };

    bool found = false;
    for (const auto& dbg : debuggers) {
        HWND hwnd = FindWindowA(dbg.className, NULL);
        if (hwnd) {
            std::string msg = std::string("找到窗口: ") + dbg.displayName + " (类名: " + dbg.className + ")";
            PrintFail(msg.c_str());
            found = true;
        }
    }

    if (!found) {
        PrintOK("未找到任何已知调试器窗口");
    }
}

void Demo_ThreadHideFromDebugger() {
    PrintTitle("Demo 7: NtSetInformationThread (ThreadHideFromDebugger)");
    PrintInfo("原理: 调用 NtSetInformationThread(ThreadHideFromDebugger = 0x11)");
    PrintInfo("       调用后, 操作系统不再向调试器发送此线程的调试事件");
    PrintInfo("       调试器中运行此项后, 调试器将无法捕获后续断点/异常");
    PrintInfo("绕过: Hook NtSetInformationThread, 当参数==0x11 时直接返回成功");
    PrintSeparator();

    SetColor(COLOR_YELLOW);
    std::cout << "  [!] 警告: 执行此项后, 如果你正在调试, 调试器将失去对本线程的控制!" << std::endl;
    std::cout << "      确认执行? (y/n): ";
    SetColor(COLOR_DEFAULT);

    char ch;
    std::cin >> ch;
    std::cin.ignore(1024, '\n');

    if (ch != 'y' && ch != 'Y') {
        PrintInfo("已跳过此项演示");
        return;
    }

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) { PrintWarn("无法获取 ntdll.dll"); return; }

    pfnNtSetInformationThread NtSetInfoThread =
        (pfnNtSetInformationThread)GetProcAddress(hNtDll, "NtSetInformationThread");
    if (!NtSetInfoThread) { PrintWarn("无法解析 NtSetInformationThread"); return; }

    NTSTATUS status = NtSetInfoThread(GetCurrentThread(), 0x11, NULL, 0);

    if (status == 0) {
        PrintFail("ThreadHideFromDebugger 已成功设置!");
        PrintInfo("现在触发一个 INT 3 断点来验证效果...");

        __try {
            __debugbreak();  // INT 3
            // 如果调试器仍能接管, 执行会到这里（调试器按 F9 继续后）
            PrintInfo("调试器仍然拦截了断点 (ThreadHideFromDebugger 可能被绕过了)");
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // 如果调试器没有接管, 异常走 SEH 到这里
            PrintOK("INT 3 异常由程序自身 SEH 处理 —— 调试器已被隐藏!");
        }
    } else {
        PrintWarn("NtSetInformationThread 调用失败");
    }
}

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

std::string ToLowerStr(const std::string& s) {
    std::string r = s;
    for (auto& c : r) c = (char)tolower((unsigned char)c);
    return r;
}

void Demo_ParentProcess() {
    PrintTitle("Demo 8: 父进程进程名检测");
    PrintInfo("原理: 通过 NtQueryInformationProcess(ProcessBasicInformation) 获取父进程 PID");
    PrintInfo("       再通过进程快照查询父进程名, 如果是已知调试器则报警");
    PrintInfo("绕过: Hook NtQueryInformationProcess 修改父 PID, 或从正常进程启动");
    PrintSeparator();

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) { PrintWarn("无法获取 ntdll.dll"); return; }

    pfnNtQueryInformationProcess NtQueryInfoProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProcess) { PrintWarn("无法解析 NtQueryInformationProcess"); return; }

    PROCESS_BASIC_INFORMATION_FULL pbi = { 0 };
    NTSTATUS status = NtQueryInfoProcess(
        GetCurrentProcess(), (PROCESSINFOCLASS)0, &pbi, sizeof(pbi), NULL);
    if (status != 0) { PrintWarn("NtQueryInformationProcess 调用失败"); return; }

    DWORD parentPid = (DWORD)pbi.InheritedFromUniqueProcessId;
    std::string parentName = ToLowerStr(GetProcessNameByPid(parentPid));

    std::cout << "  父进程 PID: " << parentPid << std::endl;
    std::cout << "  父进程名称: " << (parentName.empty() ? "<未知>" : parentName) << std::endl;

    const char* debuggers[] = {
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe",
        "windbg.exe", "devenv.exe", "idaq.exe", "idaq64.exe",
        "ida.exe", "ida64.exe", "immunitydebugger.exe",
        "cheatengine-x86_64.exe", "cheatengine-i386.exe",
    };

    bool isDebugger = false;
    for (const auto& dbg : debuggers) {
        if (parentName == dbg) {
            std::string msg = std::string("父进程是已知调试器: ") + parentName;
            PrintFail(msg.c_str());
            isDebugger = true;
            break;
        }
    }

    if (!isDebugger) {
        std::string normalParents[] = { "explorer.exe", "cmd.exe", "powershell.exe", "windowsterminal.exe", "conhost.exe" };
        bool isNormal = false;
        for (const auto& np : normalParents) {
            if (parentName == np) { isNormal = true; break; }
        }

        if (!isNormal && !parentName.empty()) {
            std::string msg = std::string("父进程不是常见 Shell: ") + parentName + " (可疑)";
            PrintFail(msg.c_str());
        } else {
            std::string msg = std::string("父进程正常: ") + parentName;
            PrintOK(msg.c_str());
        }
    }
}

void Demo_DebugBreak() {
    PrintTitle("Demo 9: DebugBreak() 断点异常检测");
    PrintInfo("原理: 主动触发 INT 3 断点异常 (DebugBreak / __debugbreak / INT 2D)");
    PrintInfo("       无调试器时, 异常走 SEH 由程序自己处理");
    PrintInfo("       有调试器时, 调试器吞掉断点, SEH 不会被触发");
    PrintInfo("绕过: 在调试器中手动跳过断点指令, 或 NOP 掉 DebugBreak 调用");
    PrintSeparator();

    SetColor(COLOR_YELLOW);
    std::cout << "  [!] 警告: 如果你正在调试, 调试器会在此断下!" << std::endl;
    std::cout << "      确认执行? (y/n): ";
    SetColor(COLOR_DEFAULT);

    char ch;
    std::cin >> ch;
    std::cin.ignore(1024, '\n');

    if (ch != 'y' && ch != 'Y') {
        PrintInfo("已跳过此项演示");
        return;
    }

    __try {
        DebugBreak();
    }
    __except (
        GetExceptionCode() == EXCEPTION_BREAKPOINT
        ? EXCEPTION_EXECUTE_HANDLER
        : EXCEPTION_CONTINUE_SEARCH
        ) {
        PrintOK("INT 3 异常由 SEH 捕获 —— 未检测到调试器");
        return;
    }

    PrintFail("调试器吞掉了断点 —— 检测到调试器!");
}

void Demo_TimingCheck() {
    PrintTitle("Demo 10: 时间差检测 (RDTSC / QPC / GetTickCount)");
    PrintInfo("原理: 在一段简单代码前后采集时间戳");
    PrintInfo("       单步调试时每条指令都会被拦截, 时间差会异常大");
    PrintInfo("绕过: Hook rdtsc / NOP 掉检测代码, 或修改阈值判断跳转");
    PrintSeparator();

    PrintInfo("[RDTSC] 读取 CPU 时间戳计数器...");
    unsigned __int64 t1 = __rdtsc();
    volatile int dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    unsigned __int64 t2 = __rdtsc();
    unsigned __int64 delta_rdtsc = t2 - t1;
    std::cout << "  RDTSC delta = " << delta_rdtsc << " cycles" << std::endl;
    if (delta_rdtsc > 10000000) {
        PrintFail("RDTSC 时间差过大 —— 疑似调试器单步执行!");
    } else {
        PrintOK("RDTSC 时间差正常");
    }

    PrintInfo("[QPC] QueryPerformanceCounter...");
    LARGE_INTEGER freq, qpc1, qpc2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&qpc1);
    dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    QueryPerformanceCounter(&qpc2);
    double elapsed_us = (double)(qpc2.QuadPart - qpc1.QuadPart) / freq.QuadPart * 1000000.0;
    std::cout << "  QPC delta = " << std::fixed << std::setprecision(2) << elapsed_us << " us" << std::endl;
    if (elapsed_us > 10000.0) {
        PrintFail("QPC 时间差过大 —— 疑似调试器单步执行!");
    } else {
        PrintOK("QPC 时间差正常");
    }

    PrintInfo("[GetTickCount] 毫秒级检测...");
    DWORD tick1 = GetTickCount();
    dummy = 0;
    for (int i = 0; i < 100; i++) dummy += i;
    DWORD tick2 = GetTickCount();
    DWORD delta_tick = tick2 - tick1;
    std::cout << "  GetTickCount delta = " << delta_tick << " ms" << std::endl;
    if (delta_tick > 100) {
        PrintFail("GetTickCount 时间差过大 —— 疑似调试器单步执行!");
    } else {
        PrintOK("GetTickCount 时间差正常");
    }
}

void Demo_NoDebugInherit() {
    PrintTitle("Demo 11: ProcessDebugFlags (NoDebugInherit)");
    PrintInfo("原理: NtQueryInformationProcess(ProcessDebugFlags = 0x1F)");
    PrintInfo("       未调试时返回 1 (EPROCESS->NoDebugInherit), 被调试时返回 0");
    PrintInfo("绕过: Hook NtQueryInformationProcess, 当 class==0x1F 时将结果改为 1");
    PrintSeparator();

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (!hNtDll) { PrintWarn("无法获取 ntdll.dll"); return; }

    pfnNtQueryInformationProcess NtQueryInfoProcess =
        (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInfoProcess) { PrintWarn("无法解析 NtQueryInformationProcess"); return; }

    DWORD noDebugInherit = 0;
    NTSTATUS status = NtQueryInfoProcess(
        GetCurrentProcess(), (PROCESSINFOCLASS)0x1F, &noDebugInherit, sizeof(noDebugInherit), NULL);

    if (status != 0) { PrintWarn("NtQueryInformationProcess 调用失败"); return; }

    std::cout << "  NoDebugInherit = " << noDebugInherit << std::endl;

    if (noDebugInherit == 0) {
        PrintFail("NoDebugInherit == 0 —— 检测到调试器!");
    } else {
        PrintOK("NoDebugInherit == 1 —— 未检测到调试器");
    }
}

void Demo_RunAll() {
    PrintTitle("运行所有被动检测 (1-6, 8, 10-11)");
    PrintSeparator();
    Demo_IsDebuggerPresent();
    Demo_PEB_BeingDebugged();
    Demo_CheckRemoteDebuggerPresent();
    Demo_NtQueryInformationProcess();
    Demo_HardwareBreakpoints();
    Demo_FindWindow();
    Demo_ParentProcess();
    Demo_TimingCheck();
    Demo_NoDebugInherit();
}


void PrintMenu() {
    SetColor(COLOR_WHITE);
    std::cout << "\n";
    std::cout << "  ╔════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "  ║          Anti-Debug Demo  反调试技术演示控制台          ║" << std::endl;
    std::cout << "  ╠════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "  ║                                                        ║" << std::endl;
    std::cout << "  ║   1. IsDebuggerPresent()          [API 调用]           ║" << std::endl;
    std::cout << "  ║   2. PEB->BeingDebugged           [直接读内存]         ║" << std::endl;
    std::cout << "  ║   3. CheckRemoteDebuggerPresent() [API 调用]           ║" << std::endl;
    std::cout << "  ║   4. NtQueryInformationProcess    [Nt 原生 API]        ║" << std::endl;
    std::cout << "  ║   5. Hardware Breakpoints (Dr0-3) [寄存器检测]         ║" << std::endl;
    std::cout << "  ║   6. FindWindow                   [窗口枚举]           ║" << std::endl;
    std::cout << "  ║   7. ThreadHideFromDebugger       [隐藏线程] ⚠        ║" << std::endl;
    std::cout << "  ║   8. 父进程进程名检测             [进程检测]           ║" << std::endl;
    std::cout << "  ║   9. DebugBreak() 断点异常        [断点检测] ⚠        ║" << std::endl;
    std::cout << "  ║  10. 时间差检测 (RDTSC/QPC)      [时间检测]           ║" << std::endl;
    std::cout << "  ║  11. ProcessDebugFlags           [NoDebugInherit]     ║" << std::endl;
    std::cout << "  ║                                                        ║" << std::endl;
    std::cout << "  ║  12. 运行全部被动检测 (1-6, 8, 10-11)                  ║" << std::endl;
    std::cout << "  ║   0. 退出                                              ║" << std::endl;
    std::cout << "  ║                                                        ║" << std::endl;
    std::cout << "  ╚════════════════════════════════════════════════════════╝" << std::endl;
    SetColor(COLOR_DEFAULT);
    std::cout << "\n  请选择 [0-12]: ";
}

int main() {
    // 设置控制台标题和代码页
    SetConsoleTitleA("Anti-Debug Demo - 反调试技术演示");
    SetConsoleOutputCP(65001); // UTF-8

    while (true) {
        PrintMenu();

        int choice = -1;
        std::cin >> choice;
        std::cin.ignore(1024, '\n');

        switch (choice) {
            case 1: Demo_IsDebuggerPresent();           break;
            case 2: Demo_PEB_BeingDebugged();            break;
            case 3: Demo_CheckRemoteDebuggerPresent();   break;
            case 4: Demo_NtQueryInformationProcess();    break;
            case 5: Demo_HardwareBreakpoints();          break;
            case 6: Demo_FindWindow();                   break;
            case 7: Demo_ThreadHideFromDebugger();       break;
            case 8: Demo_ParentProcess();                break;
            case 9: Demo_DebugBreak();                   break;
            case 10: Demo_TimingCheck();                  break;
            case 11: Demo_NoDebugInherit();                break;
            case 12: Demo_RunAll();                        break;
            case 0:
                SetColor(COLOR_GREEN);
                std::cout << "\n  Bye!\n" << std::endl;
                SetColor(COLOR_DEFAULT);
                return 0;
            default:
                PrintWarn("无效选项, 请重新选择");
                break;
        }

        std::cout << std::endl;
        SetColor(COLOR_YELLOW);
        std::cout << "  按 Enter 返回菜单...";
        SetColor(COLOR_DEFAULT);
        std::cin.get();
    }

    return 0;
}
