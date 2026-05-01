#include <Windows.h>
#include <intrin.h>
#include <cstdio>

typedef LONG NTSTATUS;
typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(HANDLE, ULONG, PVOID, ULONG);

constexpr NTSTATUS STATUS_SUCCESS_VALUE = 0x00000000L;
constexpr ULONG ProcessDebugPortValue = 7;
constexpr ULONG ProcessDebugObjectHandleValue = 0x1E;
constexpr ULONG ProcessDebugFlagsValue = 0x1F;
constexpr ULONG ThreadHideFromDebuggerValue = 0x11;
constexpr DWORD HEAP_DEBUG_FLAGS_MASK = 0x40000060;

#if defined(_M_X64)
constexpr size_t PEB_NT_GLOBAL_FLAG_OFFSET = 0xBC;
constexpr size_t HEAP_FLAGS_OFFSET = 0x70;
constexpr size_t HEAP_FORCE_FLAGS_OFFSET = 0x74;
#else
constexpr size_t PEB_NT_GLOBAL_FLAG_OFFSET = 0x68;
constexpr size_t HEAP_FLAGS_OFFSET = 0x40;
constexpr size_t HEAP_FORCE_FLAGS_OFFSET = 0x44;
#endif

static unsigned char* GetPeb()
{
#if defined(_M_X64)
    return reinterpret_cast<unsigned char*>(__readgsqword(0x60));
#elif defined(_M_IX86)
    return reinterpret_cast<unsigned char*>(__readfsdword(0x30));
#else
    return nullptr;
#endif
}

static void HitAndSuspend(const char* method)
{
    std::printf("\n[Sample] Anti-debug hit: %s\n", method);
    std::printf("[Sample] Suspending current thread. Inject/bypass before resuming or terminate this process.\n");
    std::fflush(stdout);

    SuspendThread(GetCurrentThread());
    Sleep(INFINITE);
}

static void CheckPebState()
{
    unsigned char* peb = GetPeb();
    if (!peb)
        return;

    BYTE beingDebugged = *(peb + 2);
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(peb + PEB_NT_GLOBAL_FLAG_OFFSET);
    std::printf("[Sample] PEB BeingDebugged=%u NtGlobalFlag=0x%08lx\n", beingDebugged, ntGlobalFlag);

    if (beingDebugged != 0)
        HitAndSuspend("PEB->BeingDebugged");

    if ((ntGlobalFlag & 0x70) != 0)
        HitAndSuspend("PEB->NtGlobalFlag heap debug bits");
}

static void CheckHeapState()
{
    HANDLE heap = GetProcessHeap();
    if (!heap)
        return;

    __try
    {
        unsigned char* heapBytes = reinterpret_cast<unsigned char*>(heap);
        DWORD flags = *reinterpret_cast<DWORD*>(heapBytes + HEAP_FLAGS_OFFSET);
        DWORD forceFlags = *reinterpret_cast<DWORD*>(heapBytes + HEAP_FORCE_FLAGS_OFFSET);
        std::printf("[Sample] ProcessHeap Flags=0x%08lx ForceFlags=0x%08lx\n", flags, forceFlags);

        if ((flags & HEAP_DEBUG_FLAGS_MASK) != 0 || (forceFlags & HEAP_DEBUG_FLAGS_MASK) != 0)
            HitAndSuspend("ProcessHeap Flags / ForceFlags debug bits");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        std::printf("[Sample] ProcessHeap Flags unavailable\n");
    }
}

static void RunNtQueryChecks(NtQueryInformationProcess_t ntQuery)
{
    if (!ntQuery)
        return;

    ULONG_PTR debugPort = 0;
    NTSTATUS portStatus = ntQuery(
        GetCurrentProcess(),
        ProcessDebugPortValue,
        &debugPort,
        sizeof(debugPort),
        nullptr
    );

    HANDLE debugObject = nullptr;
    NTSTATUS objectStatus = ntQuery(
        GetCurrentProcess(),
        ProcessDebugObjectHandleValue,
        &debugObject,
        sizeof(debugObject),
        nullptr
    );

    ULONG debugFlags = 0;
    NTSTATUS flagsStatus = ntQuery(
        GetCurrentProcess(),
        ProcessDebugFlagsValue,
        &debugFlags,
        sizeof(debugFlags),
        nullptr
    );

    std::printf(
        "[Sample] NtQuery DebugPort(status=0x%08lx,value=%llu) DebugObject(status=0x%08lx,value=%p) DebugFlags(status=0x%08lx,value=%lu)\n",
        static_cast<unsigned long>(portStatus),
        static_cast<unsigned long long>(debugPort),
        static_cast<unsigned long>(objectStatus),
        debugObject,
        static_cast<unsigned long>(flagsStatus),
        debugFlags
    );

    if (portStatus == STATUS_SUCCESS_VALUE && debugPort != 0)
        HitAndSuspend("NtQueryInformationProcess(ProcessDebugPort)");

    if (objectStatus == STATUS_SUCCESS_VALUE && debugObject != nullptr)
        HitAndSuspend("NtQueryInformationProcess(ProcessDebugObjectHandle)");

    if (flagsStatus == STATUS_SUCCESS_VALUE && debugFlags == 0)
        HitAndSuspend("NtQueryInformationProcess(ProcessDebugFlags)");
}

static void RunThreadChecks(NtSetInformationThread_t ntSetInformationThread)
{
    if (ntSetInformationThread)
    {
        NTSTATUS status = ntSetInformationThread(
            GetCurrentThread(),
            ThreadHideFromDebuggerValue,
            nullptr,
            0
        );
        std::printf("[Sample] NtSetInformationThread(ThreadHideFromDebugger) status=0x%08lx\n", static_cast<unsigned long>(status));
    }

    CONTEXT context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    BOOL contextOk = GetThreadContext(GetCurrentThread(), &context);
    std::printf(
        "[Sample] GetThreadContext ok=%d Dr0=%p Dr1=%p Dr2=%p Dr3=%p Dr7=0x%llx\n",
        contextOk,
        reinterpret_cast<void*>(context.Dr0),
        reinterpret_cast<void*>(context.Dr1),
        reinterpret_cast<void*>(context.Dr2),
        reinterpret_cast<void*>(context.Dr3),
        static_cast<unsigned long long>(context.Dr7)
    );

    if (contextOk && (context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0 || context.Dr7 != 0))
        HitAndSuspend("GetThreadContext debug registers");
}

int main()
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtQueryInformationProcess_t ntQuery = ntdll
        ? reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(ntdll, "NtQueryInformationProcess"))
        : nullptr;
    NtSetInformationThread_t ntSetInformationThread = ntdll
        ? reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"))
        : nullptr;

    std::printf("[Sample] PID = %lu\n", GetCurrentProcessId());
    std::printf("[Sample] If any debugger signal is detected, this process prints the hit method and suspends itself.\n");
    std::printf("[Sample] Use Controller's suspended launch injection to load Agent before this loop runs.\n\n");

    for (;;)
    {
        BOOL remote = FALSE;
        BOOL isDebuggerPresent = IsDebuggerPresent();
        BOOL checkRemoteOk = CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);

        std::printf("[Sample] IsDebuggerPresent=%d CheckRemote(ok=%d,present=%d)\n", isDebuggerPresent, checkRemoteOk, remote);

        if (isDebuggerPresent)
            HitAndSuspend("IsDebuggerPresent");

        if (checkRemoteOk && remote)
            HitAndSuspend("CheckRemoteDebuggerPresent");

        CheckPebState();
        CheckHeapState();
        RunNtQueryChecks(ntQuery);

        OutputDebugStringA("[Sample] OutputDebugStringA probe");
        OutputDebugStringW(L"[Sample] OutputDebugStringW probe");

        RunThreadChecks(ntSetInformationThread);

        std::printf("----\n");
        Sleep(2000);
    }
}
