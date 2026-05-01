// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <windows.h>
#include <intrin.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cwchar>

#include "..\Shared\AntiDebugConfig.h"

typedef LONG NTSTATUS;

#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#define STATUS_INVALID_INFO_CLASS ((NTSTATUS)0xC0000003L)

constexpr ULONG ProcessDebugPortValue = 7;
constexpr ULONG ProcessDebugObjectHandleValue = 0x1E;
constexpr ULONG ProcessDebugFlagsValue = 0x1F;
constexpr ULONG ThreadHideFromDebuggerValue = 0x11;

#if defined(_M_X64)
constexpr size_t PEB_NT_GLOBAL_FLAG_OFFSET = 0xBC;
constexpr size_t HEAP_FLAGS_OFFSET = 0x70;
constexpr size_t HEAP_FORCE_FLAGS_OFFSET = 0x74;
#else
constexpr size_t PEB_NT_GLOBAL_FLAG_OFFSET = 0x68;
constexpr size_t HEAP_FLAGS_OFFSET = 0x40;
constexpr size_t HEAP_FORCE_FLAGS_OFFSET = 0x44;
#endif

constexpr size_t PEB_BEING_DEBUGGED_OFFSET = 0x02;
constexpr DWORD HEAP_DEBUG_FLAGS_MASK = 0x40000060;

struct AgentConfig
{
    DWORD detectMask = ADT_FEATURE_ALL;
    DWORD bypassMask =
        ADT_FEATURE_IS_DEBUGGER_PRESENT |
        ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT |
        ADT_FEATURE_NT_QUERY_INFORMATION_PROCESS |
        ADT_FEATURE_PEB_BEING_DEBUGGED |
        ADT_FEATURE_PEB_NT_GLOBAL_FLAG |
        ADT_FEATURE_PEB_HEAP_FLAGS |
        ADT_FEATURE_NT_SET_INFORMATION_THREAD |
        ADT_FEATURE_GET_THREAD_CONTEXT;
    bool keepPebClean = false;
};

struct HookContext
{
    void* target = nullptr;
    void* detour = nullptr;
    unsigned char original[16] = {};
    size_t patchLen = 14;
    bool originalSaved = false;
    bool installed = false;
    const char* name = nullptr;
};

typedef BOOL(WINAPI* IsDebuggerPresent_t)();
typedef BOOL(WINAPI* CheckRemoteDebuggerPresent_t)(HANDLE, PBOOL);
typedef VOID(WINAPI* OutputDebugStringA_t)(LPCSTR);
typedef VOID(WINAPI* OutputDebugStringW_t)(LPCWSTR);
typedef BOOL(WINAPI* GetThreadContext_t)(HANDLE, LPCONTEXT);

typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

static AgentConfig g_Config;
static wchar_t g_DllDir[MAX_PATH] = {};
static wchar_t g_ConfigPath[MAX_PATH] = {};
static wchar_t g_LogPath[MAX_PATH] = {};
static CRITICAL_SECTION g_LogLock;
static bool g_LogLockReady = false;

static HookContext g_IsDebuggerPresentHook{ nullptr, nullptr, {}, 14, false, false, "IsDebuggerPresent" };
static HookContext g_CheckRemoteDebuggerPresentHook{ nullptr, nullptr, {}, 14, false, false, "CheckRemoteDebuggerPresent" };
static HookContext g_NtQueryInformationProcessHook{ nullptr, nullptr, {}, 14, false, false, "NtQueryInformationProcess" };
static HookContext g_OutputDebugStringAHook{ nullptr, nullptr, {}, 14, false, false, "OutputDebugStringA" };
static HookContext g_OutputDebugStringWHook{ nullptr, nullptr, {}, 14, false, false, "OutputDebugStringW" };
static HookContext g_NtSetInformationThreadHook{ nullptr, nullptr, {}, 14, false, false, "NtSetInformationThread" };
static HookContext g_GetThreadContextHook{ nullptr, nullptr, {}, 14, false, false, "GetThreadContext" };

static IsDebuggerPresent_t g_RealIsDebuggerPresent = nullptr;
static CheckRemoteDebuggerPresent_t g_RealCheckRemoteDebuggerPresent = nullptr;
static NtQueryInformationProcess_t g_RealNtQueryInformationProcess = nullptr;
static OutputDebugStringA_t g_RealOutputDebugStringA = nullptr;
static OutputDebugStringW_t g_RealOutputDebugStringW = nullptr;
static NtSetInformationThread_t g_RealNtSetInformationThread = nullptr;
static GetThreadContext_t g_RealGetThreadContext = nullptr;

static thread_local bool g_InIsDebuggerPresent = false;
static thread_local bool g_InCheckRemoteDebuggerPresent = false;
static thread_local bool g_InNtQueryInformationProcess = false;
static thread_local bool g_InOutputDebugStringA = false;
static thread_local bool g_InOutputDebugStringW = false;
static thread_local bool g_InNtSetInformationThread = false;
static thread_local bool g_InGetThreadContext = false;

static bool FeatureEnabled(DWORD mask)
{
    return (g_Config.detectMask & mask) != 0 || (g_Config.bypassMask & mask) != 0;
}

static bool ShouldDetect(DWORD mask)
{
    return (g_Config.detectMask & mask) != 0;
}

static bool ShouldBypass(DWORD mask)
{
    return (g_Config.bypassMask & mask) != 0;
}

static void InitPaths(HINSTANCE hinst)
{
    GetModuleFileNameW(hinst, g_DllDir, MAX_PATH);

    wchar_t* slash = wcsrchr(g_DllDir, L'\\');
    if (slash)
        *(slash + 1) = L'\0';

    wsprintfW(g_ConfigPath, L"%s%s", g_DllDir, ADT_CONFIG_FILE_NAME);

    wchar_t logDir[MAX_PATH] = {};
    wsprintfW(logDir, L"%s%s", g_DllDir, ADT_LOG_DIR_NAME);
    CreateDirectoryW(logDir, nullptr);

    wsprintfW(g_LogPath, L"%s\\%s", logDir, ADT_LOG_FILE_NAME);

    if (GetPrivateProfileIntW(L"Agent", L"ResetLog", 1, g_ConfigPath))
        DeleteFileW(g_LogPath);
}

static void LoadConfig()
{
    g_Config.detectMask = GetPrivateProfileIntW(L"Agent", L"DetectMask", ADT_FEATURE_ALL, g_ConfigPath);
    g_Config.bypassMask = GetPrivateProfileIntW(L"Agent", L"BypassMask", g_Config.bypassMask, g_ConfigPath);
    g_Config.keepPebClean = GetPrivateProfileIntW(L"Agent", L"KeepPebClean", 0, g_ConfigPath) != 0;
}

static void AppendLogRaw(const char* text)
{
    if (!g_LogLockReady || g_LogPath[0] == L'\0')
        return;

    EnterCriticalSection(&g_LogLock);

    HANDLE file = CreateFileW(
        g_LogPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (file != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(file, text, static_cast<DWORD>(strlen(text)), &written, nullptr);
        CloseHandle(file);
    }

    LeaveCriticalSection(&g_LogLock);
}

static void AppendLogf(const char* format, ...)
{
    char buffer[768] = {};
    va_list args;
    va_start(args, format);
    vsnprintf_s(buffer, sizeof(buffer), _TRUNCATE, format, args);
    va_end(args);
    AppendLogRaw(buffer);
}

static void BuildAbsJmp14(void* dst, unsigned char out[14])
{
    out[0] = 0xFF;
    out[1] = 0x25;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x00;
    memcpy(out + 6, &dst, sizeof(dst));
}

static bool InstallInlineHook14(HookContext& ctx)
{
    if (!ctx.target || !ctx.detour)
        return false;

    if (ctx.installed)
        return true;

    DWORD oldProtect = 0;
    if (!VirtualProtect(ctx.target, ctx.patchLen, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    if (!ctx.originalSaved)
    {
        memcpy(ctx.original, ctx.target, ctx.patchLen);
        ctx.originalSaved = true;
    }

    unsigned char patch[14] = {};
    BuildAbsJmp14(ctx.detour, patch);
    memcpy(ctx.target, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), ctx.target, ctx.patchLen);

    DWORD dummy = 0;
    VirtualProtect(ctx.target, ctx.patchLen, oldProtect, &dummy);
    ctx.installed = true;
    return true;
}

static bool UninstallInlineHook14(HookContext& ctx)
{
    if (!ctx.target || !ctx.originalSaved)
        return false;

    if (!ctx.installed)
        return true;

    DWORD oldProtect = 0;
    if (!VirtualProtect(ctx.target, ctx.patchLen, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(ctx.target, ctx.original, ctx.patchLen);
    FlushInstructionCache(GetCurrentProcess(), ctx.target, ctx.patchLen);

    DWORD dummy = 0;
    VirtualProtect(ctx.target, ctx.patchLen, oldProtect, &dummy);
    ctx.installed = false;
    return true;
}

static bool InstallHookByName(HMODULE module, const char* procName, void* detour, HookContext& ctx)
{
    FARPROC target = GetProcAddress(module, procName);
    if (!target)
    {
        AppendLogf("{\"event\":\"hook_missing\",\"api\":\"%s\"}\r\n", procName);
        return false;
    }

    ctx.target = reinterpret_cast<void*>(target);
    ctx.detour = detour;

    bool ok = InstallInlineHook14(ctx);
    AppendLogf(
        "{\"event\":\"hook_%s\",\"api\":\"%s\"}\r\n",
        ok ? "installed" : "failed",
        procName
    );
    return ok;
}

template <typename T>
static T CallOriginal0(HookContext& hook, T(WINAPI* fn)())
{
    bool wasInstalled = hook.installed;
    if (wasInstalled)
        UninstallInlineHook14(hook);

    T result = fn();

    if (wasInstalled)
        InstallInlineHook14(hook);

    return result;
}

template <typename T, typename A1, typename A2>
static T CallOriginal2(HookContext& hook, T(WINAPI* fn)(A1, A2), A1 a1, A2 a2)
{
    bool wasInstalled = hook.installed;
    if (wasInstalled)
        UninstallInlineHook14(hook);

    T result = fn(a1, a2);

    if (wasInstalled)
        InstallInlineHook14(hook);

    return result;
}

template <typename T, typename A1, typename A2, typename A3, typename A4>
static T CallOriginal4Nt(HookContext& hook, T(NTAPI* fn)(A1, A2, A3, A4), A1 a1, A2 a2, A3 a3, A4 a4)
{
    bool wasInstalled = hook.installed;
    if (wasInstalled)
        UninstallInlineHook14(hook);

    T result = fn(a1, a2, a3, a4);

    if (wasInstalled)
        InstallInlineHook14(hook);

    return result;
}

template <typename T, typename A1, typename A2, typename A3, typename A4, typename A5>
static T CallOriginal5Nt(HookContext& hook, T(NTAPI* fn)(A1, A2, A3, A4, A5), A1 a1, A2 a2, A3 a3, A4 a4, A5 a5)
{
    bool wasInstalled = hook.installed;
    if (wasInstalled)
        UninstallInlineHook14(hook);

    T result = fn(a1, a2, a3, a4, a5);

    if (wasInstalled)
        InstallInlineHook14(hook);

    return result;
}

template <typename A1>
static void CallOriginalVoid1(HookContext& hook, void(WINAPI* fn)(A1), A1 a1)
{
    bool wasInstalled = hook.installed;
    if (wasInstalled)
        UninstallInlineHook14(hook);

    fn(a1);

    if (wasInstalled)
        InstallInlineHook14(hook);
}

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

static void ObserveAndCleanPeb(const char* phase, bool emitLog)
{
    unsigned char* peb = GetPeb();
    if (!peb)
        return;

    BYTE oldBeingDebugged = *(peb + PEB_BEING_DEBUGGED_OFFSET);
    DWORD* ntGlobalFlagPtr = reinterpret_cast<DWORD*>(peb + PEB_NT_GLOBAL_FLAG_OFFSET);
    DWORD oldNtGlobalFlag = *ntGlobalFlagPtr;

    if (emitLog && (ShouldDetect(ADT_FEATURE_PEB_BEING_DEBUGGED) || ShouldDetect(ADT_FEATURE_PEB_NT_GLOBAL_FLAG)))
    {
        AppendLogf(
            "{\"event\":\"peb_observed\",\"phase\":\"%s\",\"BeingDebugged\":%u,\"NtGlobalFlag\":%lu}\r\n",
            phase,
            static_cast<unsigned>(oldBeingDebugged),
            oldNtGlobalFlag
        );
    }

    if (ShouldBypass(ADT_FEATURE_PEB_BEING_DEBUGGED))
        *(peb + PEB_BEING_DEBUGGED_OFFSET) = 0;

    if (ShouldBypass(ADT_FEATURE_PEB_NT_GLOBAL_FLAG))
        *ntGlobalFlagPtr = oldNtGlobalFlag & ~0x70UL;

    if (emitLog && (ShouldBypass(ADT_FEATURE_PEB_BEING_DEBUGGED) || ShouldBypass(ADT_FEATURE_PEB_NT_GLOBAL_FLAG)))
    {
        AppendLogf(
            "{\"event\":\"peb_cleaned\",\"phase\":\"%s\",\"BeingDebugged\":%u,\"NtGlobalFlag\":%lu}\r\n",
            phase,
            static_cast<unsigned>(*(peb + PEB_BEING_DEBUGGED_OFFSET)),
            *ntGlobalFlagPtr
        );
    }
}

static bool CleanOneHeapFlags(HANDLE heap, bool doClean, DWORD& oldFlags, DWORD& newFlags, DWORD& oldForceFlags, DWORD& newForceFlags)
{
    if (!heap)
        return false;

    __try
    {
        unsigned char* heapBytes = reinterpret_cast<unsigned char*>(heap);
        DWORD* flags = reinterpret_cast<DWORD*>(heapBytes + HEAP_FLAGS_OFFSET);
        DWORD* forceFlags = reinterpret_cast<DWORD*>(heapBytes + HEAP_FORCE_FLAGS_OFFSET);

        oldFlags = *flags;
        oldForceFlags = *forceFlags;

        bool looksLikeNtHeap =
            (oldFlags & HEAP_GROWABLE) != 0 ||
            (oldFlags & HEAP_DEBUG_FLAGS_MASK) != 0 ||
            (oldForceFlags & HEAP_DEBUG_FLAGS_MASK) != 0;

        if (!looksLikeNtHeap)
            return false;

        newFlags = (oldFlags & ~HEAP_DEBUG_FLAGS_MASK) | HEAP_GROWABLE;
        newForceFlags = oldForceFlags & ~HEAP_DEBUG_FLAGS_MASK;

        if (oldForceFlags == HEAP_DEBUG_FLAGS_MASK || oldForceFlags == 0x40000000)
            newForceFlags = 0;

        if (doClean)
        {
            *flags = newFlags;
            *forceFlags = newForceFlags;
        }

        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

static void ObserveAndCleanHeapFlags(const char* phase, bool emitLog)
{
    if (!ShouldDetect(ADT_FEATURE_PEB_HEAP_FLAGS) && !ShouldBypass(ADT_FEATURE_PEB_HEAP_FLAGS))
        return;

    HANDLE heaps[64] = {};
    constexpr DWORD heapCapacity = static_cast<DWORD>(sizeof(heaps) / sizeof(heaps[0]));
    DWORD heapCount = GetProcessHeaps(heapCapacity, heaps);
    if (heapCount > heapCapacity)
        heapCount = heapCapacity;

    DWORD cleaned = 0;
    DWORD observed = 0;

    for (DWORD i = 0; i < heapCount; ++i)
    {
        DWORD oldFlags = 0;
        DWORD newFlags = 0;
        DWORD oldForceFlags = 0;
        DWORD newForceFlags = 0;

        bool doClean = ShouldBypass(ADT_FEATURE_PEB_HEAP_FLAGS);

        if (!CleanOneHeapFlags(heaps[i], doClean, oldFlags, newFlags, oldForceFlags, newForceFlags))
            continue;

        ++observed;

        if (!doClean)
            continue;

        ++cleaned;

        if (emitLog && i == 0)
        {
            AppendLogf(
                "{\"event\":\"heap_flags_cleaned\",\"phase\":\"%s\",\"heap_index\":%lu,\"old_flags\":%lu,\"new_flags\":%lu,\"old_force_flags\":%lu,\"new_force_flags\":%lu}\r\n",
                phase,
                i,
                oldFlags,
                newFlags,
                oldForceFlags,
                newForceFlags
            );
        }
    }

    if (emitLog && ShouldDetect(ADT_FEATURE_PEB_HEAP_FLAGS))
    {
        AppendLogf(
            "{\"event\":\"heap_flags_summary\",\"phase\":\"%s\",\"observed_heaps\":%lu,\"cleaned_heaps\":%lu}\r\n",
            phase,
            observed,
            cleaned
        );
    }
}

static DWORD WINAPI PebKeeperThread(LPVOID)
{
    for (;;)
    {
        ObserveAndCleanPeb("keep_alive", false);
        ObserveAndCleanHeapFlags("keep_alive", false);
        Sleep(500);
    }
}

extern "C" __declspec(noinline) BOOL WINAPI Hook_IsDebuggerPresent()
{
    if (g_InIsDebuggerPresent)
        return FALSE;

    g_InIsDebuggerPresent = true;

    BOOL original = FALSE;
    if (g_RealIsDebuggerPresent && !ShouldBypass(ADT_FEATURE_IS_DEBUGGER_PRESENT))
        original = CallOriginal0<BOOL>(g_IsDebuggerPresentHook, g_RealIsDebuggerPresent);

    BOOL cleaned = ShouldBypass(ADT_FEATURE_IS_DEBUGGER_PRESENT) ? FALSE : original;

    if (ShouldDetect(ADT_FEATURE_IS_DEBUGGER_PRESENT))
    {
        AppendLogf(
            "{\"api\":\"IsDebuggerPresent\",\"orig_ret\":%d,\"clean_ret\":%d,\"bypass\":%d}\r\n",
            original,
            cleaned,
            ShouldBypass(ADT_FEATURE_IS_DEBUGGER_PRESENT) ? 1 : 0
        );
    }

    g_InIsDebuggerPresent = false;
    return cleaned;
}

extern "C" __declspec(noinline) BOOL WINAPI Hook_CheckRemoteDebuggerPresent(HANDLE process, PBOOL debuggerPresent)
{
    if (g_InCheckRemoteDebuggerPresent)
        return TRUE;

    g_InCheckRemoteDebuggerPresent = true;

    BOOL originalFlag = FALSE;
    BOOL originalResult = TRUE;

    if (g_RealCheckRemoteDebuggerPresent && !ShouldBypass(ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT))
    {
        BOOL temp = FALSE;
        originalResult = CallOriginal2<BOOL, HANDLE, PBOOL>(
            g_CheckRemoteDebuggerPresentHook,
            g_RealCheckRemoteDebuggerPresent,
            process,
            &temp
        );
        originalFlag = temp;
        if (debuggerPresent)
            *debuggerPresent = temp;
    }

    if (ShouldBypass(ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT))
    {
        if (debuggerPresent)
            *debuggerPresent = FALSE;
        originalResult = TRUE;
    }

    if (ShouldDetect(ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT))
    {
        AppendLogf(
            "{\"api\":\"CheckRemoteDebuggerPresent\",\"orig_flag\":%d,\"clean_flag\":%d,\"bypass\":%d}\r\n",
            originalFlag,
            debuggerPresent ? *debuggerPresent : 0,
            ShouldBypass(ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT) ? 1 : 0
        );
    }

    g_InCheckRemoteDebuggerPresent = false;
    return originalResult;
}

static DWORD FeatureForProcessInformationClass(ULONG infoClass)
{
    if (infoClass == ProcessDebugPortValue)
        return ADT_FEATURE_NT_QUERY_DEBUG_PORT;
    if (infoClass == ProcessDebugObjectHandleValue)
        return ADT_FEATURE_NT_QUERY_DEBUG_OBJECT;
    if (infoClass == ProcessDebugFlagsValue)
        return ADT_FEATURE_NT_QUERY_DEBUG_FLAGS;
    return 0;
}

extern "C" __declspec(noinline) NTSTATUS NTAPI Hook_NtQueryInformationProcess(
    HANDLE process,
    ULONG infoClass,
    PVOID processInformation,
    ULONG processInformationLength,
    PULONG returnLength
)
{
    DWORD feature = FeatureForProcessInformationClass(infoClass);

    if (g_InNtQueryInformationProcess)
        return STATUS_INVALID_INFO_CLASS;

    g_InNtQueryInformationProcess = true;

    if (feature != 0 && ShouldBypass(feature))
    {
        if (infoClass == ProcessDebugPortValue && processInformation && processInformationLength >= sizeof(ULONG_PTR))
        {
            *reinterpret_cast<ULONG_PTR*>(processInformation) = 0;
            if (returnLength)
                *returnLength = sizeof(ULONG_PTR);
            if (ShouldDetect(feature))
                AppendLogRaw("{\"api\":\"NtQueryInformationProcess\",\"class\":7,\"clean\":\"DebugPort=0\",\"bypass\":1}\r\n");
            g_InNtQueryInformationProcess = false;
            return STATUS_SUCCESS;
        }

        if (infoClass == ProcessDebugObjectHandleValue && processInformation && processInformationLength >= sizeof(HANDLE))
        {
            *reinterpret_cast<HANDLE*>(processInformation) = nullptr;
            if (returnLength)
                *returnLength = sizeof(HANDLE);
            if (ShouldDetect(feature))
                AppendLogRaw("{\"api\":\"NtQueryInformationProcess\",\"class\":30,\"clean\":\"DebugObjectHandle=NULL\",\"bypass\":1}\r\n");
            g_InNtQueryInformationProcess = false;
            return STATUS_SUCCESS;
        }

        if (infoClass == ProcessDebugFlagsValue && processInformation && processInformationLength >= sizeof(ULONG))
        {
            *reinterpret_cast<ULONG*>(processInformation) = 1;
            if (returnLength)
                *returnLength = sizeof(ULONG);
            if (ShouldDetect(feature))
                AppendLogRaw("{\"api\":\"NtQueryInformationProcess\",\"class\":31,\"clean\":\"DebugFlags=1\",\"bypass\":1}\r\n");
            g_InNtQueryInformationProcess = false;
            return STATUS_SUCCESS;
        }
    }

    NTSTATUS status = STATUS_INVALID_INFO_CLASS;
    if (g_RealNtQueryInformationProcess)
    {
        status = CallOriginal5Nt<NTSTATUS, HANDLE, ULONG, PVOID, ULONG, PULONG>(
            g_NtQueryInformationProcessHook,
            g_RealNtQueryInformationProcess,
            process,
            infoClass,
            processInformation,
            processInformationLength,
            returnLength
        );
    }

    if (feature != 0 && ShouldDetect(feature))
    {
        unsigned long long value = 0;
        if (processInformation)
        {
            if (infoClass == ProcessDebugPortValue && processInformationLength >= sizeof(ULONG_PTR))
                value = *reinterpret_cast<ULONG_PTR*>(processInformation);
            else if (infoClass == ProcessDebugObjectHandleValue && processInformationLength >= sizeof(HANDLE))
                value = static_cast<unsigned long long>(
                    reinterpret_cast<ULONG_PTR>(*reinterpret_cast<HANDLE*>(processInformation))
                );
            else if (infoClass == ProcessDebugFlagsValue && processInformationLength >= sizeof(ULONG))
                value = *reinterpret_cast<ULONG*>(processInformation);
        }

        AppendLogf(
            "{\"api\":\"NtQueryInformationProcess\",\"class\":%lu,\"status\":%ld,\"orig_value\":%llu,\"bypass\":0}\r\n",
            infoClass,
            status,
            value
        );
    }

    g_InNtQueryInformationProcess = false;
    return status;
}

extern "C" __declspec(noinline) VOID WINAPI Hook_OutputDebugStringA(LPCSTR text)
{
    if (g_InOutputDebugStringA)
        return;

    g_InOutputDebugStringA = true;

    if (ShouldDetect(ADT_FEATURE_OUTPUT_DEBUG_STRING))
    {
        int len = text ? lstrlenA(text) : 0;
        AppendLogf(
            "{\"api\":\"OutputDebugStringA\",\"length\":%d,\"bypass\":%d}\r\n",
            len,
            ShouldBypass(ADT_FEATURE_OUTPUT_DEBUG_STRING) ? 1 : 0
        );
    }

    if (!ShouldBypass(ADT_FEATURE_OUTPUT_DEBUG_STRING) && g_RealOutputDebugStringA)
        CallOriginalVoid1<LPCSTR>(g_OutputDebugStringAHook, g_RealOutputDebugStringA, text);

    g_InOutputDebugStringA = false;
}

extern "C" __declspec(noinline) VOID WINAPI Hook_OutputDebugStringW(LPCWSTR text)
{
    if (g_InOutputDebugStringW)
        return;

    g_InOutputDebugStringW = true;

    if (ShouldDetect(ADT_FEATURE_OUTPUT_DEBUG_STRING))
    {
        int len = text ? lstrlenW(text) : 0;
        AppendLogf(
            "{\"api\":\"OutputDebugStringW\",\"length\":%d,\"bypass\":%d}\r\n",
            len,
            ShouldBypass(ADT_FEATURE_OUTPUT_DEBUG_STRING) ? 1 : 0
        );
    }

    if (!ShouldBypass(ADT_FEATURE_OUTPUT_DEBUG_STRING) && g_RealOutputDebugStringW)
        CallOriginalVoid1<LPCWSTR>(g_OutputDebugStringWHook, g_RealOutputDebugStringW, text);

    g_InOutputDebugStringW = false;
}

extern "C" __declspec(noinline) NTSTATUS NTAPI Hook_NtSetInformationThread(
    HANDLE thread,
    ULONG infoClass,
    PVOID threadInformation,
    ULONG threadInformationLength
)
{
    if (g_InNtSetInformationThread)
        return STATUS_INVALID_INFO_CLASS;

    g_InNtSetInformationThread = true;

    bool hideFromDebugger = infoClass == ThreadHideFromDebuggerValue;
    if (hideFromDebugger && ShouldDetect(ADT_FEATURE_NT_SET_INFORMATION_THREAD))
    {
        AppendLogf(
            "{\"api\":\"NtSetInformationThread\",\"class\":%lu,\"bypass\":%d}\r\n",
            infoClass,
            ShouldBypass(ADT_FEATURE_NT_SET_INFORMATION_THREAD) ? 1 : 0
        );
    }

    if (hideFromDebugger && ShouldBypass(ADT_FEATURE_NT_SET_INFORMATION_THREAD))
    {
        g_InNtSetInformationThread = false;
        return STATUS_SUCCESS;
    }

    NTSTATUS status = STATUS_INVALID_INFO_CLASS;
    if (g_RealNtSetInformationThread)
    {
        status = CallOriginal4Nt<NTSTATUS, HANDLE, ULONG, PVOID, ULONG>(
            g_NtSetInformationThreadHook,
            g_RealNtSetInformationThread,
            thread,
            infoClass,
            threadInformation,
            threadInformationLength
        );
    }

    g_InNtSetInformationThread = false;
    return status;
}

extern "C" __declspec(noinline) BOOL WINAPI Hook_GetThreadContext(HANDLE thread, LPCONTEXT context)
{
    if (g_InGetThreadContext)
        return FALSE;

    g_InGetThreadContext = true;

    BOOL ok = FALSE;
    if (g_RealGetThreadContext)
        ok = CallOriginal2<BOOL, HANDLE, LPCONTEXT>(g_GetThreadContextHook, g_RealGetThreadContext, thread, context);

    bool touchedDebugRegisters = false;
    if (ok && context && ShouldBypass(ADT_FEATURE_GET_THREAD_CONTEXT))
    {
        if ((context->ContextFlags & CONTEXT_DEBUG_REGISTERS) != 0)
        {
            context->Dr0 = 0;
            context->Dr1 = 0;
            context->Dr2 = 0;
            context->Dr3 = 0;
            context->Dr6 = 0;
            context->Dr7 = 0;
            touchedDebugRegisters = true;
        }
    }

    if (ShouldDetect(ADT_FEATURE_GET_THREAD_CONTEXT))
    {
        AppendLogf(
            "{\"api\":\"GetThreadContext\",\"ok\":%d,\"debug_registers_cleaned\":%d,\"bypass\":%d}\r\n",
            ok,
            touchedDebugRegisters ? 1 : 0,
            ShouldBypass(ADT_FEATURE_GET_THREAD_CONTEXT) ? 1 : 0
        );
    }

    g_InGetThreadContext = false;
    return ok;
}

static void InstallConfiguredHooks()
{
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    if (!kernel32 || !ntdll)
    {
        AppendLogRaw("{\"event\":\"module_lookup_failed\"}\r\n");
        return;
    }

    if (FeatureEnabled(ADT_FEATURE_IS_DEBUGGER_PRESENT))
    {
        g_RealIsDebuggerPresent = reinterpret_cast<IsDebuggerPresent_t>(GetProcAddress(kernel32, "IsDebuggerPresent"));
        InstallHookByName(kernel32, "IsDebuggerPresent", reinterpret_cast<void*>(&Hook_IsDebuggerPresent), g_IsDebuggerPresentHook);
    }

    if (FeatureEnabled(ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT))
    {
        g_RealCheckRemoteDebuggerPresent = reinterpret_cast<CheckRemoteDebuggerPresent_t>(GetProcAddress(kernel32, "CheckRemoteDebuggerPresent"));
        InstallHookByName(kernel32, "CheckRemoteDebuggerPresent", reinterpret_cast<void*>(&Hook_CheckRemoteDebuggerPresent), g_CheckRemoteDebuggerPresentHook);
    }

    if (FeatureEnabled(ADT_FEATURE_NT_QUERY_INFORMATION_PROCESS))
    {
        g_RealNtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
        InstallHookByName(ntdll, "NtQueryInformationProcess", reinterpret_cast<void*>(&Hook_NtQueryInformationProcess), g_NtQueryInformationProcessHook);
    }

    if (FeatureEnabled(ADT_FEATURE_OUTPUT_DEBUG_STRING))
    {
        g_RealOutputDebugStringA = reinterpret_cast<OutputDebugStringA_t>(GetProcAddress(kernel32, "OutputDebugStringA"));
        g_RealOutputDebugStringW = reinterpret_cast<OutputDebugStringW_t>(GetProcAddress(kernel32, "OutputDebugStringW"));
        InstallHookByName(kernel32, "OutputDebugStringA", reinterpret_cast<void*>(&Hook_OutputDebugStringA), g_OutputDebugStringAHook);
        InstallHookByName(kernel32, "OutputDebugStringW", reinterpret_cast<void*>(&Hook_OutputDebugStringW), g_OutputDebugStringWHook);
    }

    if (FeatureEnabled(ADT_FEATURE_NT_SET_INFORMATION_THREAD))
    {
        g_RealNtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(GetProcAddress(ntdll, "NtSetInformationThread"));
        InstallHookByName(ntdll, "NtSetInformationThread", reinterpret_cast<void*>(&Hook_NtSetInformationThread), g_NtSetInformationThreadHook);
    }

    if (FeatureEnabled(ADT_FEATURE_GET_THREAD_CONTEXT))
    {
        g_RealGetThreadContext = reinterpret_cast<GetThreadContext_t>(GetProcAddress(kernel32, "GetThreadContext"));
        InstallHookByName(kernel32, "GetThreadContext", reinterpret_cast<void*>(&Hook_GetThreadContext), g_GetThreadContextHook);
    }
}

static void UninstallAllHooks()
{
    UninstallInlineHook14(g_GetThreadContextHook);
    UninstallInlineHook14(g_NtSetInformationThreadHook);
    UninstallInlineHook14(g_OutputDebugStringWHook);
    UninstallInlineHook14(g_OutputDebugStringAHook);
    UninstallInlineHook14(g_NtQueryInformationProcessHook);
    UninstallInlineHook14(g_CheckRemoteDebuggerPresentHook);
    UninstallInlineHook14(g_IsDebuggerPresentHook);
}

static DWORD WINAPI BootstrapThread(LPVOID)
{
    LoadConfig();

    AppendLogf(
        "{\"event\":\"agent_loaded\",\"pid\":%lu,\"detect_mask\":%lu,\"bypass_mask\":%lu}\r\n",
        GetCurrentProcessId(),
        g_Config.detectMask,
        g_Config.bypassMask
    );

    ObserveAndCleanPeb("startup", true);
    ObserveAndCleanHeapFlags("startup", true);
    InstallConfiguredHooks();

    if (g_Config.keepPebClean &&
        (ShouldBypass(ADT_FEATURE_PEB_BEING_DEBUGGED) ||
            ShouldBypass(ADT_FEATURE_PEB_NT_GLOBAL_FLAG) ||
            ShouldBypass(ADT_FEATURE_PEB_HEAP_FLAGS)))
    {
        HANDLE thread = CreateThread(nullptr, 0, PebKeeperThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }

    return 0;
}

BOOL APIENTRY DllMain(HINSTANCE hinst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinst);
        InitPaths(hinst);
        InitializeCriticalSection(&g_LogLock);
        g_LogLockReady = true;

        HANDLE thread = CreateThread(nullptr, 0, BootstrapThread, nullptr, 0, nullptr);
        if (thread)
            CloseHandle(thread);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        UninstallAllHooks();

        if (g_LogLockReady)
        {
            g_LogLockReady = false;
            DeleteCriticalSection(&g_LogLock);
        }
    }

    return TRUE;
}
