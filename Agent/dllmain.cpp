// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <cstring>
#include <cwchar>
static wchar_t g_LogPath[MAX_PATH] = {};
static void InitLogPath(HINSTANCE hinst)
{
    wchar_t dllPath[MAX_PATH] = {};
    GetModuleFileNameW(hinst, dllPath, MAX_PATH);

    wchar_t* lastSlash = wcsrchr(dllPath, L'\\');
    if (lastSlash)
        *(lastSlash + 1) = L'\0';

    wchar_t logDir[MAX_PATH] = {};
    wsprintfW(logDir, L"%slogs", dllPath);

    CreateDirectoryW(logDir, nullptr);

    wsprintfW(g_LogPath, L"%s\\AntiDebugTimeline.jsonl", logDir);

    DeleteFileW(g_LogPath); // 每次注入时清理旧日志
}
static void AppendLog(const char* text)
{
    if (g_LogPath[0] == L'\0')
        return;
    HANDLE hFile = CreateFileW(
        g_LogPath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE)
        return;
    DWORD written = 0;

    WriteFile(
        hFile,
        text,
        static_cast<DWORD>(strlen(text)),
        &written,
        nullptr
    );

    CloseHandle(hFile);
}
struct HookContext
{
    void* target = nullptr;
    void* detour = nullptr; //hook 后要跳过去的函数
    unsigned char original[16] = {};
    size_t patchLen = 14;
};

static HookContext g_IsDebuggerPresentHook{};
static HookContext g_CheckRemoteDebuggerPresentHook{};

static void BuildAbsJmp14(void* dst, unsigned char out[14])
{
    out[0] = 0xFF;
    out[1] = 0x25;
    out[2] = 0x00;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x00;//JMP [rip+0x00]
                  //64位任意地址
    memcpy(out + 6, &dst, sizeof(dst));
}
extern "C" __declspec(noinline) BOOL WINAPI Hook_IsDebuggerPresent() // WINAPI:Windows API 的调用约定宏
{
    AppendLog("{\"api\":\"IsDebuggerPresent\",\"clean_ret\":false}\r\n");
    return FALSE;
}
extern "C" __declspec(noinline) BOOL WINAPI Hook_CheckRemoteDebuggerPresent(
    HANDLE hProcess,
    PBOOL pbDebuggerPresent
)
{
    if (pbDebuggerPresent)
        *pbDebuggerPresent = FALSE;

    AppendLog("{\"api\":\"CheckRemoteDebuggerPresent\",\"clean_ret\":false}\r\n");

    return TRUE;
}
static bool InstallInlineHook14(HookContext& ctx)
{
    DWORD oldProtect = 0;
    if(!VirtualProtect(ctx.target,ctx.patchLen,PAGE_EXECUTE_READWRITE,&oldProtect))
    {
        return false;
    }
    memcpy(ctx.original, ctx.target, ctx.patchLen);
    unsigned char patch[14] = {};
    BuildAbsJmp14(ctx.detour, patch);
    memcpy(ctx.target, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), ctx.target, ctx.patchLen);//刷新指令缓存

    DWORD dummy = 0;
    VirtualProtect(ctx.target, ctx.patchLen, oldProtect, &dummy);

    return true;
}
static bool UninstallInlineHook14(HookContext& ctx)
{
    DWORD oldProtect = 0;

    if (!VirtualProtect(ctx.target, ctx.patchLen, PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(ctx.target, ctx.original, ctx.patchLen);

    FlushInstructionCache(GetCurrentProcess(), ctx.target, ctx.patchLen);

    DWORD dummy = 0;
    VirtualProtect(ctx.target, ctx.patchLen, oldProtect, &dummy);

    return true;
}
static DWORD WINAPI BootstrapThread(LPVOID)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
        return 1;

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pIsDebuggerPresent)
        return 2;
    FARPROC pCheckRemoteDebuggerPresent =
        GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");
    g_IsDebuggerPresentHook.target = reinterpret_cast<void*>(pIsDebuggerPresent);
    g_IsDebuggerPresentHook.detour = reinterpret_cast<void*>(&Hook_IsDebuggerPresent);
    g_CheckRemoteDebuggerPresentHook.target = reinterpret_cast<void*>(pCheckRemoteDebuggerPresent);
    g_CheckRemoteDebuggerPresentHook.detour = reinterpret_cast<void*>(&Hook_CheckRemoteDebuggerPresent);
    if (!InstallInlineHook14(g_IsDebuggerPresentHook))
        return 3;
    if (!InstallInlineHook14(g_CheckRemoteDebuggerPresentHook))
        return 3;
    AppendLog("{\"event\":\"hook_installed\",\"api\":\"IsDebuggerPresent\"}\r\n");
    AppendLog("{\"event\":\"hook_installed\",\"api\":\"CheckRemoteDebuggerPresentHook\"}\r\n");
    Sleep(2000);

    return 0;
}
BOOL APIENTRY DllMain(
    HINSTANCE hinst,
    DWORD reason, 
    LPVOID reserved
)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinst);
        InitLogPath(hinst);
        AppendLog("{\"event\":\"agent_loaded\"}\r\n");
        HANDLE hThread = CreateThread(
            nullptr,
            0,
            BootstrapThread,
            nullptr,
            0,
            nullptr
        );
        if (hThread) CloseHandle(hThread);
        return TRUE;
    }

    return TRUE;
}

