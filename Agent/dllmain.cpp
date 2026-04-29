// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <windows.h>
#include <cstring>
static void AppendLog(const char* text) {
    wchar_t tempPath[MAX_PATH] = {};
    GetTempPathW(MAX_PATH,tempPath);
    wchar_t logPath[MAX_PATH] = {};
    wsprintfW(logPath, L"%sAntiDebugTimeline_demo.jsonl", tempPath);
    HANDLE hFile = CreateFileW(
        logPath,
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
    WriteFile(hFile, text, lstrlenA(text), &written, nullptr);
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
static DWORD WINAPI BootstrapThread(LPVOID)
{
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32)
        return 1;

    FARPROC pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
    if (!pIsDebuggerPresent)
        return 2;

    g_IsDebuggerPresentHook.target = reinterpret_cast<void*>(pIsDebuggerPresent);
    g_IsDebuggerPresentHook.detour = reinterpret_cast<void*>(&Hook_IsDebuggerPresent);

    if (!InstallInlineHook14(g_IsDebuggerPresentHook))
        return 3;

    AppendLog("{\"event\":\"hook_installed\",\"api\":\"IsDebuggerPresent\"}\r\n");

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

