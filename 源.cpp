#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <windowsx.h>

#include <algorithm>
#include <cwctype>
#include <string>
#include <vector>

#include "Shared/AntiDebugConfig.h"

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Comdlg32.lib")

namespace
{
    constexpr int ID_PROCESS_LIST = 1001;
    constexpr int ID_REFRESH = 1002;
    constexpr int ID_INJECT = 1003;
    constexpr int ID_BROWSE_AGENT = 1004;
    constexpr int ID_AGENT_PATH = 1005;
    constexpr int ID_STATUS = 1006;
    constexpr int ID_LOG = 1007;
    constexpr int ID_OPEN_LOG = 1008;
    constexpr int ID_DETECT_ALL = 1009;
    constexpr int ID_SEARCH_PROCESS = 1010;
    constexpr int ID_TARGET_PATH = 1011;
    constexpr int ID_BROWSE_TARGET = 1012;
    constexpr int ID_LAUNCH_SUSPENDED = 1013;
    constexpr int ID_RESUME_LAUNCHED = 1014;

    constexpr int ID_FEATURE_BASE = 1100;
    constexpr UINT_PTR ID_LOG_TIMER = 1;

    struct ProcessInfo
    {
        DWORD pid = 0;
        std::wstring name;
        std::wstring path;
    };

    struct FeatureOption
    {
        int id = 0;
        DWORD mask = 0;
        const wchar_t* label = nullptr;
        bool checkedByDefault = true;
        HWND hwnd = nullptr;
    };

    HINSTANCE g_Instance = nullptr;
    HWND g_ProcessList = nullptr;
    HWND g_AgentPathEdit = nullptr;
    HWND g_Status = nullptr;
    HWND g_LogEdit = nullptr;
    HWND g_DetectAll = nullptr;
    HWND g_SearchEdit = nullptr;
    HWND g_TargetPathEdit = nullptr;
    HFONT g_Font = nullptr;
    HFONT g_MonoFont = nullptr;

    std::vector<ProcessInfo> g_Processes;
    std::wstring g_AgentPath;
    std::wstring g_TargetPath;
    std::wstring g_LogPath;
    DWORD g_LastLogSize = 0;
    DWORD g_SuspendedPid = 0;

    FeatureOption g_Features[] = {
        { ID_FEATURE_BASE + 0, ADT_FEATURE_IS_DEBUGGER_PRESENT, L"IsDebuggerPresent", true },
        { ID_FEATURE_BASE + 1, ADT_FEATURE_CHECK_REMOTE_DEBUGGER_PRESENT, L"CheckRemoteDebuggerPresent", true },
        { ID_FEATURE_BASE + 2, ADT_FEATURE_NT_QUERY_DEBUG_PORT, L"NtQueryInformationProcess: DebugPort", true },
        { ID_FEATURE_BASE + 3, ADT_FEATURE_NT_QUERY_DEBUG_OBJECT, L"NtQueryInformationProcess: DebugObject", true },
        { ID_FEATURE_BASE + 4, ADT_FEATURE_NT_QUERY_DEBUG_FLAGS, L"NtQueryInformationProcess: DebugFlags", true },
        { ID_FEATURE_BASE + 5, ADT_FEATURE_PEB_BEING_DEBUGGED, L"PEB BeingDebugged", true },
        { ID_FEATURE_BASE + 6, ADT_FEATURE_PEB_NT_GLOBAL_FLAG, L"PEB NtGlobalFlag", true },
        { ID_FEATURE_BASE + 7, ADT_FEATURE_PEB_HEAP_FLAGS, L"PEB Heap Flags / ForceFlags", true },
        { ID_FEATURE_BASE + 8, ADT_FEATURE_OUTPUT_DEBUG_STRING, L"OutputDebugString no-op", false },
        { ID_FEATURE_BASE + 9, ADT_FEATURE_NT_SET_INFORMATION_THREAD, L"NtSetInformationThread HideFromDebugger", true },
        { ID_FEATURE_BASE + 10, ADT_FEATURE_GET_THREAD_CONTEXT, L"GetThreadContext debug registers", true },
    };

    std::wstring GetModuleDirectory()
    {
        wchar_t path[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, path, MAX_PATH);

        wchar_t* slash = wcsrchr(path, L'\\');
        if (slash)
            *(slash + 1) = L'\0';

        return path;
    }

    std::wstring GetDirectoryOfPath(const std::wstring& path)
    {
        std::wstring result = path;
        size_t slash = result.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
            return L"";

        result.resize(slash + 1);
        return result;
    }

    std::wstring CombinePath(const std::wstring& dir, const wchar_t* leaf)
    {
        if (dir.empty())
            return leaf;

        if (dir.back() == L'\\' || dir.back() == L'/')
            return dir + leaf;

        return dir + L"\\" + leaf;
    }

    bool FileExists(const std::wstring& path)
    {
        DWORD attr = GetFileAttributesW(path.c_str());
        return attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
    }

    void SetStatus(const std::wstring& text)
    {
        SetWindowTextW(g_Status, text.c_str());
    }

    void SetChildFont(HWND hwnd)
    {
        if (hwnd && g_Font)
            SendMessageW(hwnd, WM_SETFONT, reinterpret_cast<WPARAM>(g_Font), TRUE);
    }

    HFONT CreateNiceCodeFont()
    {
        LOGFONTW lf = {};
        lf.lfHeight = -16;
        lf.lfWeight = FW_NORMAL;
        lf.lfQuality = CLEARTYPE_QUALITY;
        lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
        wcscpy_s(lf.lfFaceName, L"Cascadia Mono");
        return CreateFontIndirectW(&lf);
    }

    std::wstring ToLowerCopy(std::wstring text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        return text;
    }

    std::wstring QueryProcessPath(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return L"";

        wchar_t path[MAX_PATH] = {};
        DWORD size = MAX_PATH;
        if (!QueryFullProcessImageNameW(process, 0, path, &size))
            path[0] = L'\0';

        CloseHandle(process);
        return path;
    }

    void AddListColumn(int index, int width, const wchar_t* text)
    {
        LVCOLUMNW column = {};
        column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        column.cx = width;
        column.iSubItem = index;
        column.pszText = const_cast<wchar_t*>(text);
        ListView_InsertColumn(g_ProcessList, index, &column);
    }

    bool MatchesProcessFilter(const ProcessInfo& info, const std::wstring& filter)
    {
        if (filter.empty())
            return true;

        wchar_t pidText[32] = {};
        wsprintfW(pidText, L"%lu", info.pid);

        std::wstring haystack = info.name + L" " + info.path + L" " + pidText;
        return ToLowerCopy(haystack).find(filter) != std::wstring::npos;
    }

    void PopulateProcessList()
    {
        ListView_DeleteAllItems(g_ProcessList);

        wchar_t searchText[512] = {};
        if (g_SearchEdit)
            GetWindowTextW(g_SearchEdit, searchText, static_cast<int>(_countof(searchText)));

        std::wstring filter = ToLowerCopy(searchText);
        size_t visibleCount = 0;

        for (size_t i = 0; i < g_Processes.size(); ++i)
        {
            const ProcessInfo& info = g_Processes[i];
            if (!MatchesProcessFilter(info, filter))
                continue;

            wchar_t pidText[32] = {};
            wsprintfW(pidText, L"%lu", info.pid);

            LVITEMW item = {};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = static_cast<int>(visibleCount);
            item.pszText = pidText;
            item.lParam = static_cast<LPARAM>(i);
            int row = ListView_InsertItem(g_ProcessList, &item);
            ListView_SetItemText(g_ProcessList, row, 1, const_cast<wchar_t*>(info.name.c_str()));
            ListView_SetItemText(g_ProcessList, row, 2, const_cast<wchar_t*>(info.path.c_str()));
            ++visibleCount;
        }

        wchar_t status[160] = {};
        if (filter.empty())
        {
            wsprintfW(status, L"Loaded %lu processes. Select one target and click Inject.", static_cast<DWORD>(g_Processes.size()));
        }
        else
        {
            wsprintfW(
                status,
                L"Showing %lu of %lu processes for \"%s\".",
                static_cast<DWORD>(visibleCount),
                static_cast<DWORD>(g_Processes.size()),
                searchText
            );
        }
        SetStatus(status);
    }

    void RefreshProcessList()
    {
        g_Processes.clear();

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            SetStatus(L"CreateToolhelp32Snapshot failed.");
            return;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);

        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                ProcessInfo info;
                info.pid = entry.th32ProcessID;
                info.name = entry.szExeFile;
                info.path = QueryProcessPath(info.pid);
                g_Processes.push_back(info);
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);

        std::sort(g_Processes.begin(), g_Processes.end(), [](const ProcessInfo& a, const ProcessInfo& b) {
            int nameCmp = _wcsicmp(a.name.c_str(), b.name.c_str());
            if (nameCmp != 0)
                return nameCmp < 0;
            return a.pid < b.pid;
        });

        PopulateProcessList();
    }

    bool GetSelectedProcess(ProcessInfo& info)
    {
        int row = ListView_GetNextItem(g_ProcessList, -1, LVNI_SELECTED);
        if (row < 0)
            return false;

        LVITEMW item = {};
        item.mask = LVIF_PARAM;
        item.iItem = row;
        if (!ListView_GetItem(g_ProcessList, &item))
            return false;

        size_t index = static_cast<size_t>(item.lParam);
        if (index >= g_Processes.size())
            return false;

        info = g_Processes[index];
        return true;
    }

    DWORD GetBypassMask()
    {
        DWORD mask = 0;
        for (const FeatureOption& feature : g_Features)
        {
            if (Button_GetCheck(feature.hwnd) == BST_CHECKED)
                mask |= feature.mask;
        }
        return mask;
    }

    DWORD GetDetectMask(DWORD bypassMask)
    {
        if (Button_GetCheck(g_DetectAll) == BST_CHECKED)
            return ADT_FEATURE_ALL;
        return bypassMask;
    }

    bool WriteAgentConfig(bool earlyLaunch = false)
    {
        wchar_t editPath[MAX_PATH * 2] = {};
        GetWindowTextW(g_AgentPathEdit, editPath, static_cast<int>(_countof(editPath)));
        g_AgentPath = editPath;

        if (!FileExists(g_AgentPath))
        {
            SetStatus(L"Agent.dll does not exist.");
            return false;
        }

        DWORD bypassMask = GetBypassMask();
        DWORD detectMask = GetDetectMask(bypassMask);

        if (earlyLaunch && (bypassMask & ADT_FEATURE_OUTPUT_DEBUG_STRING) == 0)
            detectMask &= ~ADT_FEATURE_OUTPUT_DEBUG_STRING;

        std::wstring agentDir = GetDirectoryOfPath(g_AgentPath);
        std::wstring configPath = CombinePath(agentDir, ADT_CONFIG_FILE_NAME);
        std::wstring logDir = CombinePath(agentDir, ADT_LOG_DIR_NAME);
        g_LogPath = CombinePath(logDir, ADT_LOG_FILE_NAME);

        CreateDirectoryW(logDir.c_str(), nullptr);

        std::wstring bypassText = std::to_wstring(bypassMask);
        std::wstring detectText = std::to_wstring(detectMask);

        BOOL ok = TRUE;
        ok &= WritePrivateProfileStringW(L"Agent", L"DetectMask", detectText.c_str(), configPath.c_str());
        ok &= WritePrivateProfileStringW(L"Agent", L"BypassMask", bypassText.c_str(), configPath.c_str());
        ok &= WritePrivateProfileStringW(L"Agent", L"KeepPebClean", L"0", configPath.c_str());
        ok &= WritePrivateProfileStringW(L"Agent", L"ResetLog", L"1", configPath.c_str());

        if (!ok)
        {
            SetStatus(L"Could not write AntiDebugTimeline.ini.");
            return false;
        }

        DeleteFileW(g_LogPath.c_str());
        g_LastLogSize = 0;
        SetWindowTextW(g_LogEdit, L"");
        return true;
    }

    bool InjectDllIntoProcess(HANDLE process, const std::wstring& dllPath)
    {
        if (!process)
        {
            return false;
        }

        SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
        void* remoteMem = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remoteMem)
        {
            wchar_t message[128] = {};
            wsprintfW(message, L"VirtualAllocEx failed: %lu", GetLastError());
            SetStatus(message);
            return false;
        }

        BOOL written = WriteProcessMemory(process, remoteMem, dllPath.c_str(), bytes, nullptr);
        if (!written)
        {
            wchar_t message[128] = {};
            wsprintfW(message, L"WriteProcessMemory failed: %lu", GetLastError());
            SetStatus(message);
            VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
            return false;
        }

        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC loadLibraryW = kernel32 ? GetProcAddress(kernel32, "LoadLibraryW") : nullptr;
        if (!loadLibraryW)
        {
            SetStatus(L"Could not locate LoadLibraryW.");
            VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
            return false;
        }

        HANDLE thread = CreateRemoteThread(
            process,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryW),
            remoteMem,
            0,
            nullptr
        );

        if (!thread)
        {
            wchar_t message[128] = {};
            wsprintfW(message, L"CreateRemoteThread failed: %lu", GetLastError());
            SetStatus(message);
            VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);
            return false;
        }

        DWORD wait = WaitForSingleObject(thread, 10000);
        DWORD exitCode = 0;
        GetExitCodeThread(thread, &exitCode);

        CloseHandle(thread);
        VirtualFreeEx(process, remoteMem, 0, MEM_RELEASE);

        if (wait != WAIT_OBJECT_0)
        {
            SetStatus(L"Injection thread did not finish within 10 seconds.");
            return false;
        }

        if (exitCode == 0)
        {
            SetStatus(L"LoadLibraryW returned 0. Check Agent bitness and path.");
            return false;
        }

        return true;
    }

    bool InjectDll(DWORD pid, const std::wstring& dllPath)
    {
        HANDLE process = OpenProcess(
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
            FALSE,
            pid
        );

        if (!process)
        {
            wchar_t message[128] = {};
            wsprintfW(message, L"OpenProcess failed: %lu", GetLastError());
            SetStatus(message);
            return false;
        }

        bool ok = InjectDllIntoProcess(process, dllPath);
        CloseHandle(process);
        return ok;
    }

    DWORD SuspendProcessThreads(DWORD pid)
    {
        DWORD currentTid = GetCurrentThreadId();
        DWORD suspended = 0;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        THREADENTRY32 entry = {};
        entry.dwSize = sizeof(entry);

        if (Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID != pid || entry.th32ThreadID == currentTid)
                    continue;

                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
                if (!thread)
                    continue;

                if (SuspendThread(thread) != static_cast<DWORD>(-1))
                    ++suspended;

                CloseHandle(thread);
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return suspended;
    }

    DWORD ResumeProcessThreads(DWORD pid)
    {
        DWORD resumed = 0;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        THREADENTRY32 entry = {};
        entry.dwSize = sizeof(entry);

        if (Thread32First(snapshot, &entry))
        {
            do
            {
                if (entry.th32OwnerProcessID != pid)
                    continue;

                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
                if (!thread)
                    continue;

                for (int i = 0; i < 32; ++i)
                {
                    DWORD previous = ResumeThread(thread);
                    if (previous == static_cast<DWORD>(-1) || previous == 0)
                        break;
                    ++resumed;
                    if (previous == 1)
                        break;
                }

                CloseHandle(thread);
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return resumed;
    }

    std::wstring ReadLogFile()
    {
        HANDLE file = CreateFileW(
            g_LogPath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (file == INVALID_HANDLE_VALUE)
            return L"";

        DWORD size = GetFileSize(file, nullptr);
        if (size == INVALID_FILE_SIZE || size == 0)
        {
            CloseHandle(file);
            return L"";
        }

        constexpr DWORD maxRead = 128 * 1024;
        DWORD offset = size > maxRead ? size - maxRead : 0;
        SetFilePointer(file, static_cast<LONG>(offset), nullptr, FILE_BEGIN);

        std::string bytes;
        bytes.resize(size - offset);

        DWORD read = 0;
        ReadFile(file, &bytes[0], static_cast<DWORD>(bytes.size()), &read, nullptr);
        CloseHandle(file);
        bytes.resize(read);

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
        if (wideLen <= 0)
            wideLen = MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);

        if (wideLen <= 0)
            return L"";

        std::wstring text;
        text.resize(wideLen);
        if (!MultiByteToWideChar(CP_UTF8, 0, bytes.data(), static_cast<int>(bytes.size()), &text[0], wideLen))
            MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), &text[0], wideLen);

        if (offset != 0)
            text.insert(0, L"... log truncated to last 128 KB ...\r\n");

        return text;
    }

    void RefreshLogView(bool force)
    {
        if (g_LogPath.empty())
            return;

        WIN32_FILE_ATTRIBUTE_DATA data = {};
        if (!GetFileAttributesExW(g_LogPath.c_str(), GetFileExInfoStandard, &data))
            return;

        if (!force && data.nFileSizeLow == g_LastLogSize)
            return;

        g_LastLogSize = data.nFileSizeLow;
        std::wstring text = ReadLogFile();
        SetWindowTextW(g_LogEdit, text.c_str());
        SendMessageW(g_LogEdit, EM_LINESCROLL, 0, 0x7fffffff);
    }

    void BrowseAgent()
    {
        wchar_t path[MAX_PATH * 2] = {};
        GetWindowTextW(g_AgentPathEdit, path, static_cast<int>(_countof(path)));

        OPENFILENAMEW ofn = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = GetParent(g_AgentPathEdit);
        ofn.lpstrFilter = L"DLL Files (*.dll)\0*.dll\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = path;
        ofn.nMaxFile = static_cast<DWORD>(_countof(path));
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameW(&ofn))
        {
            SetWindowTextW(g_AgentPathEdit, path);
            g_AgentPath = path;
            std::wstring agentDir = GetDirectoryOfPath(g_AgentPath);
            g_LogPath = CombinePath(CombinePath(agentDir, ADT_LOG_DIR_NAME), ADT_LOG_FILE_NAME);
            RefreshLogView(true);
        }
    }

    void BrowseTargetExe()
    {
        wchar_t path[MAX_PATH * 2] = {};
        GetWindowTextW(g_TargetPathEdit, path, static_cast<int>(_countof(path)));

        OPENFILENAMEW ofn = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = GetParent(g_TargetPathEdit);
        ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = path;
        ofn.nMaxFile = static_cast<DWORD>(_countof(path));
        ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

        if (GetOpenFileNameW(&ofn))
        {
            SetWindowTextW(g_TargetPathEdit, path);
            g_TargetPath = path;
        }
    }

    void InjectSelected()
    {
        ProcessInfo target;
        if (!GetSelectedProcess(target))
        {
            SetStatus(L"Select a process first.");
            return;
        }

        if (!WriteAgentConfig())
            return;

        wchar_t status[256] = {};
        wsprintfW(status, L"Injecting PID %lu (%s)...", target.pid, target.name.c_str());
        SetStatus(status);

        if (!InjectDll(target.pid, g_AgentPath))
            return;

        wsprintfW(status, L"Injected PID %lu (%s). Watching log: %s", target.pid, target.name.c_str(), g_LogPath.c_str());
        SetStatus(status);
        RefreshLogView(true);
    }

    void ResumeLaunchedTarget()
    {
        if (g_SuspendedPid == 0)
        {
            SetStatus(L"No suspended launched target is waiting.");
            return;
        }

        DWORD resumed = ResumeProcessThreads(g_SuspendedPid);

        wchar_t status[256] = {};
        wsprintfW(status, L"Resumed %lu thread suspend counts for launched PID %lu.", resumed, g_SuspendedPid);
        SetStatus(status);
        g_SuspendedPid = 0;
        RefreshProcessList();
    }

    void LaunchSuspendedInjectAndKeepSuspended()
    {
        if (g_SuspendedPid != 0)
        {
            wchar_t message[160] = {};
            wsprintfW(message, L"PID %lu is still suspended. Attach IDA, then click Resume launched first.", g_SuspendedPid);
            SetStatus(message);
            return;
        }

        if (!WriteAgentConfig(true))
            return;

        wchar_t targetPath[MAX_PATH * 2] = {};
        GetWindowTextW(g_TargetPathEdit, targetPath, static_cast<int>(_countof(targetPath)));
        g_TargetPath = targetPath;

        if (!FileExists(g_TargetPath))
        {
            SetStatus(L"Target .exe does not exist.");
            return;
        }

        std::wstring workingDir = GetDirectoryOfPath(g_TargetPath);
        std::wstring commandLine = L"\"" + g_TargetPath + L"\"";

        STARTUPINFOW startup = {};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION processInfo = {};

        BOOL created = CreateProcessW(
            g_TargetPath.c_str(),
            &commandLine[0],
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            workingDir.empty() ? nullptr : workingDir.c_str(),
            &startup,
            &processInfo
        );

        if (!created)
        {
            wchar_t message[160] = {};
            wsprintfW(message, L"CreateProcess(CREATE_SUSPENDED) failed: %lu", GetLastError());
            SetStatus(message);
            return;
        }

        wchar_t status[256] = {};
        wsprintfW(status, L"Created suspended PID %lu. Injecting Agent before temporary startup...", processInfo.dwProcessId);
        SetStatus(status);

        bool injected = InjectDllIntoProcess(processInfo.hProcess, g_AgentPath);
        if (!injected)
        {
            TerminateProcess(processInfo.hProcess, 2);
            CloseHandle(processInfo.hThread);
            CloseHandle(processInfo.hProcess);
            SetStatus(L"Injection failed. Suspended target was terminated.");
            return;
        }

        ResumeThread(processInfo.hThread);
        CloseHandle(processInfo.hThread);

        Sleep(750);

        DWORD suspended = SuspendProcessThreads(processInfo.dwProcessId);
        g_SuspendedPid = processInfo.dwProcessId;

        wsprintfW(
            status,
            L"Injected PID %lu, then suspended %lu thread(s). Attach IDA now, then click Resume launched.",
            processInfo.dwProcessId,
            suspended
        );
        SetStatus(status);

        CloseHandle(processInfo.hProcess);

        RefreshProcessList();
        RefreshLogView(true);
    }

    HWND MakeControl(HWND parent, const wchar_t* className, const wchar_t* text, DWORD style, DWORD exStyle, int id)
    {
        HWND hwnd = CreateWindowExW(
            exStyle,
            className,
            text,
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            10,
            10,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
            g_Instance,
            nullptr
        );
        SetChildFont(hwnd);
        return hwnd;
    }

    void LayoutControls(HWND hwnd)
    {
        RECT rc = {};
        GetClientRect(hwnd, &rc);
        int width = rc.right - rc.left;
        int height = rc.bottom - rc.top;

        int margin = 10;
        int rightWidth = 360;
        int topHeight = 100;
        int statusHeight = 24;
        int logHeight = 145;
        int listWidth = std::max(620, width - rightWidth - margin * 3);
        int listHeight = std::max(220, height - topHeight - logHeight - statusHeight - margin * 5);
        int rightX = margin + listWidth + margin;

        HWND refresh = GetDlgItem(hwnd, ID_REFRESH);
        HWND inject = GetDlgItem(hwnd, ID_INJECT);
        HWND browse = GetDlgItem(hwnd, ID_BROWSE_AGENT);
        HWND browseTarget = GetDlgItem(hwnd, ID_BROWSE_TARGET);
        HWND launchSuspended = GetDlgItem(hwnd, ID_LAUNCH_SUSPENDED);
        HWND resumeLaunched = GetDlgItem(hwnd, ID_RESUME_LAUNCHED);
        HWND openLog = GetDlgItem(hwnd, ID_OPEN_LOG);

        MoveWindow(refresh, margin, margin, 90, 26, TRUE);
        MoveWindow(inject, margin + 100, margin, 90, 26, TRUE);
        MoveWindow(g_AgentPathEdit, margin + 200, margin, listWidth - 290, 26, TRUE);
        MoveWindow(browse, margin + listWidth - 80, margin, 80, 26, TRUE);
        MoveWindow(launchSuspended, margin, margin + 34, 200, 26, TRUE);
        MoveWindow(resumeLaunched, margin + 210, margin + 34, 130, 26, TRUE);
        MoveWindow(g_TargetPathEdit, margin + 350, margin + 34, listWidth - 440, 26, TRUE);
        MoveWindow(browseTarget, margin + listWidth - 80, margin + 34, 80, 26, TRUE);
        MoveWindow(g_SearchEdit, margin, margin + 68, listWidth, 26, TRUE);

        MoveWindow(g_ProcessList, margin, margin + topHeight, listWidth, listHeight, TRUE);

        MoveWindow(g_DetectAll, rightX, margin, rightWidth, 24, TRUE);
        int y = margin + 34;
        for (FeatureOption& feature : g_Features)
        {
            MoveWindow(feature.hwnd, rightX, y, rightWidth, 24, TRUE);
            y += 25;
        }

        MoveWindow(openLog, rightX, y + 8, 120, 28, TRUE);

        int logY = margin + topHeight + listHeight + margin;
        MoveWindow(g_LogEdit, margin, logY, width - margin * 2, logHeight, TRUE);
        MoveWindow(g_Status, margin, height - statusHeight - margin, width - margin * 2, statusHeight, TRUE);
    }

    void CreateMainControls(HWND hwnd)
    {
        g_MonoFont = CreateNiceCodeFont();
        g_Font = g_MonoFont ? g_MonoFont : static_cast<HFONT>(GetStockObject(DEFAULT_GUI_FONT));

        MakeControl(hwnd, L"BUTTON", L"Refresh", BS_PUSHBUTTON, 0, ID_REFRESH);
        MakeControl(hwnd, L"BUTTON", L"Inject", BS_DEFPUSHBUTTON, 0, ID_INJECT);
        MakeControl(hwnd, L"BUTTON", L"Browse", BS_PUSHBUTTON, 0, ID_BROWSE_AGENT);
        MakeControl(hwnd, L"BUTTON", L"Browse exe", BS_PUSHBUTTON, 0, ID_BROWSE_TARGET);
        MakeControl(hwnd, L"BUTTON", L"Launch+inject paused", BS_PUSHBUTTON, 0, ID_LAUNCH_SUSPENDED);
        MakeControl(hwnd, L"BUTTON", L"Resume launched", BS_PUSHBUTTON, 0, ID_RESUME_LAUNCHED);
        MakeControl(hwnd, L"BUTTON", L"Open log", BS_PUSHBUTTON, 0, ID_OPEN_LOG);

        g_AgentPathEdit = MakeControl(hwnd, L"EDIT", L"", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_AGENT_PATH);
        g_AgentPath = CombinePath(GetModuleDirectory(), L"Agent.dll");
        SetWindowTextW(g_AgentPathEdit, g_AgentPath.c_str());
        g_LogPath = CombinePath(CombinePath(GetDirectoryOfPath(g_AgentPath), ADT_LOG_DIR_NAME), ADT_LOG_FILE_NAME);

        g_TargetPathEdit = MakeControl(hwnd, L"EDIT", L"", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_TARGET_PATH);
        SendMessageW(g_TargetPathEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Target .exe to start suspended before injection"));

        g_SearchEdit = MakeControl(hwnd, L"EDIT", L"", ES_AUTOHSCROLL, WS_EX_CLIENTEDGE, ID_SEARCH_PROCESS);
        SendMessageW(g_SearchEdit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(L"Search process name, PID, or path"));

        g_ProcessList = MakeControl(hwnd, WC_LISTVIEWW, L"", LVS_REPORT | LVS_SINGLESEL | WS_TABSTOP, WS_EX_CLIENTEDGE, ID_PROCESS_LIST);
        ListView_SetExtendedListViewStyle(g_ProcessList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
        AddListColumn(0, 80, L"PID");
        AddListColumn(1, 180, L"Process");
        AddListColumn(2, 420, L"Path");

        g_DetectAll = MakeControl(hwnd, L"BUTTON", L"Log/detect all supported checks", BS_AUTOCHECKBOX, 0, ID_DETECT_ALL);
        Button_SetCheck(g_DetectAll, BST_CHECKED);

        for (FeatureOption& feature : g_Features)
        {
            feature.hwnd = MakeControl(hwnd, L"BUTTON", feature.label, BS_AUTOCHECKBOX, 0, feature.id);
            Button_SetCheck(feature.hwnd, feature.checkedByDefault ? BST_CHECKED : BST_UNCHECKED);
        }

        g_LogEdit = MakeControl(
            hwnd,
            L"EDIT",
            L"",
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY | WS_VSCROLL | WS_HSCROLL,
            WS_EX_CLIENTEDGE,
            ID_LOG
        );

        g_Status = MakeControl(hwnd, L"STATIC", L"Ready.", SS_LEFTNOWORDWRAP, 0, ID_STATUS);

        RefreshProcessList();
        RefreshLogView(true);
        SetTimer(hwnd, ID_LOG_TIMER, 1000, nullptr);
    }

    LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        switch (msg)
        {
        case WM_CREATE:
            CreateMainControls(hwnd);
            return 0;

        case WM_SIZE:
            LayoutControls(hwnd);
            return 0;

        case WM_TIMER:
            if (wParam == ID_LOG_TIMER)
                RefreshLogView(false);
            return 0;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
            case ID_REFRESH:
                RefreshProcessList();
                return 0;
            case ID_INJECT:
                InjectSelected();
                return 0;
            case ID_BROWSE_AGENT:
                BrowseAgent();
                return 0;
            case ID_BROWSE_TARGET:
                BrowseTargetExe();
                return 0;
            case ID_LAUNCH_SUSPENDED:
                LaunchSuspendedInjectAndKeepSuspended();
                return 0;
            case ID_RESUME_LAUNCHED:
                ResumeLaunchedTarget();
                return 0;
            case ID_OPEN_LOG:
                if (!g_LogPath.empty())
                    ShellExecuteW(hwnd, L"open", g_LogPath.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
                return 0;
            case ID_SEARCH_PROCESS:
                if (HIWORD(wParam) == EN_CHANGE)
                {
                    PopulateProcessList();
                    return 0;
                }
                break;
            }
            break;

        case WM_NOTIFY:
        {
            NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
            if (hdr && hdr->idFrom == ID_PROCESS_LIST && hdr->code == NM_DBLCLK)
                InjectSelected();
            return 0;
        }

        case WM_DESTROY:
            KillTimer(hwnd, ID_LOG_TIMER);
            if (g_MonoFont)
            {
                DeleteObject(g_MonoFont);
                g_MonoFont = nullptr;
            }
            PostQuitMessage(0);
            return 0;
        }

        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCmd)
{
    g_Instance = instance;

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icc);

    const wchar_t* className = L"AntiDebugTimelineControllerWindow";

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1);
    wc.lpszClassName = className;

    if (!RegisterClassExW(&wc))
        return 1;

    HWND hwnd = CreateWindowExW(
        0,
        className,
        L"AntiDebugTimeline Controller",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        1080,
        720,
        nullptr,
        nullptr,
        instance,
        nullptr
    );

    if (!hwnd)
        return 2;

    ShowWindow(hwnd, showCmd);
    UpdateWindow(hwnd);

    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return static_cast<int>(msg.wParam);
}
