#include <iostream>
#include <windows.h>
#include <winnt.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <processthreadsapi.h>
#include <locale>
#include <cstdio>
#include <algorithm>
#include <tlhelp32.h>
#include <cstdarg>
#include <atomic>
#include <mutex>
#include <cmath>

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// --- 动态加载 API 定义 ---
typedef BOOL(WINAPI* SetThreadSelectedCpuSetsPtr)(HANDLE, const ULONG*, ULONG);

// --- 全局变量新增 ---
std::mutex g_statsMutex; // 保护缓存的互斥锁

struct ThreadStats {
    DWORD threadId;
    FILETIME creationTime;

    // 用于每秒更新的瞬时数据 (保留用于调试或备用)
    ULARGE_INTEGER lastKernelTime;
    ULARGE_INTEGER lastUserTime;
    ULARGE_INTEGER lastCheckTime;

    // --- 新增：用于长周期计算的快照数据 ---
    ULARGE_INTEGER intervalStartKernelTime;
    ULARGE_INTEGER intervalStartUserTime;
    ULARGE_INTEGER intervalStartTime;
    double intervalAverageLoad; // 周期内的平均负载
    // ------------------------------------

    bool isMainThread;
    bool hasCpuSets;
    ULONG assignedCpuSetId;
};

struct ProcessStats {
    DWORD processId;
    std::map<DWORD, ThreadStats> threads;
    bool isInitialized;
    bool ignoreMonitoring;
    ULARGE_INTEGER lastOptimizationTime;
    // --- 新增 ---
    ULARGE_INTEGER lastForegroundTime; // 最后一次在前台的时间
    // -----------
};

// 核心缓存：PID -> 进程统计数据
std::map<DWORD, ProcessStats> g_processStatsCache;

// 辅助函数：将 FILETIME 转换为 ULARGE_INTEGER
ULARGE_INTEGER FT2ULL(FILETIME ft) {
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    return ull;
}

// --- 全局变量与常量 ---
#define COLOR_INFO      11
#define COLOR_SUCCESS   10
#define COLOR_WARNING   14
#define COLOR_ERROR     12
#define COLOR_DEFAULT   7

HANDLE g_hConsole;
bool g_silentMode = false;
HWINEVENTHOOK g_hForegroundHook;
std::atomic<bool> g_processListChanged(false);
std::atomic<bool> g_foregroundHasChanged(false);

// --- 手动定义标准 SDK 中不存在的 NT API 类型 ---
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
const PROCESS_INFORMATION_CLASS ProcessIoPriority = (PROCESS_INFORMATION_CLASS)33;
typedef enum _IO_PRIORITY_HINT
{
    IoPriorityVeryLow = 0, IoPriorityLow = 1, IoPriorityNormal = 2,
    IoPriorityHigh = 3, IoPriorityCritical = 4, MaxIoPriorityTypes
} IO_PRIORITY_HINT;

// --- Windows Native API 函数指针 ---
using NtSetInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
using NtQueryInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using DwmEnableMMCSSPtr = HRESULT(WINAPI*)(BOOL);

// --- 全局配置变量 ---
struct Settings
{
    int dwmInterval = 60;
    int dscp = -1;
    int scheduling = -1;
    int weight = -1;
    int ioResetInterval = 60;
    int idealCore = -1;
    int cpuSetInterval = 600;
    bool optimizeOtherThreads = false;
    // --- 新增 ---
    int cpuSetResetInterval = 300; // 后台重置间隔 默认 300 秒 (5分钟)
    // -----------
};
Settings settings;
std::set<std::wstring> blackList, whiteList, blackListJob;
std::map<DWORD, HANDLE> managedJobs;
std::map<DWORD, IO_PRIORITY_HINT> originalIoPriorities;
DWORD lastProcessId = 0;
DWORD lastAttachedThreadId = 0;

// --- 后台进程扫描缓存 ---
struct ProcessInfo
{
    DWORD cpuPriority;
    IO_PRIORITY_HINT ioPriority;
};
std::map<std::pair<std::wstring, DWORD>, ProcessInfo> processCache;


// --- 函数定义 ---

void Log(const char* format, ...)
{
    if (g_silentMode) return;
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void LogColor(WORD color, const char* format, ...)
{
    if (g_silentMode) return;
    SetConsoleTextAttribute(g_hConsole, color);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    SetConsoleTextAttribute(g_hConsole, COLOR_DEFAULT);
}

bool EnablePrivilege(LPCWSTR privilegeName)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return false;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid))
    {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

void EnableAllPrivileges()
{
    LogColor(COLOR_INFO, "[权限提升] 正在尝试为当前进程启用所有可用特权...\n");
    const LPCWSTR privileges[] = {
        L"SeDebugPrivilege", L"SeTakeOwnershipPrivilege", L"SeBackupPrivilege", L"SeRestorePrivilege",
        L"SeLoadDriverPrivilege", L"SeSystemEnvironmentPrivilege", L"SeSecurityPrivilege",
        L"SeIncreaseQuotaPrivilege", L"SeChangeNotifyPrivilege", L"SeSystemProfilePrivilege",
        L"SeSystemtimePrivilege", L"SeProfileSingleProcessPrivilege", L"SeIncreaseBasePriorityPrivilege",
        L"SeCreatePagefilePrivilege", L"SeShutdownPrivilege", L"SeRemoteShutdownPrivilege",
        L"SeUndockPrivilege", L"SeManageVolumePrivilege", L"SeIncreaseWorkingSetPrivilege",
        L"SeTimeZonePrivilege", L"SeCreateSymbolicLinkPrivilege", L"SeDelegateSessionUserImpersonatePrivilege"
    };

    for (const auto& priv : privileges)
    {
        if (EnablePrivilege(priv))
        {
            LogColor(COLOR_SUCCESS, "  -> 成功启用: %ws\n", priv);
        }
        else
        {
            LogColor(COLOR_WARNING, "  -> 警告: 无法启用 %ws \n", priv);
        }
    }
}

std::wstring to_lower(std::wstring str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::towlower);
    return str;
}

std::wstring string_to_wstring(const std::string& str)
{
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

void ParseIniFile(const std::wstring& path)
{
    LogColor(COLOR_INFO, "[配置] 正在尝试从以下路径加载INI文件: %ws\n", path.c_str());
    std::ifstream file(path);
    if (!file.is_open())
    {
        LogColor(COLOR_ERROR, "[配置] 错误: 无法打开INI文件 使用默认设置\n");
        return;
    }

    LogColor(COLOR_SUCCESS, "[配置] 成功打开INI文件\n");
    std::string narrow_line;
    std::wstring currentSection;

    while (std::getline(file, narrow_line))
    {
        std::wstring line = string_to_wstring(narrow_line);
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;

        if (line[0] == L'[' && line.back() == L']')
        {
            currentSection = line.substr(1, line.size() - 2);
        }
        else
        {
            if (currentSection == L"Settings")
            {
                std::wstringstream ss(line);
                std::wstring key, value;
                if (std::getline(ss, key, L'=') && std::getline(ss, value))
                {
                    if (key == L"DwmEnableMMCSS") settings.dwmInterval = std::stoi(value);
                    else if (key == L"DSCP") settings.dscp = std::stoi(value);
                    else if (key == L"Scheduling") settings.scheduling = std::stoi(value);
                    else if (key == L"Weight") settings.weight = std::stoi(value);
                    else if (key == L"IOReset") settings.ioResetInterval = std::stoi(value);
                    else if (key == L"IdealCore") settings.idealCore = std::stoi(value);
					else if (key == L"CpuSetInterval") settings.cpuSetInterval = std::stoi(value);
					else if (key == L"OptimizeOtherThreads") settings.optimizeOtherThreads = (std::stoi(value) != 0);
					else if (key == L"CpuSetResetInterval") settings.cpuSetResetInterval = std::stoi(value);
                }
            }
            else if (currentSection == L"BlackList")
            {
                blackList.insert(to_lower(line));
            }
            else if (currentSection == L"WhiteList")
            {
                whiteList.insert(to_lower(line));
            }
            else if (currentSection == L"BlackListJob")
            {
                blackListJob.insert(to_lower(line));
            }
        }
    }
}

std::wstring GetProcessNameById(DWORD processId)
{
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (handle)
    {
        wchar_t buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(handle, 0, buffer, &size))
        {
            CloseHandle(handle);
            std::wstring fullPath(buffer);
            return fullPath.substr(fullPath.find_last_of(L"\\/") + 1);
        }
        CloseHandle(handle);
    }
    return L"";
}

void SetProcessIoPriority(HANDLE processHandle, IO_PRIORITY_HINT priority)
{
    static NtSetInformationProcessPtr NtSetInformationProcess = (NtSetInformationProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (NtSetInformationProcess)
    {
        NtSetInformationProcess(processHandle, ProcessIoPriority, &priority, sizeof(priority));
    }
}

bool GetProcessIoPriority(HANDLE processHandle, IO_PRIORITY_HINT& priority)
{
    static NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess)
    {
        ULONG returnLength;
        NTSTATUS status = NtQueryInformationProcess(processHandle, ProcessIoPriority, &priority, sizeof(priority), &returnLength);
        return NT_SUCCESS(status);
    }
    return false;
}

void ApplyJobObjectSettings(HANDLE jobHandle, const std::wstring& processName)
{
    LogColor(COLOR_WARNING, "  -> 正在应用作业对象设置...\n");
    if (settings.scheduling >= 0)
    {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        basicInfo.LimitFlags = JOB_OBJECT_LIMIT_SCHEDULING_CLASS;
        basicInfo.SchedulingClass = settings.scheduling;
        if (SetInformationJobObject(jobHandle, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo)))
        {
            LogColor(COLOR_SUCCESS, "     - 成功: 调度类已设置为 %d\n", settings.scheduling);
        }
        else
        {
            LogColor(COLOR_ERROR, "     - 失败: 无法设置调度类 错误码: %lu\n", GetLastError());
        }
    }
    if (settings.weight >= 1)
    {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        cpuInfo.Weight = settings.weight;
        if (SetInformationJobObject(jobHandle, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo)))
        {
            LogColor(COLOR_SUCCESS, "     - 成功: 时间片权重已设置为 %d\n", settings.weight);
        }
        else
        {
            LogColor(COLOR_ERROR, "     - 失败: 无法设置时间片权重 错误码: %lu\n", GetLastError());
        }
    }
    if (settings.dscp >= 0)
    {
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG;
        netInfo.DscpTag = (BYTE)settings.dscp;
        if (SetInformationJobObject(jobHandle, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo)))
        {
            LogColor(COLOR_SUCCESS, "     - 成功: DSCP标记已设置为 %d\n", settings.dscp);
        }
        else
        {
            LogColor(COLOR_ERROR, "     - 失败: 无法设置DSCP标记 错误码: %lu\n", GetLastError());
        }
    }
}

void ResetAndReleaseJobObject(DWORD processId)
{
    if (managedJobs.count(processId))
    {
        HANDLE hJob = managedJobs[processId];
        LogColor(COLOR_WARNING, "  -> 正在为进程ID %lu 重置作业对象设置...\n", processId);
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo));
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        SetInformationJobObject(hJob, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo));
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = (JOB_OBJECT_NET_RATE_CONTROL_FLAGS)0;
        SetInformationJobObject(hJob, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo));
        LogColor(COLOR_WARNING, "  -> 正在为进程ID %lu 关闭句柄并释放作业对象...\n", processId);
        CloseHandle(hJob);
        managedJobs.erase(processId);
    }
}

// 用于存储线程信息以便排序
struct ThreadInfo {
    DWORD threadId;
    FILETIME creationTime;
};

// 比较函数 用于根据创建时间对线程进行排序
bool CompareThreadsByCreationTime(const ThreadInfo& a, const ThreadInfo& b) {
    // CompareFileTime 返回 -1 如果 a < b, 0 如果 a == b, 1 如果 a > b
    return CompareFileTime(&a.creationTime, &b.creationTime) < 0;
}

// 获取指定进程的第一个线程（主线程）的ID
DWORD GetProcessMainThreadId(DWORD dwProcessId) {
    std::vector<ThreadInfo> threads;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == dwProcessId) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                if (hThread) {
                    ThreadInfo info;
                    info.threadId = te32.th32ThreadID;
                    FILETIME exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &info.creationTime, &exitTime, &kernelTime, &userTime)) {
                        threads.push_back(info);
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);

    if (threads.empty()) {
        return 0; // 未找到任何线程
    }

    // 根据创建时间排序 找到最早创建的线程
    std::sort(threads.begin(), threads.end(), CompareThreadsByCreationTime);

    return threads[0].threadId;
}

void ScanAndResetIoPriorities()
{
    LogColor(COLOR_WARNING, "[后台扫描] 已触发扫描！\n");
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    std::map<std::pair<std::wstring, DWORD>, ProcessInfo> currentProcesses;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32))
    {
        do
        {
            DWORD pid = pe32.th32ProcessID;
            if (pid == 0 || pid == 4) continue;

            std::wstring processNameLower = to_lower(pe32.szExeFile);
            std::pair<std::wstring, DWORD> processKey = { processNameLower, pid };

            if (pid == lastProcessId || blackList.count(processNameLower))
            {
                continue;
            }

            auto it = processCache.find(processKey);
            if (it != processCache.end())
            {
                currentProcesses[processKey] = it->second;
                continue;
            }

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid);
            if (!hProcess) continue;

            DWORD priorityClass = GetPriorityClass(hProcess);
            IO_PRIORITY_HINT ioPriority;
            if (GetProcessIoPriority(hProcess, ioPriority))
            {
                currentProcesses[processKey] = { priorityClass, ioPriority };

                if ((priorityClass == NORMAL_PRIORITY_CLASS || priorityClass == IDLE_PRIORITY_CLASS || priorityClass == BELOW_NORMAL_PRIORITY_CLASS) && ioPriority == IoPriorityHigh)
                {
                    LogColor(COLOR_WARNING, "  -> 检测到新进程 %ws (PID: %lu) \n", processNameLower.c_str(), pid);
                    SetProcessIoPriority(hProcess, IoPriorityNormal);
                    currentProcesses[processKey].ioPriority = IoPriorityNormal;
                    LogColor(COLOR_SUCCESS, "     -> 已重置其I/O优先级为正常\n");
                }
            }

            CloseHandle(hProcess);

        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    processCache.swap(currentProcesses);
    LogColor(COLOR_INFO, "[后台扫描] 扫描完成 当前缓存 %zu 个进程\n", processCache.size());
}

void CALLBACK ForegroundEventProc(HWINEVENTHOOK hWinEventHook, DWORD event, HWND hwnd, LONG idObject, LONG idChild, DWORD dwEventThread, DWORD dwmsEventTime)
{
    if (event != EVENT_SYSTEM_FOREGROUND || !hwnd)
    {
        return;
    }

    DWORD currentProcessId = 0;
    DWORD currentThreadId = 0;

    currentThreadId = GetWindowThreadProcessId(hwnd, &currentProcessId);

    if (currentProcessId == 0 || currentProcessId == lastProcessId)
    {
        return;
    }

    g_foregroundHasChanged = true;

    if (lastProcessId != 0)
    {
        Log("前台进程已变更 (原PID: %lu)\n", lastProcessId);
        HANDLE hOldProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, lastProcessId);
        if (hOldProcess)
        {
            if (originalIoPriorities.count(lastProcessId))
            {
                LogColor(COLOR_WARNING, "  -> 正在为进程ID %lu 恢复I/O优先级为正常\n", lastProcessId);
                SetProcessIoPriority(hOldProcess, originalIoPriorities[lastProcessId]);
                originalIoPriorities.erase(lastProcessId);
            }
            CloseHandle(hOldProcess);
        }
        ResetAndReleaseJobObject(lastProcessId);
    }

    Log("新前台进程PID: %lu\n", currentProcessId);
    std::wstring processNameLower = to_lower(GetProcessNameById(currentProcessId));
    if (!processNameLower.empty() && !blackList.count(processNameLower))
    {
        Log("  -> 进程名: %ws (不在黑名单中)\n", processNameLower.c_str());
        HANDLE hNewProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, currentProcessId);
        if (hNewProcess)
        {
            IO_PRIORITY_HINT currentPriority;
            if (GetProcessIoPriority(hNewProcess, currentPriority) && currentPriority == IoPriorityNormal)
            {
                originalIoPriorities[currentProcessId] = currentPriority;
                SetProcessIoPriority(hNewProcess, IoPriorityHigh);
                LogColor(COLOR_SUCCESS, "  -> I/O优先级已提升为高\n");
            }

            if (settings.dscp >= 0 || settings.weight >= 1 || settings.scheduling >= 0)
            {
                if (!blackListJob.count(processNameLower))
                {
                    std::wstring jobName = L"Global\\ForegroundBoosterJob_" + processNameLower + L"_" + std::to_wstring(currentProcessId);
                    HANDLE hJob = CreateJobObjectW(NULL, jobName.c_str());
                    if (hJob)
                    {
                        Log("  -> 已创建作业对象: %ws\n", jobName.c_str());
                        ApplyJobObjectSettings(hJob, processNameLower);
                        if (AssignProcessToJobObject(hJob, hNewProcess))
                        {
                            LogColor(COLOR_SUCCESS, "  -> 成功将进程分配到已配置的作业对象\n");
                            managedJobs[currentProcessId] = hJob;
                        }
                        else
                        {
                            LogColor(COLOR_ERROR, "  -> 失败: 无法将进程分配到作业对象 错误码: %lu (进程处于另一个作业中)\n", GetLastError());
                            CloseHandle(hJob);
                        }
                    }
                    else
                    {
                        LogColor(COLOR_ERROR, "  -> 失败: 无法创建作业对象 错误码: %lu\n", GetLastError());
                    }
                }
                else
                {
                    LogColor(COLOR_WARNING, "  -> 进程位于作业对象黑名单中 跳过Job Object操作\n");
                }
            }
            CloseHandle(hNewProcess);
        }
        else
        {
            DWORD lastError = GetLastError();
            if (lastError == 5)
            {
                LogColor(COLOR_ERROR, "  -> 失败: 打开进程句柄时被拒绝访问 错误码: 5\n");
            }
            else
            {
                LogColor(COLOR_ERROR, "  -> 失败: 无法打开进程 错误码: %lu\n", lastError);
            }
        }
    }
    lastProcessId = currentProcessId;

    if (!whiteList.empty() && currentThreadId != 0 && currentThreadId != lastAttachedThreadId)
    {
        LogColor(COLOR_INFO, "[附加线程] 检测到新前台线程ID: %lu\n", currentThreadId);
        std::vector<DWORD> threadsToAttach;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);
            if (Process32FirstW(hSnapshot, &pe32))
            {
                do
                {
                    if (whiteList.count(to_lower(pe32.szExeFile)))
                    {
                        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                        if(hThreadSnapshot != INVALID_HANDLE_VALUE)
                        {
                            THREADENTRY32 te32;
                            te32.dwSize = sizeof(THREADENTRY32);
                            if (Thread32First(hThreadSnapshot, &te32))
                            {
                                do
                                {
                                    if (te32.th32OwnerProcessID == pe32.th32ProcessID)
                                    {
                                        threadsToAttach.push_back(te32.th32ThreadID);
                                    }
                                } while (Thread32Next(hThreadSnapshot, &te32));
                            }
                            CloseHandle(hThreadSnapshot);
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }

        if (!threadsToAttach.empty())
        {
            if (lastAttachedThreadId != 0)
            {
                LogColor(COLOR_WARNING, "  -> 正在从旧前台线程 %lu 分离 %zu 个白名单线程...\n", lastAttachedThreadId, threadsToAttach.size());
                for (DWORD tid : threadsToAttach)
                {
                    AttachThreadInput(tid, lastAttachedThreadId, FALSE);
                }
            }
            std::wstring currentProcessNameLower = to_lower(GetProcessNameById(currentProcessId));
            if (!whiteList.count(currentProcessNameLower))
            {
                LogColor(COLOR_WARNING, "  -> 正在尝试将 %zu 个白名单线程附加到新前台线程 %lu...\n", threadsToAttach.size(), currentThreadId);
                int successCount = 0;
                for (DWORD tid : threadsToAttach)
                {
                    if (AttachThreadInput(tid, currentThreadId, TRUE))
                    {
                        successCount++;
                    }
                }
                LogColor(COLOR_SUCCESS, "  -> 附加完成: %d / %zu 个线程成功\n", successCount, threadsToAttach.size());
            }
        }
        lastAttachedThreadId = currentThreadId;
    }
}

void EventMessageLoopThread()
{
    g_hForegroundHook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, NULL, ForegroundEventProc, 0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (g_hForegroundHook)
    {
        LogColor(COLOR_SUCCESS, "[事件钩子] 成功设置前台窗口变化事件钩子\n");
    }
    else
    {
        LogColor(COLOR_ERROR, "[事件钩子] 错误: 无法设置前台窗口事件钩子 错误码: %lu\n", GetLastError());
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    if(g_hForegroundHook) UnhookWinEvent(g_hForegroundHook);
}

// --- 新增：CPU Sets API 定义与辅助函数 ---
using GetSystemCpuSetInformationPtr = BOOL(WINAPI*)(PSYSTEM_CPU_SET_INFORMATION, ULONG, PULONG, HANDLE, ULONG);
using SetThreadSelectedCpuSetsPtr = BOOL(WINAPI*)(HANDLE, const ULONG*, ULONG);

// 辅助函数：将逻辑核心索引 (如 19) 转换为系统 CPU Set ID
// 如果失败返回 0
ULONG GetCpuSetIdFromLogicalIndex(DWORD logicalIndex, GetSystemCpuSetInformationPtr pGetSystemCpuSetInformation) {
    if (!pGetSystemCpuSetInformation) return 0;

    ULONG returnLength = 0;
    // 第一次调用获取所需缓冲区大小
    pGetSystemCpuSetInformation(NULL, 0, &returnLength, GetCurrentProcess(), 0);

    if (returnLength == 0) return 0;

    std::vector<BYTE> buffer(returnLength);
    PSYSTEM_CPU_SET_INFORMATION pInfo = (PSYSTEM_CPU_SET_INFORMATION)buffer.data();

    // 第二次调用获取实际数据
    if (!pGetSystemCpuSetInformation(pInfo, returnLength, &returnLength, GetCurrentProcess(), 0)) {
        return 0;
    }

    // 遍历缓冲区
    BYTE* ptr = buffer.data();
    BYTE* end = ptr + returnLength;

    while (ptr < end) {
        PSYSTEM_CPU_SET_INFORMATION entry = (PSYSTEM_CPU_SET_INFORMATION)ptr;

        // Type 0 是 CpuSetInformation
        if (entry->Type == 0) { // CpuSetInformation
            if (entry->CpuSet.LogicalProcessorIndex == logicalIndex) {
                return entry->CpuSet.Id; // 找到对应的 ID
            }
        }

        // 移动到下一个条目 (注意：必须使用 entry->Size 因为结构体大小可能随系统版本变化)
        if (entry->Size == 0) break; // 防止死循环
        ptr += entry->Size;
    }

    return 0; // 未找到
}

// --- 补充 NTAPI 缺失的定义 ---

// 1. 定义 CLIENT_ID
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

// 2. 定义 THREADINFOCLASS 枚举
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    MaxThreadInfoClass
} THREADINFOCLASS;

// 3. 定义 THREAD_BASIC_INFORMATION (现在 CLIENT_ID 已定义 不会报错了)
typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// 4. 定义函数指针 (现在 THREADINFOCLASS 已定义 不会报错了)
using NtQueryInformationThreadPtr = NTSTATUS(NTAPI*)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);

// --- 新增：CPU 拓扑分析结构 ---
struct CpuTopology {
    std::vector<DWORD> pCores;      // 性能核 (物理主核)
    std::vector<DWORD> htCores;     // 超线程 (逻辑核)
    std::vector<DWORD> eCores;      // 效率核
    std::map<DWORD, DWORD> lpToCoreIndex; // 逻辑核 -> 物理核索引映射
    bool isInitialized = false;
};

// 辅助函数：分析系统拓扑
void AnalyzeCpuTopology(GetSystemCpuSetInformationPtr pGetSystemCpuSetInformation, CpuTopology& topology) {
    if (!pGetSystemCpuSetInformation || topology.isInitialized) return;

    ULONG returnLength = 0;
    pGetSystemCpuSetInformation(NULL, 0, &returnLength, GetCurrentProcess(), 0);
    if (returnLength == 0) return;

    std::vector<BYTE> buffer(returnLength);
    if (!pGetSystemCpuSetInformation((PSYSTEM_CPU_SET_INFORMATION)buffer.data(), returnLength, &returnLength, GetCurrentProcess(), 0)) return;

    std::map<DWORD, std::vector<DWORD>> coreGroups; // CoreIndex -> [LogicalProcessors]
    std::map<DWORD, BYTE> coreEfficiency;           // CoreIndex -> EfficiencyClass

    BYTE* ptr = buffer.data();
    BYTE* end = ptr + returnLength;

    while (ptr < end) {
        PSYSTEM_CPU_SET_INFORMATION entry = (PSYSTEM_CPU_SET_INFORMATION)ptr;
        if (entry->Type == 0) { // CpuSetInformation
            coreGroups[entry->CpuSet.CoreIndex].push_back(entry->CpuSet.LogicalProcessorIndex);
            coreEfficiency[entry->CpuSet.CoreIndex] = entry->CpuSet.EfficiencyClass;
            topology.lpToCoreIndex[entry->CpuSet.LogicalProcessorIndex] = entry->CpuSet.CoreIndex;
        }
        if (entry->Size == 0) break;
        ptr += entry->Size;
    }

    // 分类核心
    for (auto& pair : coreGroups) {
        DWORD coreIndex = pair.first;
        std::vector<DWORD>& lps = pair.second;
        BYTE eff = coreEfficiency[coreIndex];

        // 简单假设：EfficiencyClass 0 为 E核 >=1 为 P核 (适用于 Intel 12/13/14代)
        // 如果所有核心 EfficiencyClass 都相同 则视为全 P核
        if (eff == 0 && coreEfficiency.size() > 1) {
            // E-Cores
            for (DWORD lp : lps) topology.eCores.push_back(lp);
        } else {
            // P-Cores & HT
            std::sort(lps.begin(), lps.end());
            if (!lps.empty()) {
                topology.pCores.push_back(lps[0]); // 第一个逻辑核视为物理主核
                for (size_t i = 1; i < lps.size(); ++i) {
                    topology.htCores.push_back(lps[i]); // 后续的视为超线程
                }
            }
        }
    }

    // 排序以确保顺序确定性
    std::sort(topology.pCores.begin(), topology.pCores.end()); // 正序
    std::sort(topology.htCores.begin(), topology.htCores.end()); // 正序 (稍后使用时再倒序)
    std::sort(topology.eCores.begin(), topology.eCores.end()); // 正序

    topology.isInitialized = true;
    LogColor(COLOR_INFO, "[拓扑] P核: %zu, HT: %zu, E核: %zu\n", topology.pCores.size(), topology.htCores.size(), topology.eCores.size());
}

using GetProcessDefaultCpuSetsPtr = BOOL(WINAPI*)(HANDLE, PULONG, ULONG, PULONG);

void ThreadOptimizerThread()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    SetThreadSelectedCpuSetsPtr pSetThreadSelectedCpuSets =
        (SetThreadSelectedCpuSetsPtr)GetProcAddress(hKernel32, "SetThreadSelectedCpuSets");
    GetSystemCpuSetInformationPtr pGetSystemCpuSetInformation =
        (GetSystemCpuSetInformationPtr)GetProcAddress(hKernel32, "GetSystemCpuSetInformation");
    GetProcessDefaultCpuSetsPtr pGetProcessDefaultCpuSets =
        (GetProcessDefaultCpuSetsPtr)GetProcAddress(hKernel32, "GetProcessDefaultCpuSets");
    NtQueryInformationThreadPtr pNtQueryInformationThread =
        (NtQueryInformationThreadPtr)GetProcAddress(hNtdll, "NtQueryInformationThread");

    if (!pSetThreadSelectedCpuSets || !pGetSystemCpuSetInformation)
    {
        LogColor(COLOR_WARNING, "[警告] 当前系统不支持 CPU Sets API (需要 Win10 1709+) 优化功能受限\n");
    }

    ULONG idealCoreCpuSetId = 0;
    ULONG mainThreadFallbackCpuSetId = 0;

    if (settings.idealCore >= 0 && pGetSystemCpuSetInformation) {
        idealCoreCpuSetId = GetCpuSetIdFromLogicalIndex((DWORD)settings.idealCore, pGetSystemCpuSetInformation);
        if (settings.idealCore >= 2) {
            mainThreadFallbackCpuSetId = GetCpuSetIdFromLogicalIndex((DWORD)(settings.idealCore - 2), pGetSystemCpuSetInformation);
        }
    }

    CpuTopology topology;
    DWORD previousPid = 0;

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        // --- 新增：主开关检查 ---
        // 如果未设置 IdealCore 则视为禁用所有 CPU 优化功能
        // 跳过后续的拓扑分析、监控、日志和计算 仅保持线程存活
        if (settings.idealCore < 0)
        {
            continue;
        }
        // -----------------------

        DWORD currentPid = lastProcessId;

        // --- 修正点 1: 在循环顶部统一定义时间变量 ---
        FILETIME ftSystem;
        GetSystemTimeAsFileTime(&ftSystem);
        ULARGE_INTEGER now = FT2ULL(ftSystem);
        // -------------------------------------------

        // --- 后台进程清理逻辑 ---
        if (settings.cpuSetResetInterval > 0 && pSetThreadSelectedCpuSets)
        {
            std::lock_guard<std::mutex> lock(g_statsMutex);
            ULONGLONG resetThreshold = (ULONGLONG)settings.cpuSetResetInterval * 10000000ULL;

            for (auto& procPair : g_processStatsCache)
            {
                DWORD pid = procPair.first;
                ProcessStats& pStats = procPair.second;

                if (pid == currentPid)
                {
                    pStats.lastForegroundTime = now;
                    continue;
                }

                if (pStats.lastForegroundTime.QuadPart > 0 && now.QuadPart > pStats.lastForegroundTime.QuadPart)
                {
                    ULONGLONG timeInBg = now.QuadPart - pStats.lastForegroundTime.QuadPart;

                    if (timeInBg > resetThreshold)
                    {
                        bool anyReset = false;
                        for (auto& threadPair : pStats.threads)
                        {
                            ThreadStats& tStats = threadPair.second;
                            if (tStats.hasCpuSets)
                            {
                                HANDLE hThread = OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, tStats.threadId);
                                if (hThread)
                                {
                                    if (pSetThreadSelectedCpuSets(hThread, NULL, 0)) anyReset = true;
                                    CloseHandle(hThread);
                                }
                                tStats.hasCpuSets = false;
                                tStats.assignedCpuSetId = 0;
                            }
                        }

                        if (anyReset)
                        {
                            LogColor(COLOR_WARNING, "[清理] 进程 %lu 在后台超过 %d 秒 重置其线程 CPU Sets\n",
                                pid, settings.cpuSetResetInterval);
                            pStats.lastForegroundTime = now;
                        }
                    }
                }
            }
        }

        if (currentPid == 0) continue;

        // --- 快速检查：是否忽略 ---
        {
            std::lock_guard<std::mutex> lock(g_statsMutex);
            if (g_processStatsCache.count(currentPid) && g_processStatsCache[currentPid].ignoreMonitoring) continue;
        }

        // --- 亲和性与 CPU Sets 检查 ---
        bool customConfigDetected = false;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, currentPid);
        if (hProcess)
        {
            DWORD_PTR processAffinity, systemAffinity;
            if (GetProcessAffinityMask(hProcess, &processAffinity, &systemAffinity))
            {
                if (processAffinity != systemAffinity) customConfigDetected = true;
            }

            if (!customConfigDetected && pGetProcessDefaultCpuSets)
            {
                ULONG requiredIdCount = 0;
                pGetProcessDefaultCpuSets(hProcess, NULL, 0, &requiredIdCount);
                if (requiredIdCount > 0) customConfigDetected = true;
            }
            CloseHandle(hProcess);
        }

        if (customConfigDetected)
        {
            std::lock_guard<std::mutex> lock(g_statsMutex);
            ProcessStats& procStats = g_processStatsCache[currentPid];
            procStats.processId = currentPid;
            if (!procStats.ignoreMonitoring)
            {
                procStats.ignoreMonitoring = true;
                procStats.threads.clear();
                LogColor(COLOR_WARNING, "  -> [监控停止] 进程 %lu 已设置亲和性或 CPU Sets 停止追踪其线程负载\n", currentPid);
            }
            continue;
        }

        // --- 在循环内部初始化拓扑 (仅一次) ---
        if (!topology.isInitialized && pGetSystemCpuSetInformation) {
            AnalyzeCpuTopology(pGetSystemCpuSetInformation, topology);
        }

        // --- 修正点 2: 删除了此处重复定义的 ftSystem 和 now ---
        // (原代码这里有重复定义 导致编译错误)
        // ---------------------------------------------------

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) continue;

        std::vector<DWORD> currentThreadIds;
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        {
            std::lock_guard<std::mutex> lock(g_statsMutex);
            ProcessStats& procStats = g_processStatsCache[currentPid];
            procStats.processId = currentPid;

            // 再次更新前台时间 防止清理逻辑误判 (双重保险)
            procStats.lastForegroundTime = now;

            // --- 检测前台切换 ---
            if (currentPid != previousPid)
            {
                if (procStats.lastOptimizationTime.QuadPart == 0)
                {
                    LogColor(COLOR_INFO, "[监控] 新进程 %lu 将立即执行首次优化\n", currentPid);
                }
                else
                {
                    LogColor(COLOR_INFO, "[监控] 旧进程 %lu 将在 %d 秒后应用优化\n", currentPid, settings.cpuSetInterval);
                    procStats.lastOptimizationTime = now;
                    for (auto& pair : procStats.threads) {
                        pair.second.intervalStartTime = now;
                        pair.second.intervalStartKernelTime = pair.second.lastKernelTime;
                        pair.second.intervalStartUserTime = pair.second.lastUserTime;
                    }
                }
                previousPid = currentPid;
            }

            // --- 更新线程列表与快照 ---
            if (Thread32First(hSnapshot, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == currentPid)
                    {
                        DWORD tid = te32.th32ThreadID;
                        currentThreadIds.push_back(tid);

                        bool isNewThread = (procStats.threads.find(tid) == procStats.threads.end());

                        if (isNewThread)
                        {
                            ThreadStats ts = {};
                            ts.threadId = tid;
                            ts.hasCpuSets = false;
                            ts.assignedCpuSetId = 0;

                            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
                            if (hThread)
                            {
                                FILETIME ftExit, ftKernel, ftUser;
                                if (GetThreadTimes(hThread, &ts.creationTime, &ftExit, &ftKernel, &ftUser))
                                {
                                    ts.lastKernelTime = FT2ULL(ftKernel);
                                    ts.lastUserTime = FT2ULL(ftUser);
                                    ts.lastCheckTime = now;
                                    ts.intervalStartKernelTime = ts.lastKernelTime;
                                    ts.intervalStartUserTime = ts.lastUserTime;
                                    ts.intervalStartTime = now;
                                }
                                CloseHandle(hThread);
                            }
                            procStats.threads[tid] = ts;
                        }
                        else
                        {
                            ThreadStats& ts = procStats.threads[tid];
                            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
                            if (hThread)
                            {
                                FILETIME ftCreation, ftExit, ftKernel, ftUser;
                                if (GetThreadTimes(hThread, &ftCreation, &ftExit, &ftKernel, &ftUser))
                                {
                                    ts.lastKernelTime = FT2ULL(ftKernel);
                                    ts.lastUserTime = FT2ULL(ftUser);
                                    ts.lastCheckTime = now;

                                    if (procStats.lastOptimizationTime.QuadPart != 0 &&
                                        ts.intervalStartTime.QuadPart != procStats.lastOptimizationTime.QuadPart)
                                    {
                                        ts.intervalStartKernelTime = ts.lastKernelTime;
                                        ts.intervalStartUserTime = ts.lastUserTime;
                                        ts.intervalStartTime = now;
                                    }
                                }
                                CloseHandle(hThread);
                            }
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }

            for (auto it = procStats.threads.begin(); it != procStats.threads.end(); )
            {
                bool exists = false;
                for (DWORD activeTid : currentThreadIds) {
                    if (activeTid == it->first) { exists = true; break; }
                }
                if (!exists) it = procStats.threads.erase(it);
                else ++it;
            }

            ULONGLONG timeSinceLastOpt = now.QuadPart - procStats.lastOptimizationTime.QuadPart;
            ULONGLONG intervalUnits = (ULONGLONG)settings.cpuSetInterval * 10000000ULL;

            if (timeSinceLastOpt >= intervalUnits)
            {
                bool isImmediateRun = (procStats.lastOptimizationTime.QuadPart == 0);
                if (isImmediateRun) {
                    LogColor(COLOR_INFO, "[分析] 触发新进程立即优化...\n");
                } else {
                    LogColor(COLOR_INFO, "[分析] 观察周期结束 正在计算平均负载并应用优化...\n");
                }

                for (auto& pair : procStats.threads)
                {
                    ThreadStats& ts = pair.second;
                    if (isImmediateRun) {
                        ts.intervalAverageLoad = 0.0;
                        continue;
                    }
                    ULONGLONG timeDelta = now.QuadPart - ts.intervalStartTime.QuadPart;
                    ULONGLONG workDelta = (ts.lastKernelTime.QuadPart - ts.intervalStartKernelTime.QuadPart) +
                                          (ts.lastUserTime.QuadPart - ts.intervalStartUserTime.QuadPart);
                    if (timeDelta > 0) ts.intervalAverageLoad = (double)workDelta / (double)timeDelta * 100.0;
                    else ts.intervalAverageLoad = 0.0;
                    ts.intervalStartKernelTime = ts.lastKernelTime;
                    ts.intervalStartUserTime = ts.lastUserTime;
                    ts.intervalStartTime = now;
                }

                procStats.lastOptimizationTime = now;

                ThreadStats* pMainThread = nullptr;
                ThreadStats* pHeavyThread = nullptr;

                for (auto& pair : procStats.threads)
                {
                    ThreadStats& t = pair.second;
                    if (pMainThread == nullptr || CompareFileTime(&t.creationTime, &pMainThread->creationTime) < 0)
                        pMainThread = &t;
                }

                if (!isImmediateRun)
                {
                    for (auto& pair : procStats.threads)
                    {
                        ThreadStats& t = pair.second;
                        if (pMainThread && t.threadId != pMainThread->threadId)
                        {
                            if (pHeavyThread == nullptr || t.intervalAverageLoad > pHeavyThread->intervalAverageLoad)
                                pHeavyThread = &t;
                        }
                    }
                }

                if (pMainThread) pMainThread->isMainThread = true;

                auto EnsureCoreInAffinity = [&](HANDLE hThread, DWORD coreIndex) {
                    if (!pNtQueryInformationThread) return;
                    THREAD_BASIC_INFORMATION tbi;
                    if (NT_SUCCESS(pNtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), NULL)))
                    {
                        if (!(tbi.AffinityMask & (1ULL << coreIndex)))
                        {
                            DWORD_PTR newMask = tbi.AffinityMask | (1ULL << coreIndex);
                            SetThreadAffinityMask(hThread, newMask);
                        }
                    }
                };

                if (settings.idealCore >= 0 && pMainThread && pSetThreadSelectedCpuSets && idealCoreCpuSetId != 0)
                {
                    DWORD assignedMainCore = settings.idealCore;
                    DWORD assignedHeavyCore = settings.idealCore;

                    if (pHeavyThread && pHeavyThread->intervalAverageLoad > 10.0)
                    {
                        LogColor(COLOR_INFO, "  -> 检测到重负载线程 %lu (平均负载 %.1f%%) 执行分离策略\n",
                            pHeavyThread->threadId, pHeavyThread->intervalAverageLoad);

                        if (!pHeavyThread->hasCpuSets || pHeavyThread->assignedCpuSetId != idealCoreCpuSetId)
                        {
                            for (auto& pair : procStats.threads) {
                                ThreadStats& t = pair.second;
                                if (t.threadId != pMainThread->threadId && t.hasCpuSets && t.assignedCpuSetId != 0) {
                                    HANDLE hOther = OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, t.threadId);
                                    if (hOther) {
                                        pSetThreadSelectedCpuSets(hOther, NULL, 0);
                                        t.hasCpuSets = false; t.assignedCpuSetId = 0;
                                        CloseHandle(hOther);
                                    }
                                }
                            }

                            HANDLE hHeavy = OpenThread(THREAD_SET_LIMITED_INFORMATION | THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, pHeavyThread->threadId);
                            if (hHeavy)
                            {
                                EnsureCoreInAffinity(hHeavy, settings.idealCore);
                                ULONG cpuSetIds[] = { idealCoreCpuSetId };
                                if (pSetThreadSelectedCpuSets(hHeavy, cpuSetIds, 1))
                                {
                                    LogColor(COLOR_SUCCESS, "  -> [优化] 线程 %lu (重负载) 绑定 CPU Set ID: %lu\n", pHeavyThread->threadId, idealCoreCpuSetId);
                                    pHeavyThread->hasCpuSets = true;
                                    pHeavyThread->assignedCpuSetId = idealCoreCpuSetId;
                                }
                                CloseHandle(hHeavy);
                            }
                        }

                        if (mainThreadFallbackCpuSetId != 0 && pMainThread->assignedCpuSetId != mainThreadFallbackCpuSetId)
                        {
                            HANDLE hMain = OpenThread(THREAD_SET_LIMITED_INFORMATION | THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, pMainThread->threadId);
                            if (hMain)
                            {
                                EnsureCoreInAffinity(hMain, settings.idealCore - 2);
                                ULONG cpuSetIds[] = { mainThreadFallbackCpuSetId };
                                if (pSetThreadSelectedCpuSets(hMain, cpuSetIds, 1))
                                {
                                    LogColor(COLOR_SUCCESS, "  -> [优化] 主线程 %lu 绑定 CPU Set ID: %lu (Core %d)\n",
                                        pMainThread->threadId, mainThreadFallbackCpuSetId, settings.idealCore - 2);
                                    pMainThread->hasCpuSets = true;
                                    pMainThread->assignedCpuSetId = mainThreadFallbackCpuSetId;
                                }
                                CloseHandle(hMain);
                            }
                        }
                        assignedHeavyCore = settings.idealCore;
                        assignedMainCore = settings.idealCore - 2;
                    }
                    else
                    {
                        for (auto& pair : procStats.threads) {
                            ThreadStats& t = pair.second;
                            if (t.threadId != pMainThread->threadId && t.hasCpuSets && t.assignedCpuSetId != 0) {
                                HANDLE hOther = OpenThread(THREAD_SET_LIMITED_INFORMATION, FALSE, t.threadId);
                                if (hOther) {
                                    pSetThreadSelectedCpuSets(hOther, NULL, 0);
                                    t.hasCpuSets = false; t.assignedCpuSetId = 0;
                                    CloseHandle(hOther);
                                }
                            }
                        }

                        if (!pMainThread->hasCpuSets || pMainThread->assignedCpuSetId != idealCoreCpuSetId)
                        {
                            HANDLE hMain = OpenThread(THREAD_SET_LIMITED_INFORMATION | THREAD_SET_INFORMATION | THREAD_QUERY_INFORMATION, FALSE, pMainThread->threadId);
                            if (hMain)
                            {
                                EnsureCoreInAffinity(hMain, settings.idealCore);
                                ULONG cpuSetIds[] = { idealCoreCpuSetId };
                                if (pSetThreadSelectedCpuSets(hMain, cpuSetIds, 1))
                                {
                                    LogColor(COLOR_SUCCESS, "  -> [优化] 主线程 %lu 绑定 CPU Set ID: %lu\n", pMainThread->threadId, idealCoreCpuSetId);
                                    pMainThread->hasCpuSets = true;
                                    pMainThread->assignedCpuSetId = idealCoreCpuSetId;
                                }
                                CloseHandle(hMain);
                            }
                        }
                        assignedMainCore = settings.idealCore;
                        assignedHeavyCore = settings.idealCore;
                    }

                    if (settings.optimizeOtherThreads && topology.isInitialized && !isImmediateRun)
                    {
                        std::vector<ThreadStats*> otherThreads;
                        for (auto& pair : procStats.threads) {
                            ThreadStats* t = &pair.second;
                            if (t->threadId == pMainThread->threadId) continue;
                            if (pHeavyThread && t->threadId == pHeavyThread->threadId) continue;
                            otherThreads.push_back(t);
                        }
                        std::sort(otherThreads.begin(), otherThreads.end(), [](ThreadStats* a, ThreadStats* b) {
                            return a->intervalAverageLoad > b->intervalAverageLoad;
                        });

                        if (!otherThreads.empty())
                        {
                            std::vector<DWORD> allocationQueue;
                            for (DWORD core : topology.pCores) {
                                if (core == assignedMainCore || core == assignedHeavyCore) continue;
                                allocationQueue.push_back(core);
                            }

                            std::vector<DWORD> htQueue;
                            DWORD mainHT = -1;
                            DWORD heavyHT = -1;
                            DWORD mainCoreIndex = topology.lpToCoreIndex.count(assignedMainCore) ? topology.lpToCoreIndex[assignedMainCore] : -1;
                            DWORD heavyCoreIndex = topology.lpToCoreIndex.count(assignedHeavyCore) ? topology.lpToCoreIndex[assignedHeavyCore] : -1;

                            for (DWORD core : topology.htCores) {
                                DWORD coreIndex = topology.lpToCoreIndex[core];
                                if (coreIndex == mainCoreIndex) mainHT = core;
                                else if (coreIndex == heavyCoreIndex) heavyHT = core;
                                else htQueue.push_back(core);
                            }

                            std::sort(htQueue.rbegin(), htQueue.rend());
                            allocationQueue.insert(allocationQueue.end(), htQueue.begin(), htQueue.end());

                            if (mainHT != -1) allocationQueue.push_back(mainHT);
                            if (heavyHT != -1 && heavyHT != mainHT) allocationQueue.push_back(heavyHT);

                            allocationQueue.insert(allocationQueue.end(), topology.eCores.begin(), topology.eCores.end());

                            if (!allocationQueue.empty())
                            {
                                LogColor(COLOR_INFO, "  -> [其余线程] 正在为 %zu 个线程分配理想核心 (队列长度: %zu)...\n", otherThreads.size(), allocationQueue.size());
                                int successCount = 0;
                                for (size_t i = 0; i < otherThreads.size(); ++i) {
                                    DWORD targetCore = allocationQueue[i % allocationQueue.size()];
                                    HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, otherThreads[i]->threadId);
                                    if (hThread) {
                                        if (SetThreadIdealProcessor(hThread, targetCore) != (DWORD)-1) {
                                            successCount++;
                                        }
                                        CloseHandle(hThread);
                                    }
                                }
                                LogColor(COLOR_SUCCESS, "     -> 已设置 %d / %zu 个线程的理想核心\n", successCount, otherThreads.size());
                            }
                        }
                    }
                }
            }
        }

        CloseHandle(hSnapshot);
    }
}

void ProcessListCheckThread()
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(settings.ioResetInterval));

        // 检查前台是否发生变化
        if (g_foregroundHasChanged.exchange(false))
        {
            LogColor(COLOR_INFO, "[状态变更] 前台进程已切换 正在执行维护任务...\n");

            // --- 1. 清理已退出进程的缓存数据 (仅在此处执行) ---
            {
                std::lock_guard<std::mutex> lock(g_statsMutex);
                if (!g_processStatsCache.empty())
                {
                    // 获取当前所有运行中的 PID
                    std::set<DWORD> runningPids;
                    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                    if (hSnapshot != INVALID_HANDLE_VALUE)
                    {
                        PROCESSENTRY32W pe32;
                        pe32.dwSize = sizeof(PROCESSENTRY32W);
                        if (Process32FirstW(hSnapshot, &pe32))
                        {
                            do { runningPids.insert(pe32.th32ProcessID); } while (Process32NextW(hSnapshot, &pe32));
                        }
                        CloseHandle(hSnapshot);
                    }

                    // 遍历缓存 移除不在 runningPids 中的进程
                    for (auto it = g_processStatsCache.begin(); it != g_processStatsCache.end(); )
                    {
                        if (runningPids.find(it->first) == runningPids.end())
                        {
                            LogColor(COLOR_DEFAULT, "  -> [缓存清理] 进程 PID %lu 已退出 清除其线程负载数据\n", it->first);
                            it = g_processStatsCache.erase(it);
                        }
                        else
                        {
                            ++it;
                        }
                    }
                }
            }
            // --------------------------------------------------

            // --- 2. 扫描并重置后台进程优先级 ---
            ScanAndResetIoPriorities();
        }
    }
}

void DwmThread()
{
    HMODULE dwmapi = LoadLibraryA("dwmapi.dll");
    if (!dwmapi) return;
    DwmEnableMMCSSPtr DwmEnableMMCSS = (DwmEnableMMCSSPtr)GetProcAddress(dwmapi, "DwmEnableMMCSS");
    if (!DwmEnableMMCSS) { FreeLibrary(dwmapi); return; }
    while (true)
    {
        DwmEnableMMCSS(TRUE);
        std::this_thread::sleep_for(std::chrono::seconds(settings.dwmInterval));
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    if (strstr(lpCmdLine, "-hide"))
    {
        g_silentMode = true;
    }

    if (!g_silentMode)
    {
        AllocConsole();
        FILE* f;
        g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleOutputCP(65001);
        freopen_s(&f, "CONOUT$", "w", stdout);
    }

    EnableAllPrivileges();

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastDot = path.find_last_of(L".");
    if (lastDot != std::wstring::npos) path = path.substr(0, lastDot);
    path += L".ini";

    ParseIniFile(path);

    LogColor(COLOR_INFO, "--- 正在启动所有后台线程 ---\n");

    std::thread t1(EventMessageLoopThread);
    std::thread t2(DwmThread);
    std::thread t3(ProcessListCheckThread);
    std::thread t4(ThreadOptimizerThread); // 新增的线程

    t1.join();
    t2.join();
    t3.join();
    t4.join(); // 等待新线程

    return 0;
}