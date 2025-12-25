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
    ULARGE_INTEGER lastKernelTime;
    ULARGE_INTEGER lastUserTime;
    ULARGE_INTEGER lastCheckTime;
    double currentLoad; // 当前瞬时负载 (0.0 - 100.0)
    double smoothedLoad; // 平滑后的负载 (EMA算法)
    bool isMainThread;
};

struct ProcessStats {
    DWORD processId;
    std::map<DWORD, ThreadStats> threads;
    bool isInitialized;
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
    int processListInterval = 60;
    int idealCore = -1;
};
Settings settings;
std::set<std::wstring> blackList, whiteList, blackListJob;
std::map<DWORD, HANDLE> managedJobs;
std::map<DWORD, IO_PRIORITY_HINT> originalIoPriorities;
DWORD lastProcessId = 0;
DWORD lastAttachedThreadId = 0;

// 用于缓存已处理或已跳过的进程 避免重复操作
std::set<std::pair<std::wstring, DWORD>> idealCoreSetCache;
std::set<std::pair<std::wstring, DWORD>> idealCoreSkippedCache;

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
                    else if (key == L"ProcessList") settings.processListInterval = std::stoi(value);
                    else if (key == L"IdealCore") settings.idealCore = std::stoi(value);
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
            // --- 新增部分开始: 设置主线程理想核心 ---
            if (settings.idealCore >= 0)
            {
                std::pair<std::wstring, DWORD> processKey = { processNameLower, currentProcessId };

                if (idealCoreSetCache.count(processKey))
                {
                    LogColor(COLOR_INFO, "  -> 理想核心: 进程已在成功缓存中 跳过\n");
                }
                else if (idealCoreSkippedCache.count(processKey))
                {
                    LogColor(COLOR_INFO, "  -> 理想核心: 进程已在跳过缓存中 跳过\n");
                }
                else
                {
                    LogColor(COLOR_INFO, "  -> 正在尝试为进程主线程设置理想核心...\n");
                    DWORD_PTR processAffinity, systemAffinity;
                    if (GetProcessAffinityMask(hNewProcess, &processAffinity, &systemAffinity))
                    {
                        // 检查是否设置了自定义亲和性 (如果进程亲和性与系统总亲和性不同)
                        // 并且理想核心不在亲和性掩码内
                        if (processAffinity != systemAffinity && (processAffinity & (1ULL << settings.idealCore)) == 0)
                        {
                            LogColor(COLOR_WARNING, "     - 跳过: 理想核心 %d 不在亲和性 (%llu) 范围内\n", settings.idealCore, processAffinity);
                            idealCoreSkippedCache.insert(processKey);
                        }
                        else
                        {
                            DWORD mainThreadId = GetProcessMainThreadId(currentProcessId);
                            if (mainThreadId != 0)
                            {
                                HANDLE hMainThread = OpenThread(THREAD_SET_INFORMATION, FALSE, mainThreadId);
                                if (hMainThread)
                                {
                                    if (SetThreadIdealProcessor(hMainThread, settings.idealCore) != (DWORD)-1)
                                    {
                                        LogColor(COLOR_SUCCESS, "     - 成功: 已将主线程 %lu 的理想核心设置为 %d\n", mainThreadId, settings.idealCore);
                                        idealCoreSetCache.insert(processKey);
                                    }
                                    else
                                    {
                                        LogColor(COLOR_ERROR, "     - 失败: 调用 SetThreadIdealProcessor 失败 错误码: %lu\n", GetLastError());
                                    }
                                    CloseHandle(hMainThread);
                                }
                                else
                                {
                                    LogColor(COLOR_ERROR, "     - 失败: 无法打开主线程句柄 错误码: %lu\n", GetLastError());
                                }
                            }
                            else
                            {
                                LogColor(COLOR_ERROR, "     - 失败: 无法找到进程的主线程\n");
                            }
                        }
                    }
                    else
                    {
                        LogColor(COLOR_ERROR, "     - 失败: 无法获取进程亲和性掩码 错误码: %lu\n", GetLastError());
                    }
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

// 定义 SYSTEM_CPU_SET_INFORMATION 结构 (防止旧版 SDK 缺失)
// 如果您的编译环境提示重定义，请注释掉此结构体
typedef struct _SYSTEM_CPU_SET_INFORMATION {
    DWORD Size;
    DWORD Type; // CpuSetInformation
    struct {
        DWORD Id;
        WORD Group;
        BYTE LogicalProcessorIndex;
        BYTE CoreIndex;
        BYTE LastLevelCacheIndex;
        BYTE NumaNodeIndex;
        BYTE EfficiencyClass;
        union {
            BYTE AllFlags;
            struct {
                BYTE Parked : 1;
                BYTE Allocated : 1;
                BYTE AllocatedToTargetProcess : 1;
                BYTE RealTime : 1;
                BYTE ReservedFlags : 4;
            } DUMMYSTRUCTNAME;
        } DUMMYUNIONNAME;
        union {
            DWORD Reserved;
            BYTE SchedulingClass;
        };
        DWORD64 AllocationTag;
    } CpuSet;
} SYSTEM_CPU_SET_INFORMATION, *PSYSTEM_CPU_SET_INFORMATION;

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

        // 移动到下一个条目 (注意：必须使用 entry->Size，因为结构体大小可能随系统版本变化)
        if (entry->Size == 0) break; // 防止死循环
        ptr += entry->Size;
    }

    return 0; // 未找到
}

void ThreadOptimizerThread()
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    // 加载 API
    SetThreadSelectedCpuSetsPtr pSetThreadSelectedCpuSets = 
        (SetThreadSelectedCpuSetsPtr)GetProcAddress(hKernel32, "SetThreadSelectedCpuSets");
    GetSystemCpuSetInformationPtr pGetSystemCpuSetInformation = 
        (GetSystemCpuSetInformationPtr)GetProcAddress(hKernel32, "GetSystemCpuSetInformation");

    if (!pSetThreadSelectedCpuSets || !pGetSystemCpuSetInformation)
    {
        LogColor(COLOR_WARNING, "[警告] 当前系统不支持 CPU Sets API (需要 Win10 1709+)，将仅使用 IdealProcessor。\n");
    }

    // --- 预先解析 IdealCore 对应的 CpuSetId ---
    ULONG targetCpuSetId = 0;
    ULONG heavyCpuSetId = 0; // 用于重负载线程 (IdealCore - 1)

    if (settings.idealCore >= 0 && pGetSystemCpuSetInformation) {
        targetCpuSetId = GetCpuSetIdFromLogicalIndex((DWORD)settings.idealCore, pGetSystemCpuSetInformation);
        if (targetCpuSetId != 0) {
            LogColor(COLOR_INFO, "[CPU Sets] 逻辑核心 %d 映射为 CPU Set ID: %lu\n", settings.idealCore, targetCpuSetId);
        } else {
            LogColor(COLOR_ERROR, "[CPU Sets] 错误: 无法找到逻辑核心 %d 的 CPU Set ID。\n", settings.idealCore);
        }

        // 尝试解析 IdealCore - 1 (用于隔离重负载线程)
        if (settings.idealCore > 0) {
            heavyCpuSetId = GetCpuSetIdFromLogicalIndex((DWORD)(settings.idealCore - 1), pGetSystemCpuSetInformation);
        }
    }
    // -------------------------------------------

    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        DWORD currentPid = lastProcessId;
        if (currentPid == 0) continue;

        FILETIME ftSystem;
        GetSystemTimeAsFileTime(&ftSystem);
        ULARGE_INTEGER now = FT2ULL(ftSystem);

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) continue;

        std::vector<DWORD> currentThreadIds;
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);

        {
            std::lock_guard<std::mutex> lock(g_statsMutex);
            ProcessStats& procStats = g_processStatsCache[currentPid];
            procStats.processId = currentPid;

            if (Thread32First(hSnapshot, &te32))
            {
                do
                {
                    if (te32.th32OwnerProcessID == currentPid)
                    {
                        DWORD tid = te32.th32ThreadID;
                        currentThreadIds.push_back(tid);

                        if (procStats.threads.find(tid) == procStats.threads.end())
                        {
                            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
                            if (hThread)
                            {
                                ThreadStats ts = {};
                                ts.threadId = tid;
                                ts.smoothedLoad = 0.0;
                                FILETIME ftExit, ftKernel, ftUser;
                                if (GetThreadTimes(hThread, &ts.creationTime, &ftExit, &ftKernel, &ftUser))
                                {
                                    ts.lastKernelTime = FT2ULL(ftKernel);
                                    ts.lastUserTime = FT2ULL(ftUser);
                                    ts.lastCheckTime = now;
                                    procStats.threads[tid] = ts;
                                }
                                CloseHandle(hThread);
                            }
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
                                    ULARGE_INTEGER k = FT2ULL(ftKernel);
                                    ULARGE_INTEGER u = FT2ULL(ftUser);
                                    
                                    ULONGLONG timeDelta = now.QuadPart - ts.lastCheckTime.QuadPart;
                                    ULONGLONG workDelta = (k.QuadPart - ts.lastKernelTime.QuadPart) + 
                                                          (u.QuadPart - ts.lastUserTime.QuadPart);

                                    if (timeDelta > 0)
                                    {
                                        ts.currentLoad = (double)workDelta / (double)timeDelta * 100.0;
                                        ts.smoothedLoad = 0.3 * ts.currentLoad + 0.7 * ts.smoothedLoad;
                                    }

                                    ts.lastKernelTime = k;
                                    ts.lastUserTime = u;
                                    ts.lastCheckTime = now;
                                }
                                CloseHandle(hThread);
                            }
                        }
                    }
                } while (Thread32Next(hSnapshot, &te32));
            }

            // 清理已退出的线程
            for (auto it = procStats.threads.begin(); it != procStats.threads.end(); )
            {
                bool exists = false;
                for (DWORD activeTid : currentThreadIds) {
                    if (activeTid == it->first) { exists = true; break; }
                }
                if (!exists) it = procStats.threads.erase(it);
                else ++it;
            }

            // --- 分析与应用策略 ---
            if (!procStats.threads.empty())
            {
                ThreadStats* pMainThread = nullptr;
                ThreadStats* pHeavyThread = nullptr;

                for (auto& pair : procStats.threads)
                {
                    ThreadStats& t = pair.second;
                    if (pMainThread == nullptr || CompareFileTime(&t.creationTime, &pMainThread->creationTime) < 0)
                        pMainThread = &t;

                    if (pMainThread && t.threadId != pMainThread->threadId)
                    {
                        if (pHeavyThread == nullptr || t.smoothedLoad > pHeavyThread->smoothedLoad)
                            pHeavyThread = &t;
                    }
                }

                if (pMainThread) pMainThread->isMainThread = true;

                // --- 执行优化策略 ---
                if (settings.idealCore >= 0 && pMainThread)
                {
                    HANDLE hMain = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, pMainThread->threadId);
                    if (hMain)
                    {
                        // 1. 设置理想核心 (软性建议)
                        SetThreadIdealProcessor(hMain, settings.idealCore);
                        
                        // 2. 设置 CPU Sets (硬性建议) - 使用正确的 ID
                        if (pSetThreadSelectedCpuSets && targetCpuSetId != 0)
                        {
                            ULONG cpuSetIds[] = { targetCpuSetId };
                            // 注意：这里传入的是 ID 数组，而不是逻辑核心索引
                            if (pSetThreadSelectedCpuSets(hMain, cpuSetIds, 1))
                            {
                                static DWORD lastReportedTid = 0;
                                if (lastReportedTid != pMainThread->threadId) {
                                    LogColor(COLOR_SUCCESS, "  -> [优化] 主线程 %lu 已绑定 CPU Set ID: %lu (逻辑核: %d)\n", 
                                        pMainThread->threadId, targetCpuSetId, settings.idealCore);
                                    lastReportedTid = pMainThread->threadId;
                                }
                            }
                        }
                        
                        CloseHandle(hMain);
                    }

                    // 策略 B: 隔离重负载线程
                    if (pHeavyThread && pHeavyThread->smoothedLoad > 10.0)
                    {
                        int heavyCore = settings.idealCore - 1;
                        if (heavyCore >= 0) 
                        {
                            HANDLE hHeavy = OpenThread(THREAD_SET_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, pHeavyThread->threadId);
                            if (hHeavy)
                            {
                                SetThreadIdealProcessor(hHeavy, heavyCore);
                                
                                // 如果我们也想为重负载线程设置 CPU Sets
                                if (pSetThreadSelectedCpuSets && heavyCpuSetId != 0)
                                {
                                    ULONG cpuSetIds[] = { heavyCpuSetId };
                                    pSetThreadSelectedCpuSets(hHeavy, cpuSetIds, 1);
                                }

                                CloseHandle(hHeavy);
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
        std::this_thread::sleep_for(std::chrono::seconds(settings.processListInterval));
        
        // 检查前台是否发生变化
        if (g_foregroundHasChanged.exchange(false))
        {
            LogColor(COLOR_INFO, "[状态变更] 前台进程已切换，正在执行维护任务...\n");

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

                    // 遍历缓存，移除不在 runningPids 中的进程
                    for (auto it = g_processStatsCache.begin(); it != g_processStatsCache.end(); )
                    {
                        if (runningPids.find(it->first) == runningPids.end())
                        {
                            LogColor(COLOR_DEFAULT, "  -> [缓存清理] 进程 PID %lu 已退出，清除其线程负载数据。\n", it->first);
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