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
#include <set>
#include <utility>

std::set<std::pair<std::wstring, DWORD>> idealCoreCache;

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

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

// --- 新增函数: 获取进程的主线程ID ---
// 通过遍历线程并比较创建时间来找到第一个创建的线程
DWORD GetProcessMainThreadId(DWORD dwProcessId)
{
    struct ThreadInfo {
        DWORD threadId;
        FILETIME creationTime;
    };

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
        return 0;
    }

    // 根据创建时间排序，找到最早创建的线程
    std::sort(threads.begin(), threads.end(), [](const ThreadInfo& a, const ThreadInfo& b) {
        return CompareFileTime(&a.creationTime, &b.creationTime) < 0;
    });

    return threads[0].threadId;
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
            // --- 新增: 设置主线程理想核心的逻辑 ---
            if (settings.idealCore >= 0)
            {
                LogColor(COLOR_INFO, "  -> [理想核心] 正在检查理想核心设置 (配置为: %d)...\n", settings.idealCore);
                std::pair<std::wstring, DWORD> cacheKey = { processNameLower, currentProcessId };

                if (idealCoreCache.count(cacheKey))
                {
                    LogColor(COLOR_SUCCESS, "     - 跳过: 进程已在缓存中，之前已设置成功。\n");
                }
                else
                {
                    bool isCoreAllowed = false;
                    
                    // 1. 检查进程亲和性 (Process Affinity)
                    DWORD_PTR processAffinityMask, systemAffinityMask;
                    if (GetProcessAffinityMask(hNewProcess, &processAffinityMask, &systemAffinityMask))
                    {
                        if ((processAffinityMask & (1ULL << settings.idealCore)))
                        {
                            isCoreAllowed = true;
                            LogColor(COLOR_INFO, "     - 检查通过: 理想核心 %d 在进程亲和性掩码 (0x%llX) 范围内。\n", settings.idealCore, processAffinityMask);
                        }
                    }

                    // 2. 如果亲和性未设置或不匹配，检查 CPU Sets (适用于较新的Windows版本)
                    if (!isCoreAllowed)
                    {
                        // 动态加载 GetProcessDefaultCpuSets 以兼容旧版系统
                        using GetProcessDefaultCpuSetsPtr = BOOL(WINAPI*)(HANDLE, PULONG, ULONG, PULONG);
                        GetProcessDefaultCpuSetsPtr pGetProcessDefaultCpuSets = (GetProcessDefaultCpuSetsPtr)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "GetProcessDefaultCpuSets");

                        if (pGetProcessDefaultCpuSets)
                        {
                            ULONG requiredSize = 0;
                            pGetProcessDefaultCpuSets(hNewProcess, NULL, 0, &requiredSize);
                            if (requiredSize > 0)
                            {
                                std::vector<ULONG> cpuSetIds(requiredSize / sizeof(ULONG));
                                if (pGetProcessDefaultCpuSets(hNewProcess, cpuSetIds.data(), (ULONG)cpuSetIds.size() * sizeof(ULONG), &requiredSize))
                                {
                                    for (ULONG coreId : cpuSetIds)
                                    {
                                        if (coreId == (ULONG)settings.idealCore)
                                        {
                                            isCoreAllowed = true;
                                            LogColor(COLOR_INFO, "     - 检查通过: 理想核心 %d 在进程的 CPU Sets 列表中。\n", settings.idealCore);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (isCoreAllowed)
                    {
                        DWORD mainThreadId = GetProcessMainThreadId(currentProcessId);
                        if (mainThreadId != 0)
                        {
                            HANDLE hMainThread = OpenThread(THREAD_SET_INFORMATION, FALSE, mainThreadId);
                            if (hMainThread)
                            {
                                if (SetThreadIdealProcessor(hMainThread, settings.idealCore) != (DWORD)-1)
                                {
                                    LogColor(COLOR_SUCCESS, "     - 成功: 已将主线程 %lu 的理想核心设置为 %d。\n", mainThreadId, settings.idealCore);
                                    idealCoreCache.insert(cacheKey); // 添加到缓存
                                }
                                else
                                {
                                    LogColor(COLOR_ERROR, "     - 失败: 设置主线程 %lu 的理想核心时出错。错误码: %lu\n", mainThreadId, GetLastError());
                                }
                                CloseHandle(hMainThread);
                            }
                            else
                            {
                                LogColor(COLOR_ERROR, "     - 失败: 无法打开主线程 %lu 的句柄。错误码: %lu\n", mainThreadId, GetLastError());
                            }
                        }
                        else
                        {
                            LogColor(COLOR_ERROR, "     - 失败: 无法找到进程的主线程。\n");
                        }
                    }
                    else
                    {
                        LogColor(COLOR_WARNING, "     - 跳过: 配置的理想核心 %d 不在进程的亲和性或CPU Sets允许范围内。\n", settings.idealCore);
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

void ProcessListCheckThread()
{
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(settings.processListInterval));
        ScanAndResetIoPriorities();
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

    t1.join();
    t2.join();
    t3.join();

    return 0;
}