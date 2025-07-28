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
#include <processthreadsapi.h> // <--- 已修正此处的打字错误
#include <locale>
#include <cstdio> 
#include <algorithm> 
#include <tlhelp32.h> 

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ntdll.lib")

// --- 手动定义标准 SDK 中不存在的 NT API 类型 ---
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
const PROCESS_INFORMATION_CLASS ProcessIoPriority = (PROCESS_INFORMATION_CLASS)33;
typedef enum _IO_PRIORITY_HINT {
    IoPriorityVeryLow = 0, IoPriorityLow = 1, IoPriorityNormal = 2,
    IoPriorityHigh = 3, IoPriorityCritical = 4, MaxIoPriorityTypes
} IO_PRIORITY_HINT;

// --- Windows Native API 函数指针 ---
using NtSetInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
using NtQueryInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using DwmEnableMMCSSPtr = HRESULT(WINAPI*)(BOOL);

// --- 全局配置变量 ---
struct Settings {
    int dwmInterval = 60; int foregroundInterval = 2; int dscp = -1;
    int scheduling = -1; int weight = -1; int processListInterval = 10;
};
Settings settings;
std::set<std::wstring> blackList, whiteList, blackListJob;
std::map<DWORD, HANDLE> managedJobs;
std::map<DWORD, IO_PRIORITY_HINT> originalIoPriorities;
DWORD lastProcessId = 0;
DWORD lastAttachedThreadId = 0;
std::set<DWORD> previousPids;
int timeAccumulator = 0;

// --- 函数定义 ---

std::wstring to_lower(std::wstring str) {
    std::transform(str.begin(), str.end(), str.begin(), ::towlower);
    return str;
}

std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

void ParseIniFile(const std::wstring& path) {
    printf("[配置] 正在尝试从以下路径加载INI文件: %ws\n", path.c_str());
    std::ifstream file(path);
    if (!file.is_open()) {
        printf("[配置] 错误: 无法打开INI文件。将使用默认设置。\n");
        return;
    }
    printf("[配置] 成功打开INI文件。\n");
    std::string narrow_line;
    std::wstring currentSection;
    while (std::getline(file, narrow_line)) {
        std::wstring line = string_to_wstring(narrow_line);
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (line.empty() || line[0] == L';' || line[0] == L'#') continue;
        if (line[0] == L'[' && line.back() == L']') {
            currentSection = line.substr(1, line.size() - 2);
        } else {
            if (currentSection == L"Settings") {
                std::wstringstream ss(line);
                std::wstring key, value;
                if (std::getline(ss, key, L'=') && std::getline(ss, value)) {
                    if (key == L"DwmEnableMMCSS") settings.dwmInterval = std::stoi(value);
                    else if (key == L"Foreground") settings.foregroundInterval = std::stoi(value);
                    else if (key == L"DSCP") settings.dscp = std::stoi(value);
                    else if (key == L"Scheduling") settings.scheduling = std::stoi(value);
                    else if (key == L"Weight") settings.weight = std::stoi(value);
                    else if (key == L"ProcessList") settings.processListInterval = std::stoi(value);
                }
            } else if (currentSection == L"BlackList") {
                blackList.insert(to_lower(line));
            } else if (currentSection == L"WhiteList") {
                whiteList.insert(to_lower(line));
            } else if (currentSection == L"BlackListJob") {
                blackListJob.insert(to_lower(line));
            }
        }
    }
}

std::wstring GetProcessNameById(DWORD processId) {
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (handle) {
        wchar_t buffer[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(handle, 0, buffer, &size)) {
            CloseHandle(handle);
            std::wstring fullPath(buffer);
            return fullPath.substr(fullPath.find_last_of(L"\\/") + 1);
        }
        CloseHandle(handle);
    }
    return L"";
}

void SetProcessIoPriority(HANDLE processHandle, IO_PRIORITY_HINT priority) {
    static NtSetInformationProcessPtr NtSetInformationProcess = (NtSetInformationProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (NtSetInformationProcess) NtSetInformationProcess(processHandle, ProcessIoPriority, &priority, sizeof(priority));
}

bool GetProcessIoPriority(HANDLE processHandle, IO_PRIORITY_HINT& priority) {
    static NtQueryInformationProcessPtr NtQueryInformationProcess = (NtQueryInformationProcessPtr)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess) {
        ULONG returnLength;
        NTSTATUS status = NtQueryInformationProcess(processHandle, ProcessIoPriority, &priority, sizeof(priority), &returnLength);
        return NT_SUCCESS(status);
    }
    return false;
}

void ApplyJobObjectSettings(HANDLE jobHandle, const std::wstring& processName) {
    printf("  -> 正在应用作业对象设置...\n");
    if (settings.scheduling >= 0) {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        basicInfo.LimitFlags = JOB_OBJECT_LIMIT_SCHEDULING_CLASS;
        basicInfo.SchedulingClass = settings.scheduling;
        if (SetInformationJobObject(jobHandle, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo))) {
            printf("     - 成功: 调度类已设置为 %d。\n", settings.scheduling);
        } else {
            printf("     - 失败: 无法设置调度类。错误码: %lu\n", GetLastError());
        }
    }
    if (settings.weight >= 1) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        cpuInfo.Weight = settings.weight;
        if (SetInformationJobObject(jobHandle, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo))) {
            printf("     - 成功: 时间片权重已设置为 %d。\n", settings.weight);
        } else {
            printf("     - 失败: 无法设置时间片权重。错误码: %lu\n", GetLastError());
        }
    }
    if (settings.dscp >= 0) {
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG;
        netInfo.DscpTag = (BYTE)settings.dscp;
        if (SetInformationJobObject(jobHandle, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo))) {
            printf("     - 成功: DSCP标记已设置为 %d。\n", settings.dscp);
        } else {
            printf("     - 失败: 无法设置DSCP标记。错误码: %lu\n", GetLastError());
        }
    }
}

void ResetAndReleaseJobObject(DWORD processId) {
    if (managedJobs.count(processId)) {
        HANDLE hJob = managedJobs[processId];
        printf("  -> 正在为进程ID %lu 重置作业对象设置...\n", processId);
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo));
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        SetInformationJobObject(hJob, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo));
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = (JOB_OBJECT_NET_RATE_CONTROL_FLAGS)0;
        SetInformationJobObject(hJob, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo));
        printf("  -> 正在为进程ID %lu 关闭句柄并释放作业对象...\n", processId);
        CloseHandle(hJob);
        managedJobs.erase(processId);
    }
}

void CheckAndResetIoPriorities() {
    printf("[后台检查] 正在检查进程列表变化...\n");
    std::set<DWORD> currentPids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            currentPids.insert(pe32.th32ProcessID);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    if (currentPids == previousPids) {
        printf("[后台检查] 进程列表无变化。\n");
        return;
    }

    printf("[后台检查] 检测到进程列表变化！正在扫描所有进程的I/O优先级...\n");
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            DWORD pid = pe32.th32ProcessID;
            std::wstring processNameLower = to_lower(pe32.szExeFile);

            if (pid == lastProcessId || blackList.count(processNameLower)) {
                continue;
            }

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, pid);
            if (!hProcess) continue;

            DWORD priorityClass = GetPriorityClass(hProcess);
            if (priorityClass == NORMAL_PRIORITY_CLASS || priorityClass == IDLE_PRIORITY_CLASS || priorityClass == BELOW_NORMAL_PRIORITY_CLASS) {
                IO_PRIORITY_HINT ioPriority;
                if (GetProcessIoPriority(hProcess, ioPriority) && ioPriority == IoPriorityHigh) {
                    printf("  -> 重置进程 %ws (PID: %lu) 的I/O优先级为“正常”。\n", processNameLower.c_str(), pid);
                    SetProcessIoPriority(hProcess, IoPriorityNormal);
                }
            }
            CloseHandle(hProcess);
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    previousPids = currentPids;
}

void ForegroundBoosterThread() {
    while (true) {
        HWND foregroundWindow = GetForegroundWindow();
        DWORD currentProcessId = 0;
        DWORD currentThreadId = 0;
        if (foregroundWindow) {
            currentThreadId = GetWindowThreadProcessId(foregroundWindow, &currentProcessId);
        }

        if (currentProcessId != lastProcessId) {
            if (lastProcessId != 0) {
                printf("前台进程已变更 (原PID: %lu)\n", lastProcessId);
                HANDLE hOldProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, lastProcessId);
                if (hOldProcess) {
                    if (originalIoPriorities.count(lastProcessId)) {
                        printf("  -> 正在为进程ID %lu 恢复I/O优先级为“正常”。\n", lastProcessId);
                        SetProcessIoPriority(hOldProcess, originalIoPriorities[lastProcessId]);
                        originalIoPriorities.erase(lastProcessId);
                    }
                    CloseHandle(hOldProcess);
                }
                ResetAndReleaseJobObject(lastProcessId);
            }

            if (currentProcessId != 0) {
                printf("新的前台进程PID: %lu\n", currentProcessId);
                std::wstring processNameLower = to_lower(GetProcessNameById(currentProcessId));
                if (!processNameLower.empty() && !blackList.count(processNameLower)) {
                    printf("  -> 进程名: %ws (不在黑名单中)。\n", processNameLower.c_str());
                    HANDLE hNewProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, currentProcessId);
                    if (hNewProcess) {
                        IO_PRIORITY_HINT currentPriority;
                        if (GetProcessIoPriority(hNewProcess, currentPriority) && currentPriority == IoPriorityNormal) {
                            originalIoPriorities[currentProcessId] = currentPriority;
                            SetProcessIoPriority(hNewProcess, IoPriorityHigh);
                            printf("  -> I/O优先级已提升为“高”。\n");
                        }
                        
                        if (!blackListJob.count(processNameLower)) {
                            std::wstring jobName = L"Global\\ForegroundBoosterJob_PID_" + std::to_wstring(currentProcessId);
                            HANDLE hJob = CreateJobObjectW(NULL, jobName.c_str());
                            if (hJob) {
                                printf("  -> 已创建作业对象: %ws\n", jobName.c_str());
                                ApplyJobObjectSettings(hJob, processNameLower);
                                if (AssignProcessToJobObject(hJob, hNewProcess)) {
                                    printf("  -> 成功将进程分配到已配置的作业对象。\n");
                                    managedJobs[currentProcessId] = hJob;
                                } else {
                                    printf("  -> 失败: 无法将进程分配到作业对象。错误码: %lu (进程可能已在另一个作业中)。\n", GetLastError());
                                    CloseHandle(hJob);
                                }
                            } else {
                                printf("  -> 失败: 无法创建作业对象。错误码: %lu\n", GetLastError());
                            }
                        } else {
                            printf("  -> 进程位于作业对象黑名单中，跳过Job Object操作。\n");
                        }
                        CloseHandle(hNewProcess);
                    } else {
                        DWORD lastError = GetLastError();
                        if (lastError == 5) {
                            printf("  -> 失败: 打开进程句柄时被拒绝访问(错误码 5)。这通常发生在受保护的进程(如浏览器、反作弊程序)上，将跳过。\n");
                        } else {
                            printf("  -> 失败: 无法打开进程。错误码: %lu\n", lastError);
                        }
                    }
                }
            }
            lastProcessId = currentProcessId;
        }

        if (currentThreadId != 0 && currentThreadId != lastAttachedThreadId) {
            printf("[附加线程] 检测到新的前台线程ID: %lu\n", currentThreadId);
            std::vector<DWORD> threadsToAttach;
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
            if (hSnapshot != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32W pe32;
                pe32.dwSize = sizeof(PROCESSENTRY32W);
                if (Process32FirstW(hSnapshot, &pe32)) {
                    do {
                        if (whiteList.count(to_lower(pe32.szExeFile))) {
                            HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                            if(hThreadSnapshot != INVALID_HANDLE_VALUE){
                                THREADENTRY32 te32;
                                te32.dwSize = sizeof(THREADENTRY32);
                                if (Thread32First(hThreadSnapshot, &te32)) {
                                    do {
                                        if (te32.th32OwnerProcessID == pe32.th32ProcessID) {
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

            if (!threadsToAttach.empty()) {
                if (lastAttachedThreadId != 0) {
                    printf("  -> 正在从旧的前台线程 %lu 分离 %zu 个白名单线程...\n", lastAttachedThreadId, threadsToAttach.size());
                    for (DWORD tid : threadsToAttach) {
                        AttachThreadInput(tid, lastAttachedThreadId, FALSE);
                    }
                }
                std::wstring currentProcessNameLower = to_lower(GetProcessNameById(currentProcessId));
                if (!whiteList.count(currentProcessNameLower)) {
                    printf("  -> 正在尝试将 %zu 个白名单线程附加到新的前台线程 %lu...\n", threadsToAttach.size(), currentThreadId);
                    int successCount = 0;
                    for (DWORD tid : threadsToAttach) {
                        if (AttachThreadInput(tid, currentThreadId, TRUE)) {
                            successCount++;
                        }
                    }
                    printf("  -> 附加完成: %d / %zu 个线程成功。\n", successCount, threadsToAttach.size());
                }
            }
            lastAttachedThreadId = currentThreadId;
        }

        timeAccumulator += settings.foregroundInterval;
        if (timeAccumulator >= settings.processListInterval) {
            CheckAndResetIoPriorities();
            timeAccumulator = 0;
        }

        std::this_thread::sleep_for(std::chrono::seconds(settings.foregroundInterval));
    }
}

void DwmThread() {
    HMODULE dwmapi = LoadLibraryA("dwmapi.dll");
    if (!dwmapi) return;
    DwmEnableMMCSSPtr DwmEnableMMCSS = (DwmEnableMMCSSPtr)GetProcAddress(dwmapi, "DwmEnableMMCSS");
    if (!DwmEnableMMCSS) { FreeLibrary(dwmapi); return; }
    while (true) {
        DwmEnableMMCSS(TRUE);
        std::this_thread::sleep_for(std::chrono::seconds(settings.dwmInterval));
    }
}

int main() {
    AllocConsole();
    FILE* f;
    SetConsoleOutputCP(65001);
    freopen_s(&f, "CONOUT$", "w", stdout);
    
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastDot = path.find_last_of(L".");
    if (lastDot != std::wstring::npos) path = path.substr(0, lastDot);
    path += L".ini";
    
    ParseIniFile(path);
    
    printf("--- 主循环已启动 ---\n");
    
    std::thread t1(ForegroundBoosterThread);
    std::thread t2(DwmThread);
    t1.join();
    t2.join();
    return 0;
}