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
#include <cstdio> // For printf and console functions

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
    int scheduling = -1; int weight = -1;
};
Settings settings;
std::set<std::wstring> blackList, whiteList, blackListJob;
std::map<DWORD, HANDLE> managedJobs;
std::map<DWORD, IO_PRIORITY_HINT> originalIoPriorities;
DWORD lastProcessId = 0;

// --- 函数定义 ---

// *** 关键变更：可靠的字符串到宽字符串转换函数 ***
std::wstring string_to_wstring(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

void ParseIniFile(const std::wstring& path) {
    printf("[Config] Attempting to load INI file from: %ws\n", path.c_str());
    std::ifstream file(path);
    if (!file.is_open()) {
        printf("[Config] ERROR: Could not open INI file. Using default settings.\n");
        return;
    }
    printf("[Config] Successfully opened INI file.\n");
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
                }
            } else if (currentSection == L"BlackList") blackList.insert(line);
            else if (currentSection == L"WhiteList") whiteList.insert(line);
            else if (currentSection == L"BlackListJob") blackListJob.insert(line);
        }
    }
    printf("[Config] Finished parsing INI file.\n");
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
    printf("  -> Applying Job Object settings...\n");
    if (blackListJob.count(processName)) {
        printf("     - Process is in Job blacklist. Skipping settings.\n");
        return;
    }
    if (settings.scheduling >= 0) {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        basicInfo.LimitFlags = JOB_OBJECT_LIMIT_SCHEDULING_CLASS;
        basicInfo.SchedulingClass = settings.scheduling;
        SetInformationJobObject(jobHandle, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo));
    }
    if (settings.weight >= 1) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        cpuInfo.Weight = settings.weight;
        SetInformationJobObject(jobHandle, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo));
    }
    if (settings.dscp >= 0) {
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG;
        netInfo.DscpTag = (BYTE)settings.dscp;
        SetInformationJobObject(jobHandle, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo));
    }
}

// *** 新增函数：用于撤销/禁用Job Object的设置 ***
void RevertJobObjectSettings(HANDLE jobHandle) {
    printf("  -> Reverting Job Object settings to default...\n");
    
    // 禁用调度类
    JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
    basicInfo.LimitFlags = 0; // 传入0来清除标志
    SetInformationJobObject(jobHandle, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo));

    // 禁用CPU权重
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
    cpuInfo.ControlFlags = 0; // 传入0来禁用控制
    SetInformationJobObject(jobHandle, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo));

    // 禁用DSCP
    JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
    netInfo.ControlFlags = 0; // 传入0来禁用控制
    SetInformationJobObject(jobHandle, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo));
}


void ForegroundBoosterThread() {
    while (true) {
        HWND foregroundWindow = GetForegroundWindow();
        DWORD currentProcessId = 0;
        if (foregroundWindow) GetWindowThreadProcessId(foregroundWindow, &currentProcessId);

        if (currentProcessId != lastProcessId) {
            // --- 1. 恢复上一个进程 ---
            if (lastProcessId != 0) {
                printf("Foreground changed from PID: %lu\n", lastProcessId);
                HANDLE hOldProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, lastProcessId);
                if (hOldProcess) {
                    if (originalIoPriorities.count(lastProcessId)) {
                        printf("  -> Restoring I/O priority to Normal for PID: %lu\n", lastProcessId);
                        SetProcessIoPriority(hOldProcess, originalIoPriorities[lastProcessId]);
                        originalIoPriorities.erase(lastProcessId);
                    }
                    CloseHandle(hOldProcess);
                }
                
                // *** 关键变更：不再关闭句柄，而是撤销设置 ***
                if (managedJobs.count(lastProcessId)) {
                    RevertJobObjectSettings(managedJobs[lastProcessId]);
                }
            }

            // --- 2. 处理新的前台进程 ---
            if (currentProcessId != 0) {
                printf("New foreground process PID: %lu\n", currentProcessId);
                std::wstring processName = GetProcessNameById(currentProcessId);
                if (!processName.empty() && !blackList.count(processName)) {
                    printf("  -> Process name: %ws is not in blacklist.\n", processName.c_str());
                    
                    HANDLE hJob = NULL;

                    // *** 关键变更：检查是否已为此进程创建过Job Object ***
                    if (managedJobs.count(currentProcessId)) {
                        printf("  -> Found existing Job Object for this process. Reusing.\n");
                        hJob = managedJobs[currentProcessId];
                    } else {
                        // 如果是第一次遇到此进程，则创建并分配
                        printf("  -> First time seeing this process. Creating new Job Object.\n");
                        HANDLE hNewProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE | SYNCHRONIZE, FALSE, currentProcessId);
                        if (hNewProcess) {
                            std::wstring jobName = L"Global\\ForegroundBoosterJob_PID_" + std::to_wstring(currentProcessId);
                            hJob = CreateJobObjectW(NULL, jobName.c_str());
                            if (hJob) {
                                if (AssignProcessToJobObject(hJob, hNewProcess)) {
                                    printf("  -> Successfully assigned process to Job Object.\n");
                                    managedJobs[currentProcessId] = hJob; // 保存句柄以备后用
                                } else {
                                    printf("  -> FAILED to assign process to Job Object. Error: %lu\n", GetLastError());
                                    CloseHandle(hJob);
                                    hJob = NULL; // 标记为失败
                                }
                            } else {
                                printf("  -> FAILED to create Job Object. Error: %lu\n", GetLastError());
                            }
                            CloseHandle(hNewProcess);
                        } else {
                             printf("  -> FAILED to open process handle. Error: %lu\n", GetLastError());
                        }
                    }

                    // 无论Job是新建的还是复用的，都应用前台设置
                    if (hJob) {
                        ApplyJobObjectSettings(hJob, processName);
                        
                        // 仅在需要时提升I/O优先级
                        HANDLE hProcessForIo = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, currentProcessId);
                        if(hProcessForIo) {
                            IO_PRIORITY_HINT currentPriority;
                            if (GetProcessIoPriority(hProcessForIo, currentPriority) && currentPriority == IoPriorityNormal) {
                                originalIoPriorities[currentProcessId] = currentPriority;
                                SetProcessIoPriority(hProcessForIo, IoPriorityHigh);
                                printf("  -> I/O priority elevated to High.\n");
                            }
                            CloseHandle(hProcessForIo);
                        }
                    }
                }
            }
            lastProcessId = currentProcessId;
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
    freopen_s(&f, "CONOUT$", "w", stdout);
    
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastDot = path.find_last_of(L".");
    if (lastDot != std::wstring::npos) path = path.substr(0, lastDot);
    path += L".ini";
    
    ParseIniFile(path);
    
    printf("--- Starting Main Loop ---\n");
    
    std::thread t1(ForegroundBoosterThread);
    std::thread t2(DwmThread);
    t1.join();
    t2.join();
    return 0;
}