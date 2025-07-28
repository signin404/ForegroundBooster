#include <iostream>
#include <windows.h>
#include <winnt.h> // 显式包含以获取 Job Object 定义
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <map>
#include <set>
#include <fstream>
#include <sstream>
#include <processthreadsapi.h> // 用于 QueryFullProcessImageNameW

#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "ntdll.lib")

// --- Windows Native API 函数指针 ---
// 我们对 ntdll.dll 中的函数使用函数指针
using NtSetInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
using NtQueryInformationProcessPtr = NTSTATUS(NTAPI*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG, PULONG);
using DwmEnableMMCSSPtr = HRESULT(WINAPI*)(BOOL);

// --- 全局配置变量 ---
struct Settings {
    int dwmInterval = 60;
    int foregroundInterval = 2;
    int dscp = -1;
    int scheduling = -1;
    int weight = -1;
};

Settings settings;
std::set<std::wstring> blackList;
std::set<std::wstring> whiteList;
std::set<std::wstring> blackListJob;
std::map<DWORD, HANDLE> managedJobs;

// 用于存储原始优先级以便恢复的 Map
std::map<DWORD, IO_PRIORITY_HINT> originalIoPriorities;
DWORD lastProcessId = 0;

// --- INI 文件解析 ---
void ParseIniFile(const std::wstring& path) {
    std::wifstream file(path); // 使用 wifstream 处理宽字符串
    if (!file.is_open()) {
        return; // 如果找不到 INI 文件则静默返回
    }

    file.imbue(std::locale("")); // 处理不同的文本编码

    std::wstring line;
    std::wstring currentSection;

    while (std::getline(file, line)) {
        // 清理空白字符和回车
        line.erase(0, line.find_first_not_of(L" \t\r\n"));
        line.erase(line.find_last_not_of(L" \t\r\n") + 1);

        if (line.empty() || line[0] == L';') continue;

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
            } else if (currentSection == L"BlackList") {
                blackList.insert(line);
            } else if (currentSection == L"WhiteList") {
                whiteList.insert(line);
            } else if (currentSection == L"BlackListJob") {
                blackListJob.insert(line);
            }
        }
    }
}

// --- 核心功能函数 ---

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
    if (NtSetInformationProcess) {
        NtSetInformationProcess(processHandle, ProcessIoPriority, &priority, sizeof(priority));
    }
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
    if (blackListJob.count(processName)) return;

    if (settings.scheduling >= 0 && settings.scheduling <= 9) {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        basicInfo.LimitFlags = JOB_OBJECT_LIMIT_SCHEDULING_CLASS;
        basicInfo.SchedulingClass = settings.scheduling;
        SetInformationJobObject(jobHandle, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo));
    }
    
    if (settings.weight >= 1 && settings.weight <= 9) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
        cpuInfo.Weight = settings.weight;
        SetInformationJobObject(jobHandle, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo));
    }

    if (settings.dscp >= 0 && settings.dscp <= 63) {
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG;
        netInfo.DscpTag = (BYTE)settings.dscp;
        SetInformationJobObject(jobHandle, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo));
    }
}

void ReleaseJobObject(DWORD processId) {
    if (managedJobs.count(processId)) {
        CloseHandle(managedJobs[processId]);
        managedJobs.erase(processId);
    }
}

void ForegroundBoosterThread() {
    while (true) {
        HWND foregroundWindow = GetForegroundWindow();
        DWORD currentProcessId = 0;
        if (foregroundWindow) {
            GetWindowThreadProcessId(foregroundWindow, &currentProcessId);
        }

        if (currentProcessId != lastProcessId) {
            // 1. 恢复上一个进程
            if (lastProcessId != 0) {
                HANDLE hOldProcess = OpenProcess(PROCESS_SET_INFORMATION, FALSE, lastProcessId);
                if (hOldProcess) {
                    if (originalIoPriorities.count(lastProcessId)) {
                        SetProcessIoPriority(hOldProcess, originalIoPriorities[lastProcessId]);
                        originalIoPriorities.erase(lastProcessId);
                    }
                    CloseHandle(hOldProcess);
                }
                // 始终释放 Job Object
                ReleaseJobObject(lastProcessId);
            }

            // 2. 处理新进程
            if (currentProcessId != 0) {
                std::wstring processName = GetProcessNameById(currentProcessId);
                if (!processName.empty() && !blackList.count(processName)) {
                    HANDLE hNewProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_QUOTA | SYNCHRONIZE, FALSE, currentProcessId);
                    if (hNewProcess) {
                        IO_PRIORITY_HINT currentPriority;
                        if (GetProcessIoPriority(hNewProcess, currentPriority) && currentPriority < IoPriorityHigh) {
                            originalIoPriorities[currentProcessId] = currentPriority;
                            SetProcessIoPriority(hNewProcess, IoPriorityHigh);
                        }

                        HANDLE hJob = CreateJobObject(NULL, NULL);
                        if (hJob) {
                            if (AssignProcessToJobObject(hJob, hNewProcess)) {
                                managedJobs[currentProcessId] = hJob;
                                ApplyJobObjectSettings(hJob, processName);
                            } else {
                                CloseHandle(hJob);
                            }
                        }
                        CloseHandle(hNewProcess);
                    }
                }
            }
            lastProcessId = currentProcessId;
        }
        
        // 线程附加逻辑 (此处为占位符)
        // ...

        std::this_thread::sleep_for(std::chrono::seconds(settings.foregroundInterval));
    }
}

void DwmThread() {
    HMODULE dwmapi = LoadLibraryA("dwmapi.dll");
    if (!dwmapi) return;
    
    DwmEnableMMCSSPtr DwmEnableMMCSS = (DwmEnableMMCSSPtr)GetProcAddress(dwmapi, "DwmEnableMMCSS");
    if (!DwmEnableMMCSS) {
        FreeLibrary(dwmapi);
        return;
    }

    while (true) {
        DwmEnableMMCSS(TRUE);
        std::this_thread::sleep_for(std::chrono::seconds(settings.dwmInterval));
    }
}

int main() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastDot = path.find_last_of(L".");
    if (lastDot != std::wstring::npos) {
        path = path.substr(0, lastDot);
    }
    path += L".ini";

    ParseIniFile(path);

    std::thread t1(ForegroundBoosterThread);
    std::thread t2(DwmThread);

    t1.join();
    t2.join();

    return 0;
}