// ProcessController.cpp

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <psapi.h>
#include <map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <io.h>
#include <fcntl.h>
#include <tlhelp32.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

#if (NTDDI_VERSION < NTDDI_WIN10_RS1)
#ifndef JOB_OBJECT_NET_RATE_CONTROL_ENABLE
#define JOB_OBJECT_NET_RATE_CONTROL_ENABLE     0x1
#define JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH 0x2
#define JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG   0x4
#endif
#ifndef _JOBOBJECT_NET_RATE_CONTROL_INFORMATION_
#define _JOBOBJECT_NET_RATE_CONTROL_INFORMATION_
typedef struct _JOBOBJECT_NET_RATE_CONTROL_INFORMATION {
    DWORD64 MaxBandwidth;
    DWORD   ControlFlags;
    BYTE    DscpTag;
} JOBOBJECT_NET_RATE_CONTROL_INFORMATION, *PJOBOBJECT_NET_RATE_CONTROL_INFORMATION;
#endif
#ifndef JobObjectNetRateControlInformation
#define JobObjectNetRateControlInformation (JOBOBJECTINFOCLASS)32
#endif
#endif

HANDLE g_hJob = NULL;

#define COLOR_INFO 11
#define COLOR_SUCCESS 10
#define COLOR_WARNING 14
#define COLOR_ERROR 12
#define COLOR_DEFAULT 7

struct WorkingSetLimits {
    SIZE_T min = 0;
    SIZE_T max = 0;
    bool enabled = false;
};

void LogColor(int color, const wchar_t* format, ...) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
    wchar_t buffer[2048];
    va_list args;
    va_start(args, format);
    vswprintf(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
    va_end(args);
    std::wcout << buffer;
    SetConsoleTextAttribute(hConsole, COLOR_DEFAULT);
}

bool EnablePrivilege(LPCWSTR privilegeName) {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueW(NULL, privilegeName, &luid)) { CloseHandle(hToken); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return false; }
    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

void EnableAllPrivileges() {
    LogColor(COLOR_INFO, L"[权限提升] 正在尝试为当前进程启用所有可用特权...\n");
    const LPCWSTR privileges[] = {
        L"SeDebugPrivilege", L"SeTakeOwnershipPrivilege", L"SeBackupPrivilege", L"SeRestorePrivilege",
        L"SeLoadDriverPrivilege", L"SeSystemEnvironmentPrivilege", L"SeSecurityPrivilege",
        L"SeIncreaseQuotaPrivilege", L"SeChangeNotifyPrivilege", L"SeSystemProfilePrivilege",
        L"SeSystemtimePrivilege", L"SeProfileSingleProcessPrivilege", L"SeIncreaseBasePriorityPrivilege",
        L"SeCreatePagefilePrivilege", L"SeShutdownPrivilege", L"SeRemoteShutdownPrivilege",
        L"SeUndockPrivilege", L"SeManageVolumePrivilege", L"SeIncreaseWorkingSetPrivilege",
        L"SeTimeZonePrivilege", L"SeCreateSymbolicLinkPrivilege", L"SeDelegateSessionUserImpersonatePrivilege"
    };
    for (const auto& priv : privileges) {
        if (EnablePrivilege(priv)) LogColor(COLOR_SUCCESS, L"  -> 成功启用: %ws\n", priv);
        else LogColor(COLOR_WARNING, L"  -> 警告: 无法启用 %ws\n", priv);
    }
    std::wcout << L"----------------------------------------------------\n" << std::endl;
}

void PrintStatusLine(const std::wstring& label, const std::wstring& value) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::wcout << label;
    for (size_t i = label.length(); i < 25; ++i) std::wcout << L" ";
    std::wcout << L": ";
    if (value == L"已禁用") SetConsoleTextAttribute(hConsole, COLOR_ERROR);
    else SetConsoleTextAttribute(hConsole, COLOR_SUCCESS);
    std::wcout << value << std::endl;
    SetConsoleTextAttribute(hConsole, COLOR_DEFAULT);
}

bool ParseAffinityString(const std::wstring& w_s, DWORD_PTR& mask) {
    std::string s(w_s.begin(), w_s.end());
    mask = 0;
    std::stringstream ss(s);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        size_t dash_pos = segment.find('-');
        try {
            if (dash_pos == std::string::npos) {
                int cpu = std::stoi(segment);
                if (cpu >= 0 && cpu < sizeof(DWORD_PTR) * 8) mask |= (1ULL << cpu);
            } else {
                int start_cpu = std::stoi(segment.substr(0, dash_pos));
                int end_cpu = std::stoi(segment.substr(dash_pos + 1));
                for (int i = start_cpu; i <= end_cpu; ++i) if (i >= 0 && i < sizeof(DWORD_PTR) * 8) mask |= (1ULL << i);
            }
        } catch (...) { return false; }
    }
    return true;
}

bool ParseWorkingSetString(const std::wstring& w_s, WorkingSetLimits& limits) {
    std::string s(w_s.begin(), w_s.end());
    size_t dash_pos = s.find('-');
    if (dash_pos == std::string::npos) return false;
    try {
        limits.min = std::stoull(s.substr(0, dash_pos));
        limits.max = std::stoull(s.substr(dash_pos + 1));
        limits.enabled = true;
        return limits.min <= limits.max;
    } catch (...) {
        return false;
    }
}

// --- FINAL FIX: A robust implementation that correctly mimics PowerShell's `Get-Process -Name` ---
std::vector<DWORD> FindProcessByName(const std::wstring& processName) {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            std::wstring exeFile(pe32.szExeFile);
            size_t last_dot = exeFile.rfind(L'.');
            std::wstring baseName = (last_dot == std::wstring::npos) ? exeFile : exeFile.substr(0, last_dot);

            if (_wcsicmp(baseName.c_str(), processName.c_str()) == 0) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return pids;
}

void ClearAllJobSettings(HANDLE hJob) {
    JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimit = {};
    SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basicLimit, sizeof(basicLimit));
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuLimit = {};
    SetInformationJobObject(hJob, JobObjectCpuRateControlInformation, &cpuLimit, sizeof(cpuLimit));
    JOBOBJECT_NET_RATE_CONTROL_INFORMATION netLimit = {};
    netLimit.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(0);
    SetInformationJobObject(hJob, JobObjectNetRateControlInformation, &netLimit, sizeof(netLimit));
}

void CleanupAndExit() {
    if (g_hJob != NULL && g_hJob != INVALID_HANDLE_VALUE) {
        std::wcout << L"\n正在退出... 限制将保持生效。" << std::endl;
        CloseHandle(g_hJob);
        g_hJob = NULL;
    }
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
    case CTRL_C_EVENT: case CTRL_BREAK_EVENT: case CTRL_CLOSE_EVENT:
        CleanupAndExit();
        exit(0);
        return TRUE;
    default:
        return FALSE;
    }
}

class JobController {
public:
    JobController(HANDLE hJob) : m_hJob(hJob) {}
    bool ApplySettings() {
        bool basicResult = UpdateBasicLimits();
        bool cpuResult = UpdateCpuLimits();
        bool netResult = UpdateNetLimits();
        return basicResult && cpuResult && netResult;
    }
    void DisplayStatus() {
        system("cls");
        std::wcout << L"--- 进程控制器菜单 ---\n";
        PrintStatusLine(L"-1. 禁用所有限制", L"");
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        QueryInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo), NULL);
        QueryInformationJobObject(m_hJob, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo), NULL);
        QueryInformationJobObject(m_hJob, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo), NULL);
        
        std::wstringstream wss;
        wss << L"0x" << std::hex << basicInfo.Affinity;
        PrintStatusLine(L"1. 亲和性 (Affinity)", (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_AFFINITY) ? wss.str() : L"已禁用");
        
        std::wstring priority_str = L"已禁用";
        if (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_PRIORITY_CLASS) {
            switch (basicInfo.PriorityClass) {
                case IDLE_PRIORITY_CLASS: priority_str = L"Idle"; break;
                case BELOW_NORMAL_PRIORITY_CLASS: priority_str = L"BelowNormal"; break;
                case NORMAL_PRIORITY_CLASS: priority_str = L"Normal"; break;
                case ABOVE_NORMAL_PRIORITY_CLASS: priority_str = L"AboveNormal"; break;
                case HIGH_PRIORITY_CLASS: priority_str = L"High"; break;
                case REALTIME_PRIORITY_CLASS: priority_str = L"RealTime"; break;
            }
        }
        PrintStatusLine(L"2. 优先级 (Priority)", priority_str);
        PrintStatusLine(L"3. 调度优先级 (Scheduling)", (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS) ? std::to_wstring(basicInfo.SchedulingClass) : L"已禁用");
        PrintStatusLine(L"4. 时间片权重 (Weight)", ((cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED) && (cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) ? std::to_wstring(cpuInfo.Weight) : L"已禁用");
        PrintStatusLine(L"5. 数据包优先级 (DSCP)", ((netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG) && (netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE)) ? std::to_wstring(netInfo.DscpTag) : L"已禁用");
        PrintStatusLine(L"6. CPU使用率限制 (CpuLimit)", ((cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) && (cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) ? (std::to_wstring(cpuInfo.CpuRate / 100) + L"%") : L"已禁用");
        PrintStatusLine(L"7. 传出带宽限制 (NetLimit)", ((netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) && (netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE)) ? (std::to_wstring(netInfo.MaxBandwidth / 1024) + L" KB/s") : L"已禁用");
        
        std::wstring ws_str = L"已禁用";
        if (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_WORKINGSET) {
            ws_str = std::to_wstring(basicInfo.MinimumWorkingSetSize / (1024 * 1024)) + L"MB - " + std::to_wstring(basicInfo.MaximumWorkingSetSize / (1024 * 1024)) + L"MB";
        }
        PrintStatusLine(L"8. 物理内存限制 (Working)", ws_str);

        std::wcout << L"----------------------------------------------------\n";
    }
    DWORD_PTR affinity = 0;
    int priority = -1, scheduling = -1, weight = -1, dscp = -1, cpuLimit = -1, netLimit = -1;
    WorkingSetLimits workingSet;
private:
    HANDLE m_hJob;
    bool UpdateBasicLimits() {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimit = {};
        if (affinity != 0) { basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY; basicLimit.Affinity = affinity; }
        if (priority != -1) { basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS; basicLimit.PriorityClass = priority; }
        if (scheduling != -1) { basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_SCHEDULING_CLASS; basicLimit.SchedulingClass = scheduling; }
        if (workingSet.enabled) {
            basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
            basicLimit.MinimumWorkingSetSize = workingSet.min * 1024 * 1024;
            basicLimit.MaximumWorkingSetSize = workingSet.max * 1024 * 1024;
        }
        return SetInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicLimit, sizeof(basicLimit));
    }
    bool UpdateCpuLimits() {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuLimitInfo = {};
        if (weight != -1) {
            cpuLimitInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
            cpuLimitInfo.Weight = weight;
        } else if (cpuLimit != -1) {
            cpuLimitInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpuLimitInfo.CpuRate = cpuLimit * 100;
        }
        return SetInformationJobObject(m_hJob, JobObjectCpuRateControlInformation, &cpuLimitInfo, sizeof(cpuLimitInfo));
    }
    bool UpdateNetLimits() {
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netLimitInfo = {};
        netLimitInfo.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(0);
        if (netLimit != -1) {
            netLimitInfo.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(netLimitInfo.ControlFlags | JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH);
            netLimitInfo.MaxBandwidth = (DWORD64)netLimit * 1024;
        }
        if (dscp != -1) {
            netLimitInfo.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(netLimitInfo.ControlFlags | JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG);
            netLimitInfo.DscpTag = (BYTE)dscp;
        }
        return SetInformationJobObject(m_hJob, JobObjectNetRateControlInformation, &netLimitInfo, sizeof(netLimitInfo));
    }
};

int main(int argc, char* argv[]) {
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin),  _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    EnableAllPrivileges();
    
    std::map<std::string, std::string> args;
    bool isOneShotMode = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind('-', 0) == 0 && i + 1 < argc) {
            isOneShotMode = true;
            arg.erase(0, 1);
            std::transform(arg.begin(), arg.end(), arg.begin(), [](unsigned char c){ return std::tolower(c); });
            args[arg] = argv[++i];
        }
    }
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::wcerr << L"错误: 无法设置 Ctrl+C 处理器。" << std::endl;
        return 1;
    }
    std::vector<DWORD> pids;
    std::wstring jobIdentifier; 
    bool isInputByName = false;

    if (isOneShotMode) {
        // ... (One-shot mode logic remains the same)
    } else {
        while (pids.empty()) {
            std::wcout << L"请输入目标进程名 (例如: chrome), 或留空以输入进程ID: ";
            std::wstring name_input;
            std::getline(std::wcin, name_input);
            if (!name_input.empty()) {
                isInputByName = true;
                jobIdentifier = name_input;
                pids = FindProcessByName(jobIdentifier);
            } else {
                isInputByName = false;
                std::wcout << L"请输入目标进程ID: ";
                std::wstring id_input;
                std::getline(std::wcin, id_input);
                try {
                    jobIdentifier = id_input;
                    if(!id_input.empty()) pids.push_back(std::stoi(id_input));
                } catch(...) {}
            }
            if (pids.empty()) std::wcerr << L"未找到任何目标进程, 请重试。" << std::endl;
        }
    }
    if (pids.empty()) {
        std::wcerr << L"未找到任何目标进程, 脚本将退出。" << std::endl;
        return 1;
    }
    std::wcout << L"已找到 " << pids.size() << L" 个目标进程:" << std::endl;
    for (DWORD pid : pids) std::wcout << L"  - PID: " << pid << std::endl;
    
    std::wstring jobName;
    if (isInputByName) {
        jobName = L"Global\\ProcessControllerJob_Name_" + jobIdentifier;
    } else {
        jobName = L"Global\\ProcessControllerJob_PID_" + jobIdentifier;
    }

    g_hJob = CreateJobObjectW(NULL, jobName.c_str());
    if (g_hJob == NULL) {
        LogColor(COLOR_ERROR, L"CreateJobObjectW 失败！错误码: %lu\n", GetLastError());
        return 1;
    }
    LogColor(COLOR_INFO, L"Job Object '%ws' 已创建/打开。\n", jobName.c_str());
    
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (hProcess) {
            if (!AssignProcessToJobObject(g_hJob, hProcess)) LogColor(COLOR_ERROR, L"将 PID %lu 分配到 Job Object 失败！错误码: %lu\n", pid, GetLastError());
            CloseHandle(hProcess);
        } else {
             LogColor(COLOR_ERROR, L"打开 PID %lu 失败！错误码: %lu\n", pid, GetLastError());
        }
    }
    std::wcout << L"已将所有目标进程分配到 Job Object。" << std::endl;
    
    JobController controller(g_hJob);
    if (isOneShotMode) {
        // ... (One-shot mode logic remains the same)
    } else {
        while (true) {
            controller.DisplayStatus();
            std::wcout << L"请选择要修改的功能 (-1, 1-8), 或输入 'exit' 退出: ";
            std::wstring choice;
            std::getline(std::wcin, choice);
            
            bool settingsChanged = false;

            if (choice == L"-1") {
                ClearAllJobSettings(g_hJob);
                LogColor(COLOR_SUCCESS, L"所有限制已成功禁用！\n");
                std::wcout << L"按回车键继续...";
                std::wstring dummy;
                std::getline(std::wcin, dummy);
                continue; 
            } else if (choice == L"1") {
                std::wcout << L"新亲和性 (例: 8,10,12-15) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.affinity = 0; else ParseAffinityString(input, controller.affinity);
                settingsChanged = true;
            } else if (choice == L"2") {
                std::wcout << L"新优先级 (Idle, BelowNormal, Normal, AboveNormal, High, RealTime) 或 -1 禁用: ";
                std::wstring w_input; std::getline(std::wcin, w_input);
                std::string input(w_input.begin(), w_input.end());
                std::transform(input.begin(), input.end(), input.begin(), ::tolower);
                if (input == "-1") controller.priority = -1;
                else if (input == "idle") controller.priority = IDLE_PRIORITY_CLASS;
                else if (input == "belownormal") controller.priority = BELOW_NORMAL_PRIORITY_CLASS;
                else if (input == "normal") controller.priority = NORMAL_PRIORITY_CLASS;
                else if (input == "abovenormal") controller.priority = ABOVE_NORMAL_PRIORITY_CLASS;
                else if (input == "high") controller.priority = HIGH_PRIORITY_CLASS;
                else if (input == "realtime") controller.priority = REALTIME_PRIORITY_CLASS;
                settingsChanged = true;
            } else if (choice == L"3") {
                std::wcout << L"新调度优先级 (0-9) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.scheduling = -1; else try { controller.scheduling = std::stoi(input); } catch(...) {}
                settingsChanged = true;
            } else if (choice == L"4") {
                std::wcout << L"新时间片权重 (1-9) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.weight = -1; else try { controller.weight = std::stoi(input); controller.cpuLimit = -1; } catch(...) {}
                settingsChanged = true;
            } else if (choice == L"5") {
                std::wcout << L"新数据包优先级 (0-63) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.dscp = -1; else try { controller.dscp = std::stoi(input); } catch(...) {}
                settingsChanged = true;
            } else if (choice == L"6") {
                std::wcout << L"新CPU使用率上限 (1-100) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.cpuLimit = -1; else try { controller.cpuLimit = std::stoi(input); controller.weight = -1; } catch(...) {}
                settingsChanged = true;
            } else if (choice == L"7") {
                std::wcout << L"新传出带宽上限 (KB/s) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.netLimit = -1; else try { controller.netLimit = std::stoi(input); } catch(...) {}
                settingsChanged = true;
            } else if (choice == L"8") {
                std::wcout << L"新物理内存上限 (格式: 最小MB-最大MB) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") controller.workingSet.enabled = false; 
                else if (!ParseWorkingSetString(input, controller.workingSet)) {
                    LogColor(COLOR_ERROR, L"无效输入！\n");
                }
                settingsChanged = true;
            } else if (choice == L"exit") {
                break;
            } else {
                std::wcout << L"无效的选择, 请按回车键重试...";
                std::wstring dummy;
                std::getline(std::wcin, dummy);
            }
            
            if (settingsChanged) {
                controller.ApplySettings();
            }
        }
        CleanupAndExit();
    }
    return 0;
}