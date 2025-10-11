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

// --- NEW: Global flag to control logging ---
bool g_ConsoleAttached = false;

void LogColor(int color, const wchar_t* format, ...) {
    if (!g_ConsoleAttached) return;
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
    if (g_ConsoleAttached) std::wcout << L"----------------------------------------------------\n" << std::endl;
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

bool ParseAffinityString(std::wstring w_s, DWORD_PTR& mask) {
    std::replace(w_s.begin(), w_s.end(), L' ', L',');
    std::string s(w_s.begin(), w_s.end());
    mask = 0;
    std::stringstream ss(s);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        if (segment.empty()) continue;
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

std::vector<DWORD> FindProcessByName(std::wstring processName) {
    std::vector<DWORD> pids;
    if (processName.length() < 4 || _wcsicmp(processName.substr(processName.length() - 4).c_str(), L".exe") != 0) {
        processName += L".exe";
    }
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
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
        LogColor(COLOR_WARNING, L"\n正在退出... 限制将保持生效。\n");
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

    bool ApplySettings(DWORD_PTR affinity, int priority, int scheduling, int weight, int dscp, int cpuLimit, const std::pair<size_t, size_t>& workingSet) {
        bool success = true;
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {};
        QueryInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo), NULL);
        basicInfo.LimitFlags = 0;
        if (affinity != 0) { basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY; basicInfo.Affinity = affinity; }
        if (priority != -1) { basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS; basicInfo.PriorityClass = priority; }
        if (scheduling != -1) { basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_SCHEDULING_CLASS; basicInfo.SchedulingClass = scheduling; }
        if (workingSet.first > 0 && workingSet.second > 0) {
            basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
            basicInfo.MinimumWorkingSetSize = workingSet.first * 1024 * 1024;
            basicInfo.MaximumWorkingSetSize = workingSet.second * 1024 * 1024;
        }
        if (!SetInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo))) success = false;

        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        if (weight != -1) {
            cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
            cpuInfo.Weight = weight;
        } else if (cpuLimit != -1) {
            cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpuInfo.CpuRate = cpuLimit * 100;
        }
        if (!SetInformationJobObject(m_hJob, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo))) success = false;

        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(0);
        if (dscp != -1) {
            netInfo.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(netInfo.ControlFlags | JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG);
            netInfo.DscpTag = (BYTE)dscp;
        }
        if (!SetInformationJobObject(m_hJob, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo))) success = false;
        
        return success;
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
        wss << L"0x" << std::hex << std::uppercase << basicInfo.Affinity;
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
        
        std::wstring workingSet_str = L"已禁用";
        if (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_WORKINGSET) {
            workingSet_str = std::to_wstring(basicInfo.MinimumWorkingSetSize / 1024 / 1024) + L"MB - " + std::to_wstring(basicInfo.MaximumWorkingSetSize / 1024 / 1024) + L"MB";
        }
        PrintStatusLine(L"8. 物理内存限制 (WorkingSet)", workingSet_str);
        
        std::wcout << L"----------------------------------------------------\n";
    }

private:
    HANDLE m_hJob;
};

// --- NEW: Function to redirect standard I/O to the console ---
void RedirectIOToConsole() {
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);

    // Sync C++ streams with the new C streams
    std::wcout.clear();
    std::wcin.clear();
    std::wcerr.clear();

    // Set streams to Unicode mode
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stdin),  _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);
}

int wmain(int argc, wchar_t* argv[]) {
    bool isOneShotMode = argc > 1;

    // --- MODIFIED: Conditional console attachment logic ---
    if (isOneShotMode) {
        // Try to attach to parent console. If it fails, we run silently.
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            g_ConsoleAttached = true;
            RedirectIOToConsole();
        }
    } else {
        // Interactive mode MUST have a console.
        if (AttachConsole(ATTACH_PARENT_PROCESS) || AllocConsole()) {
            g_ConsoleAttached = true;
            RedirectIOToConsole();
        }
    }

    EnableAllPrivileges();
    
    std::map<std::wstring, std::wstring> args;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg.rfind(L'-', 0) == 0 && i + 1 < argc) {
            arg.erase(0, 1);
            std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);
            args[arg] = argv[++i];
        }
    }
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        LogColor(COLOR_ERROR, L"错误: 无法设置 Ctrl+C 处理器。\n");
        return 1;
    }
    std::vector<DWORD> pids;
    std::wstring jobIdentifier;
    bool isInputByName = false;

    if (isOneShotMode) {
        if (args.count(L"processname")) {
            isInputByName = true;
            jobIdentifier = args[L"processname"];
            pids = FindProcessByName(jobIdentifier);
        } else if (args.count(L"processid")) {
            isInputByName = false;
            jobIdentifier = args[L"processid"];
            try { pids.push_back(std::stoi(jobIdentifier)); } catch(...) {}
        } else {
            LogColor(COLOR_ERROR, L"错误: 在一次性模式下, 必须提供 -ProcessName 或 -ProcessId 参数。\n");
            return 1;
        }
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
        LogColor(COLOR_ERROR, L"未找到任何目标进程, 脚本将退出。\n");
        return 1;
    }
    LogColor(COLOR_INFO, L"已找到 %zu 个目标进程:\n", pids.size());
    for (DWORD pid : pids) LogColor(COLOR_INFO, L"  - PID: %lu\n", pid);
    
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
    
    LogColor(COLOR_INFO, L"正在将进程分配到 Job Object...\n");
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            // --- NEW: Enhanced per-process logging ---
            if (AssignProcessToJobObject(g_hJob, hProcess)) {
                LogColor(COLOR_SUCCESS, L"  -> 成功分配 PID: %lu\n", pid);
            } else {
                LogColor(COLOR_ERROR, L"  -> 失败分配 PID: %lu (错误码: %lu)\n", pid, GetLastError());
            }
            CloseHandle(hProcess);
        } else {
             LogColor(COLOR_ERROR, L"  -> 打开 PID %lu 失败！(错误码: %lu)\n", pid, GetLastError());
        }
    }
    
    JobController controller(g_hJob);
    if (isOneShotMode) {
        LogColor(COLOR_INFO, L"----------------------------------------------------\n");
        LogColor(COLOR_INFO, L"正在应用一次性设置...\n");
        DWORD_PTR affinity = 0;
        int priority = -1, scheduling = -1, weight = -1, dscp = -1, cpuLimit = -1;
        std::pair<size_t, size_t> workingSet = {0, 0};

        if (args.count(L"affinity")) ParseAffinityString(args[L"affinity"], affinity);
        if (args.count(L"priority")) {
            std::wstring p = args[L"priority"];
            std::transform(p.begin(), p.end(), p.begin(), ::towlower);
            if (p == L"idle") priority = IDLE_PRIORITY_CLASS;
            else if (p == L"belownormal") priority = BELOW_NORMAL_PRIORITY_CLASS;
            else if (p == L"normal") priority = NORMAL_PRIORITY_CLASS;
            else if (p == L"abovenormal") priority = ABOVE_NORMAL_PRIORITY_CLASS;
            else if (p == L"high") priority = HIGH_PRIORITY_CLASS;
            else if (p == L"realtime") priority = REALTIME_PRIORITY_CLASS;
        }
        if (args.count(L"scheduling")) try { scheduling = std::stoi(args[L"scheduling"]); } catch(...) {}
        if (args.count(L"weight")) try { weight = std::stoi(args[L"weight"]); } catch(...) {}
        if (args.count(L"cpulimit")) try { cpuLimit = std::stoi(args[L"cpulimit"]); } catch(...) {}
        if (args.count(L"dscp")) try { dscp = std::stoi(args[L"dscp"]); } catch(...) {}
        if (args.count(L"working")) {
            std::wstring ws_str = args[L"working"];
            size_t dash_pos = ws_str.find(L'-');
            if (dash_pos != std::wstring::npos) {
                try {
                    workingSet.first = std::stoul(ws_str.substr(0, dash_pos));
                    workingSet.second = std::stoul(ws_str.substr(dash_pos + 1));
                } catch(...) {}
            }
        }
        
        if (controller.ApplySettings(affinity, priority, scheduling, weight, dscp, cpuLimit, workingSet)) LogColor(COLOR_SUCCESS, L"设置已成功应用。脚本将退出，限制将持续有效。\n");
        else LogColor(COLOR_ERROR, L"应用设置失败！错误码: %lu\n", GetLastError());
        CloseHandle(g_hJob);
        g_hJob = NULL;
    } else {
        DWORD_PTR affinity = 0;
        int priority = -1, scheduling = -1, weight = -1, dscp = -1, cpuLimit = -1;
        std::pair<size_t, size_t> workingSet = {0, 0};

        while (true) {
            controller.DisplayStatus();
            std::wcout << L"请选择要修改的功能 (-1, 1-8), 或输入 'exit' 退出: ";
            std::wstring choice;
            std::getline(std::wcin, choice);
            if (choice == L"-1") {
                ClearAllJobSettings(g_hJob);
                LogColor(COLOR_SUCCESS, L"所有限制已成功禁用！\n");
                std::wcout << L"按回车键继续...";
                std::wstring dummy;
                std::getline(std::wcin, dummy);
                continue;
            } else if (choice == L"1") {
                std::wcout << L"新亲和性 (例: 8 10 12-15) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") affinity = 0; else ParseAffinityString(input, affinity);
            } else if (choice == L"2") {
                std::wcout << L"新优先级 (Idle, BelowNormal, Normal, AboveNormal, High, RealTime) 或 -1 禁用: ";
                std::wstring w_input; std::getline(std::wcin, w_input);
                std::transform(w_input.begin(), w_input.end(), w_input.begin(), ::towlower);
                if (w_input == L"-1") priority = -1;
                else if (w_input == L"idle") priority = IDLE_PRIORITY_CLASS;
                else if (w_input == L"belownormal") priority = BELOW_NORMAL_PRIORITY_CLASS;
                else if (w_input == L"normal") priority = NORMAL_PRIORITY_CLASS;
                else if (w_input == L"abovenormal") priority = ABOVE_NORMAL_PRIORITY_CLASS;
                else if (w_input == L"high") priority = HIGH_PRIORITY_CLASS;
                else if (w_input == L"realtime") priority = REALTIME_PRIORITY_CLASS;
            } else if (choice == L"3") {
                std::wcout << L"新调度优先级 (0-9) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") scheduling = -1; else try { scheduling = std::stoi(input); } catch(...) {}
            } else if (choice == L"4") {
                std::wcout << L"新时间片权重 (1-9) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") weight = -1; else try { weight = std::stoi(input); cpuLimit = -1; } catch(...) {}
            } else if (choice == L"5") {
                std::wcout << L"新数据包优先级 (0-63) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") dscp = -1; else try { dscp = std::stoi(input); } catch(...) {}
            } else if (choice == L"6") {
                std::wcout << L"新CPU使用率上限 (1-100) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") cpuLimit = -1; else try { cpuLimit = std::stoi(input); weight = -1; } catch(...) {}
            } else if (choice == L"8") {
                std::wcout << L"新物理内存上限 (格式: 最小MB-最大MB) 或 -1 禁用: ";
                std::wstring input; std::getline(std::wcin, input);
                if (input == L"-1") { workingSet = {0, 0}; }
                else {
                    size_t dash_pos = input.find(L'-');
                    if (dash_pos != std::wstring::npos) {
                        try {
                            workingSet.first = std::stoul(input.substr(0, dash_pos));
                            workingSet.second = std::stoul(input.substr(dash_pos + 1));
                        } catch(...) {}
                    }
                }
            } else if (choice == L"exit") {
                break;
            } else {
                std::wcout << L"无效的选择, 请按回车键重试...";
                std::wstring dummy;
                std::getline(std::wcin, dummy);
                continue;
            }
            controller.ApplySettings(affinity, priority, scheduling, weight, dscp, cpuLimit, workingSet);
        }
        CleanupAndExit();
    }
    return 0;
}