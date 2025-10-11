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
#include <tlhelp32.h>
#include <shellapi.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

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

std::vector<HANDLE> g_hJobs;
bool g_ConsoleAttached = false;

#define COLOR_LABEL_R 38
#define COLOR_LABEL_G 160
#define COLOR_LABEL_B 218

#define COLOR_ENABLED_R 246
#define COLOR_ENABLED_G 182
#define COLOR_ENABLED_B 78

#define COLOR_DISABLED_R 217
#define COLOR_DISABLED_G 66
#define COLOR_DISABLED_B 53

#define COLOR_SUCCESS_R 118
#define COLOR_SUCCESS_G 202
#define COLOR_SUCCESS_B 83

void SafeWriteConsole(const std::wstring& text) {
    if (!g_ConsoleAttached) return;
    DWORD charsWritten;
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), text.c_str(), static_cast<DWORD>(text.length()), &charsWritten, NULL);
}

void SetConsoleColorRGB(int r, int g, int b) {
    if (!g_ConsoleAttached) return;
    wchar_t color_buffer[64];
    swprintf(color_buffer, 64, L"\x1b[38;2;%d;%d;%dm", r, g, b);
    SafeWriteConsole(color_buffer);
}

void ResetConsoleColor() {
    if (!g_ConsoleAttached) return;
    SafeWriteConsole(L"\x1b[0m");
}

void LogColor(const wchar_t* format, ...) {
    if (!g_ConsoleAttached) return;
    wchar_t buffer[2048];
    va_list args;
    va_start(args, format);
    vswprintf(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
    va_end(args);
    SafeWriteConsole(buffer);
}

std::wstring SafeReadConsole() {
    if (!g_ConsoleAttached) return L"";
    wchar_t buffer[512];
    DWORD charsRead;
    ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buffer, 512, &charsRead, NULL);
    if (charsRead >= 2 && buffer[charsRead - 2] == L'\r' && buffer[charsRead - 1] == L'\n') {
        return std::wstring(buffer, charsRead - 2);
    }
    return std::wstring(buffer, charsRead);
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
    SetConsoleColorRGB(COLOR_ENABLED_R, COLOR_ENABLED_G, COLOR_ENABLED_B);
    SafeWriteConsole(L"\n[权限提升] 正在尝试为当前进程启用所有可用特权...\n");
    ResetConsoleColor();
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
        if (EnablePrivilege(priv)) {
            SetConsoleColorRGB(COLOR_SUCCESS_R, COLOR_SUCCESS_G, COLOR_SUCCESS_B);
            LogColor(L"  -> 成功启用: %ws\n", priv);
        } else {
            SetConsoleColorRGB(COLOR_DISABLED_R, COLOR_DISABLED_G, COLOR_DISABLED_B);
            LogColor(L"  -> 警告: 无法启用 %ws\n", priv);
        }
        ResetConsoleColor();
    }
    SafeWriteConsole(L"----------------------------------------------------\n\n");
}

void PrintStatusLine(const std::wstring& label, const std::wstring& value, int successCount = -1, int failCount = -1) {
    SetConsoleColorRGB(COLOR_LABEL_R, COLOR_LABEL_G, COLOR_LABEL_B);
    std::wstring paddedLabel = label;
    for (size_t i = label.length(); i < 25; ++i) paddedLabel += L" ";
    SafeWriteConsole(paddedLabel + L": ");
    
    if (value == L"已禁用" || value == L"混合值") {
        SetConsoleColorRGB(COLOR_DISABLED_R, COLOR_DISABLED_G, COLOR_DISABLED_B);
    } else {
        SetConsoleColorRGB(COLOR_ENABLED_R, COLOR_ENABLED_G, COLOR_ENABLED_B);
    }
    SafeWriteConsole(value);

    if (successCount != -1 && failCount != -1 && (successCount + failCount > 1)) {
        ResetConsoleColor();
        SafeWriteConsole(L" | ");
        SetConsoleColorRGB(COLOR_SUCCESS_R, COLOR_SUCCESS_G, COLOR_SUCCESS_B);
        SafeWriteConsole(L"成功:" + std::to_wstring(successCount));
        ResetConsoleColor();
        SafeWriteConsole(L" | ");
        SetConsoleColorRGB(COLOR_DISABLED_R, COLOR_DISABLED_G, COLOR_DISABLED_B);
        SafeWriteConsole(L"失败:" + std::to_wstring(failCount));
    }
    
    ResetConsoleColor();
    SafeWriteConsole(L"\n");
}

std::wstring MaskToAffinityString(DWORD_PTR mask) {
    if (mask == 0) return L"已禁用";
    std::wstringstream wss;
    bool first = true;
    for (int i = 0; i < sizeof(DWORD_PTR) * 8; ++i) {
        if ((mask >> i) & 1) {
            int start = i;
            while (i + 1 < sizeof(DWORD_PTR) * 8 && ((mask >> (i + 1)) & 1)) {
                i++;
            }
            int end = i;

            if (!first) {
                wss << L" ";
            }
            if (start == end) {
                wss << start;
            } else {
                wss << start << L"-" << end;
            }
            first = false;
        }
    }
    return wss.str();
}

bool ParseAffinityString(std::wstring w_s, DWORD_PTR& mask) {
    std::replace(w_s.begin(), w_s.end(), L' ', L',');
    mask = 0;
    std::wstringstream wss(w_s);
    std::wstring segment;
    while (std::getline(wss, segment, L',')) {
        if (segment.empty()) continue;
        size_t dash_pos = segment.find(L'-');
        try {
            if (dash_pos == std::wstring::npos) {
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

void ClearAllJobSettings() {
    for (HANDLE hJob : g_hJobs) {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimit = {};
        SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basicLimit, sizeof(basicLimit));
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuLimit = {};
        SetInformationJobObject(hJob, JobObjectCpuRateControlInformation, &cpuLimit, sizeof(cpuLimit));
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netLimit = {};
        netLimit.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(0);
        SetInformationJobObject(hJob, JobObjectNetRateControlInformation, &netLimit, sizeof(netLimit));
    }
}

void CleanupAndExit() {
    if (!g_hJobs.empty()) {
        SetConsoleColorRGB(COLOR_ENABLED_R, COLOR_ENABLED_G, COLOR_ENABLED_B);
        SafeWriteConsole(L"\n正在退出... 限制将保持生效。\n");
        ResetConsoleColor();
        for (HANDLE hJob : g_hJobs) {
            CloseHandle(hJob);
        }
        g_hJobs.clear();
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
    JobController() {}

    static void ApplySettingsToAll(DWORD_PTR affinity, int priority, int scheduling, int weight, int dscp, int cpuLimit, int netLimit, const std::pair<size_t, size_t>& workingSet, int& successCount, int& failCount) {
        successCount = 0;
        failCount = 0;
        for (HANDLE hJob : g_hJobs) {
            if (ApplySettingsToSingle(hJob, affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet)) {
                successCount++;
            } else {
                failCount++;
            }
        }
    }

    // FIX: Rewritten to ALWAYS set all categories of limits, ensuring -1 correctly disables them.
    static bool ApplySettingsToSingle(HANDLE m_hJob, DWORD_PTR affinity, int priority, int scheduling, int weight, int dscp, int cpuLimit, int netLimit, const std::pair<size_t, size_t>& workingSet) {
        bool overallSuccess = true;

        // --- Basic Limits ---
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = {}; 
        if (affinity != 0) { basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY; basicInfo.Affinity = affinity; }
        if (priority != -1) { basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS; basicInfo.PriorityClass = priority; }
        if (scheduling != -1) { basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_SCHEDULING_CLASS; basicInfo.SchedulingClass = scheduling; }
        if (workingSet.first > 0 && workingSet.second > 0) {
            basicInfo.LimitFlags |= JOB_OBJECT_LIMIT_WORKINGSET;
            basicInfo.MinimumWorkingSetSize = workingSet.first * 1024 * 1024;
            basicInfo.MaximumWorkingSetSize = workingSet.second * 1024 * 1024;
        }
        if (!SetInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo))) {
            overallSuccess = false;
        }

        // --- CPU Limits ---
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = {};
        if (weight != -1) {
            cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED;
            cpuInfo.Weight = weight;
        } else if (cpuLimit != -1) {
            cpuInfo.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
            cpuInfo.CpuRate = cpuLimit * 100;
        }
        if (!SetInformationJobObject(m_hJob, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo))) {
            overallSuccess = false;
        }

        // --- Network Limits ---
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = {};
        netInfo.ControlFlags = static_cast<JOB_OBJECT_NET_RATE_CONTROL_FLAGS>(0);
        if (netLimit != -1) {
            netInfo.ControlFlags |= JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH;
            netInfo.MaxBandwidth = static_cast<DWORD64>(netLimit) * 1024;
        }
        if (dscp != -1) {
            netInfo.ControlFlags |= JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG;
            netInfo.DscpTag = (BYTE)dscp;
        }
        if (!SetInformationJobObject(m_hJob, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo))) {
            overallSuccess = false;
        }
        
        return overallSuccess;
    }

    static void DisplayAggregatedStatus() {
        if (g_hJobs.empty()) return;

        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(hConsole, &csbi);
        DWORD dwConSize = csbi.dwSize.X * csbi.dwSize.Y;
        COORD coord = {0, 0};
        DWORD dwCharsWritten;
        FillConsoleOutputCharacter(hConsole, (TCHAR)' ', dwConSize, coord, &dwCharsWritten);
        SetConsoleCursorPosition(hConsole, coord);

        SetConsoleColorRGB(COLOR_ENABLED_R, COLOR_ENABLED_G, COLOR_ENABLED_B);
        SafeWriteConsole(L"--- 进程控制器菜单 ---\n");
        ResetConsoleColor();
        
        SetConsoleColorRGB(COLOR_LABEL_R, COLOR_LABEL_G, COLOR_LABEL_B);
        std::wstring disableLabel = L"0. 禁用所有限制";
        for (size_t i = disableLabel.length(); i < 27; ++i) disableLabel += L" ";
        SafeWriteConsole(disableLabel + L"\n");
        ResetConsoleColor();

        std::map<std::wstring, int> counts;
        
        auto findMostCommon = [&](const std::map<std::wstring, int>& valueCounts) {
            std::pair<std::wstring, int> mostCommon = {L"已禁用", 0};
            if (valueCounts.empty()) return mostCommon;

            int maxCount = 0;
            for (const auto& pair : valueCounts) {
                if (pair.second > maxCount) {
                    maxCount = pair.second;
                    mostCommon = pair;
                }
            }
            
            if (valueCounts.size() > 1) {
                 mostCommon.first = L"混合值";
            }

            return mostCommon;
        };

        // 1. Affinity
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_BASIC_LIMIT_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectBasicLimitInformation, &info, sizeof(info), NULL);
            if (info.LimitFlags & JOB_OBJECT_LIMIT_AFFINITY) {
                counts[MaskToAffinityString(info.Affinity)]++;
            } else {
                counts[L"已禁用"]++;
            }
        }
        auto commonAffinity = findMostCommon(counts);
        PrintStatusLine(L"1. 亲和性 (Affinity)", commonAffinity.first, counts[commonAffinity.first], static_cast<int>(g_hJobs.size()) - counts[commonAffinity.first]);

        // 2. Priority
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_BASIC_LIMIT_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectBasicLimitInformation, &info, sizeof(info), NULL);
            if (info.LimitFlags & JOB_OBJECT_LIMIT_PRIORITY_CLASS) {
                std::wstring p_str;
                switch (info.PriorityClass) {
                    case IDLE_PRIORITY_CLASS: p_str = L"Idle"; break;
                    case BELOW_NORMAL_PRIORITY_CLASS: p_str = L"BelowNormal"; break;
                    case NORMAL_PRIORITY_CLASS: p_str = L"Normal"; break;
                    case ABOVE_NORMAL_PRIORITY_CLASS: p_str = L"AboveNormal"; break;
                    case HIGH_PRIORITY_CLASS: p_str = L"High"; break;
                    case REALTIME_PRIORITY_CLASS: p_str = L"RealTime"; break;
                    default: p_str = L"Unknown"; break;
                }
                counts[p_str]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonPriority = findMostCommon(counts);
        PrintStatusLine(L"2. 优先级 (Priority)", commonPriority.first, counts[commonPriority.first], static_cast<int>(g_hJobs.size()) - counts[commonPriority.first]);

        // 3. Scheduling
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_BASIC_LIMIT_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectBasicLimitInformation, &info, sizeof(info), NULL);
            if (info.LimitFlags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS) {
                counts[std::to_wstring(info.SchedulingClass)]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonScheduling = findMostCommon(counts);
        PrintStatusLine(L"3. 调度优先级 (Scheduling)", commonScheduling.first, counts[commonScheduling.first], static_cast<int>(g_hJobs.size()) - counts[commonScheduling.first]);

        // 4. Weight
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_CPU_RATE_CONTROL_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectCpuRateControlInformation, &info, sizeof(info), NULL);
            if ((info.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED) && (info.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) {
                counts[std::to_wstring(info.Weight)]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonWeight = findMostCommon(counts);
        PrintStatusLine(L"4. 时间片权重 (Weight)", commonWeight.first, counts[commonWeight.first], static_cast<int>(g_hJobs.size()) - counts[commonWeight.first]);

        // 5. DSCP
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_NET_RATE_CONTROL_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectNetRateControlInformation, &info, sizeof(info), NULL);
            if ((info.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG) && (info.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE)) {
                counts[std::to_wstring(info.DscpTag)]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonDscp = findMostCommon(counts);
        PrintStatusLine(L"5. 数据包优先级 (DSCP)", commonDscp.first, counts[commonDscp.first], static_cast<int>(g_hJobs.size()) - counts[commonDscp.first]);

        // 6. CpuLimit
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_CPU_RATE_CONTROL_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectCpuRateControlInformation, &info, sizeof(info), NULL);
            if ((info.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) && (info.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) {
                counts[std::to_wstring(info.CpuRate / 100) + L"%"]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonCpuLimit = findMostCommon(counts);
        PrintStatusLine(L"6. CPU使用率限制 (CpuLimit)", commonCpuLimit.first, counts[commonCpuLimit.first], static_cast<int>(g_hJobs.size()) - counts[commonCpuLimit.first]);

        // 7. NetLimit
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_NET_RATE_CONTROL_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectNetRateControlInformation, &info, sizeof(info), NULL);
            if ((info.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) && (info.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE)) {
                counts[std::to_wstring(info.MaxBandwidth / 1024) + L" KB/s"]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonNetLimit = findMostCommon(counts);
        PrintStatusLine(L"7. 传出带宽限制 (NetLimit)", commonNetLimit.first, counts[commonNetLimit.first], static_cast<int>(g_hJobs.size()) - counts[commonNetLimit.first]);

        // 8. WorkingSet
        counts.clear();
        for (HANDLE hJob : g_hJobs) {
            JOBOBJECT_BASIC_LIMIT_INFORMATION info = {};
            QueryInformationJobObject(hJob, JobObjectBasicLimitInformation, &info, sizeof(info), NULL);
            if (info.LimitFlags & JOB_OBJECT_LIMIT_WORKINGSET) {
                counts[std::to_wstring(info.MinimumWorkingSetSize / 1024 / 1024) + L"MB - " + std::to_wstring(info.MaximumWorkingSetSize / 1024 / 1024) + L"MB"]++;
            } else { counts[L"已禁用"]++; }
        }
        auto commonWorkingSet = findMostCommon(counts);
        PrintStatusLine(L"8. 物理内存限制 (WorkingSet)", commonWorkingSet.first, counts[commonWorkingSet.first], static_cast<int>(g_hJobs.size()) - counts[commonWorkingSet.first]);
        
        SafeWriteConsole(L"----------------------------------------------------\n");
    }
};

void DisplayHelp() {
    if (!g_ConsoleAttached) {
        if (AllocConsole()) {
            g_ConsoleAttached = true;
            HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
            DWORD dwMode = 0;
            GetConsoleMode(hOut, &dwMode);
            dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            SetConsoleMode(hOut, dwMode);
        }
    }
    
    SetConsoleColorRGB(COLOR_ENABLED_R, COLOR_ENABLED_G, COLOR_ENABLED_B);
    SafeWriteConsole(L"ProcessController - 命令行参数帮助\n\n");
    ResetConsoleColor();
    SafeWriteConsole(L"用法: ProcessController.exe [参数] [值] ...\n\n");
    
    auto print_param = [](const std::wstring& param, const std::wstring& desc) {
        SetConsoleColorRGB(COLOR_LABEL_R, COLOR_LABEL_G, COLOR_LABEL_B);
        std::wstring paddedParam = param;
        for (size_t i = param.length(); i < 15; ++i) paddedParam += L" ";
        SafeWriteConsole(paddedParam);
        ResetConsoleColor();
        SafeWriteConsole(L"| " + desc + L"\n");
    };

    print_param(L"-ProcessName", L"目标进程的名称 (例如: chrome.exe)");
    print_param(L"-ProcessId", L"目标进程的ID (例如: 1234)");
    print_param(L"-Affinity", L"设置CPU亲和性 (例如: \"0 1 2\" 或 \"4-7\")");
    print_param(L"-Priority", L"设置优先级 (Idle, BelowNormal, Normal, AboveNormal, High, RealTime)");
    print_param(L"-Scheduling", L"设置调度优先级 (0-9)");
    print_param(L"-Weight", L"设置时间片权重 (1-9), 与CpuLimit互斥");
    print_param(L"-DSCP", L"设置网络数据包优先级 (0-63)");
    print_param(L"-CpuLimit", L"设置CPU使用率上限 (1-100), 与Weight互斥");
    print_param(L"-NetLimit", L"设置传出带宽上限 (单位: KB/s)");
    print_param(L"-Working", L"设置物理内存限制 (格式: \"最小MB-最大MB\", 例如: \"10-100\")");
    
    SafeWriteConsole(L"\n示例:\n");
    SafeWriteConsole(L"  ProcessController.exe -ProcessName \"game.exe\" -Affinity \"4-7\" -Priority High\n");
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    bool isOneShotMode = wcslen(pCmdLine) > 0;

    g_ConsoleAttached = false;
    if (isOneShotMode) {
        if (AttachConsole(ATTACH_PARENT_PROCESS)) {
            g_ConsoleAttached = true;
        }
    } else {
        if (AllocConsole()) {
            g_ConsoleAttached = true;
        }
    }

    if (g_ConsoleAttached) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
    
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv) return 1;

    std::map<std::wstring, std::wstring> args;
    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"/?") {
            args[L"?"] = L"";
            continue;
        }
        if (arg.rfind(L'-', 0) == 0 && i + 1 < argc) {
            arg.erase(0, 1);
            std::transform(arg.begin(), arg.end(), arg.begin(), ::towlower);
            args[arg] = argv[++i];
        }
    }
    LocalFree(argv);

    if (args.count(L"?")) {
        DisplayHelp();
        return 0;
    }

    EnableAllPrivileges();

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        LogColor(L"错误: 无法设置 Ctrl+C 处理器。\n");
    }

    std::vector<DWORD> pids;
    if (isOneShotMode) {
        if (args.count(L"processname")) {
            pids = FindProcessByName(args[L"processname"]);
        } else if (args.count(L"processid")) {
            try { pids.push_back(std::stoi(args[L"processid"])); } catch(...) {}
        } else {
            LogColor(L"错误: 在一次性模式下, 必须提供 -ProcessName 或 -ProcessId 参数。\n");
            return 1;
        }
    } else {
        while (pids.empty()) {
            SafeWriteConsole(L"请输入目标进程名 (例如: chrome), 或留空以输入进程ID: ");
            std::wstring name_input = SafeReadConsole();
            if (!name_input.empty()) {
                pids = FindProcessByName(name_input);
            } else {
                SafeWriteConsole(L"请输入目标进程ID: ");
                std::wstring id_input = SafeReadConsole();
                try {
                    if(!id_input.empty()) pids.push_back(std::stoi(id_input));
                } catch(...) {}
            }
            if (pids.empty()) LogColor(L"未找到任何目标进程, 请重试。\n");
        }
    }

    if (pids.empty()) {
        LogColor(L"未找到任何目标进程, 脚本将退出。\n");
        return 1;
    }
    LogColor(L"已找到 %zu 个目标进程。\n", pids.size());
    
    LogColor(L"为每个进程创建唯一的作业对象并分配...\n");
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, pid);
        if (!hProcess) {
            LogColor(L"  -> 打开 PID %lu 失败 (错误码: %lu)\n", pid, GetLastError());
            continue;
        }

        wchar_t processName[MAX_PATH];
        if (GetModuleBaseNameW(hProcess, NULL, processName, MAX_PATH) == 0) {
            wcscpy_s(processName, L"UnknownProcess");
        }

        std::wstring jobName = L"Global\\ProcessControllerJob_" + std::wstring(processName) + L"_" + std::to_wstring(pid);
        
        HANDLE hJob = CreateJobObjectW(NULL, jobName.c_str());
        if (hJob) {
            if (AssignProcessToJobObject(hJob, hProcess)) {
                LogColor(L"  -> 成功将 PID %lu (%s) 分配到作业 '%s'\n", pid, processName, jobName.c_str());
                g_hJobs.push_back(hJob);
            } else {
                LogColor(L"  -> 分配 PID %lu 到作业失败 (错误码: %lu)\n", pid, GetLastError());
                CloseHandle(hJob);
            }
        } else {
            LogColor(L"  -> 创建作业 '%s' 失败 (错误码: %lu)\n", jobName.c_str(), GetLastError());
        }
        CloseHandle(hProcess);
    }

    if (g_hJobs.empty()) {
        LogColor(L"未能成功创建并分配任何作业对象, 脚本将退出。\n");
        return 1;
    }

    if (isOneShotMode) {
        LogColor(L"----------------------------------------------------\n");
        LogColor(L"正在应用一次性设置到 %zu 个作业对象...\n", g_hJobs.size());
        DWORD_PTR affinity = 0;
        int priority = -1, scheduling = -1, weight = -1, dscp = -1, cpuLimit = -1, netLimit = -1;
        std::pair<size_t, size_t> workingSet = {0, 0};

        if (args.count(L"affinity")) ParseAffinityString(args[L"affinity"], affinity);
        if (args.count(L"priority")) {
            std::wstring p = args[L"priority"];
            std::transform(p.begin(), p.end(), p.begin(), ::towlower);
            if (p == L"idle") priority = IDLE_PRIORITY_CLASS; else if (p == L"belownormal") priority = BELOW_NORMAL_PRIORITY_CLASS; else if (p == L"normal") priority = NORMAL_PRIORITY_CLASS; else if (p == L"abovenormal") priority = ABOVE_NORMAL_PRIORITY_CLASS; else if (p == L"high") priority = HIGH_PRIORITY_CLASS; else if (p == L"realtime") priority = REALTIME_PRIORITY_CLASS;
        }
        if (args.count(L"scheduling")) try { scheduling = std::stoi(args[L"scheduling"]); } catch(...) {}
        if (args.count(L"weight")) try { weight = std::stoi(args[L"weight"]); } catch(...) {}
        if (args.count(L"cpulimit")) try { cpuLimit = std::stoi(args[L"cpulimit"]); } catch(...) {}
        if (args.count(L"dscp")) try { dscp = std::stoi(args[L"dscp"]); } catch(...) {}
        if (args.count(L"netlimit")) try { netLimit = std::stoi(args[L"netlimit"]); } catch(...) {}
        if (args.count(L"working")) {
            std::wstring ws_str = args[L"working"];
            size_t dash_pos = ws_str.find(L'-');
            if (dash_pos != std::wstring::npos) { try { workingSet.first = std::stoul(ws_str.substr(0, dash_pos)); workingSet.second = std::stoul(ws_str.substr(dash_pos + 1)); } catch(...) {} }
        }
        
        int s, f;
        JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, s, f);
        
        LogColor(L"所有操作完成。脚本将退出，限制将持续有效。\n");
        CleanupAndExit();
        if (g_ConsoleAttached) { FreeConsole(); }
        exit(0);

    } else {
        DWORD_PTR affinity = 0;
        int priority = -1, scheduling = -1, weight = -1, dscp = -1, cpuLimit = -1, netLimit = -1;
        std::pair<size_t, size_t> workingSet = {0, 0};

        while (true) {
            JobController::DisplayAggregatedStatus();
            SafeWriteConsole(L"请选择要修改的功能 (0-8), 或输入 'exit' 退出: ");
            std::wstring choice = SafeReadConsole();
            
            if (choice == L"0") {
                ClearAllJobSettings();
                affinity = 0;
                priority = -1;
                scheduling = -1;
                weight = -1;
                dscp = -1;
                cpuLimit = -1;
                netLimit = -1;
                workingSet = {0, 0};
            } else if (choice == L"1") {
                SafeWriteConsole(L"新亲和性 (例: 8 10 12-15) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") affinity = 0; else ParseAffinityString(input, affinity);
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"2") {
                SafeWriteConsole(L"新优先级 (Idle, BelowNormal, Normal, AboveNormal, High, RealTime) 或 -1 禁用: ");
                std::wstring w_input = SafeReadConsole();
                std::transform(w_input.begin(), w_input.end(), w_input.begin(), ::towlower);
                if (w_input == L"-1") priority = -1; else if (w_input == L"idle") priority = IDLE_PRIORITY_CLASS; else if (w_input == L"belownormal") priority = BELOW_NORMAL_PRIORITY_CLASS; else if (w_input == L"normal") priority = NORMAL_PRIORITY_CLASS; else if (w_input == L"abovenormal") priority = ABOVE_NORMAL_PRIORITY_CLASS; else if (w_input == L"high") priority = HIGH_PRIORITY_CLASS; else if (w_input == L"realtime") priority = REALTIME_PRIORITY_CLASS;
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"3") {
                SafeWriteConsole(L"新调度优先级 (0-9) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") scheduling = -1; else try { scheduling = std::stoi(input); } catch(...) {}
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"4") {
                SafeWriteConsole(L"新时间片权重 (1-9) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") weight = -1; else try { weight = std::stoi(input); cpuLimit = -1; } catch(...) {}
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"5") {
                SafeWriteConsole(L"新数据包优先级 (0-63) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") dscp = -1; else try { dscp = std::stoi(input); } catch(...) {}
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"6") {
                SafeWriteConsole(L"新CPU使用率上限 (1-100) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") cpuLimit = -1; else try { cpuLimit = std::stoi(input); weight = -1; } catch(...) {}
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"7") {
                SafeWriteConsole(L"新传出带宽上限 (KB/s) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") netLimit = -1; else try { netLimit = std::stoi(input); } catch(...) {}
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"8") {
                SafeWriteConsole(L"新物理内存上限 (格式: 最小MB-最大MB) 或 -1 禁用: ");
                std::wstring input = SafeReadConsole();
                if (input == L"-1") { workingSet = {0, 0}; }
                else {
                    size_t dash_pos = input.find(L'-');
                    if (dash_pos != std::wstring::npos) { try { workingSet.first = std::stoul(input.substr(0, dash_pos)); workingSet.second = std::stoul(input.substr(dash_pos + 1)); } catch(...) {} }
                }
                JobController::ApplySettingsToAll(affinity, priority, scheduling, weight, dscp, cpuLimit, netLimit, workingSet, *(new int), *(new int));
            } else if (choice == L"exit") {
                break;
            } else {
                SafeWriteConsole(L"无效的选择, 请按回车键重试...");
                SafeReadConsole();
            }
        }
        CleanupAndExit();
    }

    if (g_ConsoleAttached) {
        FreeConsole();
    }

    return 0;
}