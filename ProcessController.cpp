// ProcessController.cpp
// 编译命令 (在 Visual Studio 命令行工具中):
// cl.exe /EHsc /O2 /W3 /Fe:ProcessController.exe ProcessController.cpp kernel32.lib user32.lib psapi.lib /link /SUBSYSTEM:CONSOLE

#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <tchar.h>
#include <psapi.h>
#include <map>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <cstdarg> // 用于可变参数

// --- 确保旧版 SDK 也能编译，手动定义缺失的结构体和枚举 ---

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

// --- 全局变量 ---
HANDLE g_hJob = NULL; // 全局 Job Object 句柄，用于清理

// --- 权限提升与日志 ---
#define COLOR_INFO 15 // 亮白色
#define COLOR_SUCCESS 10 // 亮绿色
#define COLOR_WARNING 14 // 亮黄色

// 彩色日志函数
void LogColor(int color, const wchar_t* format, ...) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);

    wchar_t buffer[1024];
    va_list args;
    va_start(args, format);
    vswprintf(buffer, sizeof(buffer) / sizeof(wchar_t), format, args);
    va_end(args);

    wprintf(L"%s", buffer);

    // 重置为默认颜色 (白)
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

// 启用单个权限
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

// 启用所有常用权限
void EnableAllPrivileges()
{
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

    for (const auto& priv : privileges)
    {
        if (EnablePrivilege(priv))
        {
            LogColor(COLOR_SUCCESS, L"  -> 成功启用: %ws\n", priv);
        }
        else
        {
            LogColor(COLOR_WARNING, L"  -> 警告: 无法启用 %ws\n", priv);
        }
    }
    std::wcout << L"----------------------------------------------------\n" << std::endl;
}


// --- 辅助函数 ---

// 打印带颜色的状态行
void PrintStatusLine(const std::string& label, const std::string& value) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    std::cout << label;
    // 填充空格
    for (size_t i = label.length(); i < 35; ++i) {
        std::cout << " ";
    }
    std::cout << ": ";

    if (value == "已禁用") {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
    } else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
    }
    std::cout << value << std::endl;
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); // 重置颜色
}

// 解析亲和性字符串 (例如 "8,10,12-15")
bool ParseAffinityString(const std::string& s, DWORD_PTR& mask) {
    mask = 0;
    std::stringstream ss(s);
    std::string segment;
    while (std::getline(ss, segment, ',')) {
        size_t dash_pos = segment.find('-');
        try {
            if (dash_pos == std::string::npos) {
                int cpu = std::stoi(segment);
                if (cpu >= 0 && cpu < sizeof(DWORD_PTR) * 8) {
                    mask |= (1ULL << cpu);
                }
            } else {
                int start_cpu = std::stoi(segment.substr(0, dash_pos));
                int end_cpu = std::stoi(segment.substr(dash_pos + 1));
                for (int i = start_cpu; i <= end_cpu; ++i) {
                    if (i >= 0 && i < sizeof(DWORD_PTR) * 8) {
                        mask |= (1ULL << i);
                    }
                }
            }
        } catch (...) {
            return false; // 解析失败
        }
    }
    return true;
}

// 通过进程名查找进程
std::vector<DWORD> FindProcessByName(const std::wstring& processName) {
    std::vector<DWORD> pids;
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return pids;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (NULL != hProcess) {
                HMODULE hMod;
                DWORD cbNeeded2;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded2)) {
                    GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
                    if (processName == szProcessName) {
                        pids.push_back(aProcesses[i]);
                    }
                }
            }
            CloseHandle(hProcess);
        }
    }
    return pids;
}

// 清理函数，移除所有限制
void CleanupAndExit() {
    if (g_hJob != NULL && g_hJob != INVALID_HANDLE_VALUE) {
        std::cout << "\n正在退出... 自动移除所有限制..." << std::endl;

        // 清空基础限制
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimit = { 0 };
        basicLimit.LimitFlags = 0;
        SetInformationJobObject(g_hJob, JobObjectBasicLimitInformation, &basicLimit, sizeof(basicLimit));

        // 清空CPU限制
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuLimit = { 0 };
        cpuLimit.ControlFlags = 0; // 禁用
        SetInformationJobObject(g_hJob, JobObjectCpuRateControlInformation, &cpuLimit, sizeof(cpuLimit));

        // 清空网络限制
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netLimit = { 0 };
        netLimit.ControlFlags = 0; // 禁用
        SetInformationJobObject(g_hJob, JobObjectNetRateControlInformation, &netLimit, sizeof(netLimit));

        CloseHandle(g_hJob);
        g_hJob = NULL;
        std::cout << "解锁成功！控制器已终止。" << std::endl;
    }
}

// Ctrl+C 事件处理
BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        CleanupAndExit();
        exit(0);
        return TRUE;
    default:
        return FALSE;
    }
}

// --- 主逻辑类 ---
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
        std::cout << "--- 进程控制器菜单 ---" << std::endl;

        JOBOBJECT_BASIC_LIMIT_INFORMATION basicInfo = { 0 };
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuInfo = { 0 };
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netInfo = { 0 };

        QueryInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicInfo, sizeof(basicInfo), NULL);
        QueryInformationJobObject(m_hJob, JobObjectCpuRateControlInformation, &cpuInfo, sizeof(cpuInfo), NULL);
        QueryInformationJobObject(m_hJob, JobObjectNetRateControlInformation, &netInfo, sizeof(netInfo), NULL);

        // 1. 亲和性
        std::string affinity_str = "已禁用";
        if (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_AFFINITY) {
            std::stringstream ss;
            ss << "0x" << std::hex << basicInfo.Affinity;
            affinity_str = ss.str();
        }
        PrintStatusLine("1. 亲和性 (Affinity)", affinity_str);

        // 2. 优先级
        std::string priority_str = "已禁用";
        if (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_PRIORITY_CLASS) {
            switch (basicInfo.PriorityClass) {
                case IDLE_PRIORITY_CLASS: priority_str = "Idle"; break;
                case BELOW_NORMAL_PRIORITY_CLASS: priority_str = "BelowNormal"; break;
                case NORMAL_PRIORITY_CLASS: priority_str = "Normal"; break;
                case ABOVE_NORMAL_PRIORITY_CLASS: priority_str = "AboveNormal"; break;
                case HIGH_PRIORITY_CLASS: priority_str = "High"; break;
                case REALTIME_PRIORITY_CLASS: priority_str = "RealTime"; break;
            }
        }
        PrintStatusLine("2. 优先级 (Priority)", priority_str);

        // 3. 调度优先级
        std::string scheduling_str = "已禁用";
        if (basicInfo.LimitFlags & JOB_OBJECT_LIMIT_SCHEDULING_CLASS) {
            scheduling_str = std::to_string(basicInfo.SchedulingClass);
        }
        PrintStatusLine("3. 调度优先级 (Scheduling)", scheduling_str);

        // 4. 时间片权重
        std::string weight_str = "已禁用";
        if ((cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED) && (cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) {
            weight_str = std::to_string(cpuInfo.Weight);
        }
        PrintStatusLine("4. 时间片权重 (Weight)", weight_str);

        // 5. 数据包优先级
        std::string dscp_str = "已禁用";
        if ((netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG) && (netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE)) {
            dscp_str = std::to_string(netInfo.DscpTag);
        }
        PrintStatusLine("5. 数据包优先级 (DSCP)", dscp_str);

        // 6. CPU使用率限制
        std::string cpulimit_str = "已禁用";
        if ((cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) && (cpuInfo.ControlFlags & JOB_OBJECT_CPU_RATE_CONTROL_ENABLE)) {
            cpulimit_str = std::to_string(cpuInfo.CpuRate / 100) + "%";
        }
        PrintStatusLine("6. CPU使用率限制 (CpuLimit)", cpulimit_str);

        // 7. 传出带宽限制
        std::string netlimit_str = "已禁用";
        if ((netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) && (netInfo.ControlFlags & JOB_OBJECT_NET_RATE_CONTROL_ENABLE)) {
            netlimit_str = std::to_string(netInfo.MaxBandwidth / 1024) + " KB/s";
        }
        PrintStatusLine("7. 传出带宽限制 (NetLimit)", netlimit_str);
        
        std::cout << "----------------------------------------------------" << std::endl;
    }

    // 公共设置变量
    DWORD_PTR affinity = 0;
    int priority = -1;
    int scheduling = -1;
    int weight = -1;
    int dscp = -1;
    int cpuLimit = -1;
    int netLimit = -1;

private:
    HANDLE m_hJob;

    bool UpdateBasicLimits() {
        JOBOBJECT_BASIC_LIMIT_INFORMATION basicLimit = { 0 };
        basicLimit.LimitFlags = 0;

        if (affinity != 0) {
            basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_AFFINITY;
            basicLimit.Affinity = affinity;
        }
        if (priority != -1) {
            basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_PRIORITY_CLASS;
            basicLimit.PriorityClass = priority;
        }
        if (scheduling != -1) {
            basicLimit.LimitFlags |= JOB_OBJECT_LIMIT_SCHEDULING_CLASS;
            basicLimit.SchedulingClass = scheduling;
        }

        return SetInformationJobObject(m_hJob, JobObjectBasicLimitInformation, &basicLimit, sizeof(basicLimit));
    }

    bool UpdateCpuLimits() {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpuLimitInfo = { 0 };
        
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
        JOBOBJECT_NET_RATE_CONTROL_INFORMATION netLimitInfo = { 0 };
        netLimitInfo.ControlFlags = 0;

        if (netLimit != -1) {
            netLimitInfo.ControlFlags |= JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH;
            netLimitInfo.MaxBandwidth = (DWORD64)netLimit * 1024;
        }
        if (dscp != -1) {
            netLimitInfo.ControlFlags |= JOB_OBJECT_NET_RATE_CONTROL_ENABLE | JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG;
            netLimitInfo.DscpTag = (BYTE)dscp;
        }

        return SetInformationJobObject(m_hJob, JobObjectNetRateControlInformation, &netLimitInfo, sizeof(netLimitInfo));
    }
};


// --- 主函数 ---
int main(int argc, char* argv[]) {
    // **步骤 1: 在程序启动时立即提升权限**
    EnableAllPrivileges();

    std::map<std::string, std::string> args;
    bool isOneShotMode = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.rfind('-', 0) == 0 && i + 1 < argc) {
            isOneShotMode = true;
            // 移除前导 '-'
            arg.erase(0, 1); 
            // 转为小写以方便比较
            std::transform(arg.begin(), arg.end(), arg.begin(), [](unsigned char c){ return std::tolower(c); });
            args[arg] = argv[++i];
        }
    }

    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::cerr << "错误: 无法设置 Ctrl+C 处理器。" << std::endl;
        return 1;
    }

    std::vector<DWORD> pids;
    std::string processIdentifier;

    if (isOneShotMode) {
        if (args.count("processname")) {
            processIdentifier = args["processname"];
            std::wstring wProcessName(processIdentifier.begin(), processIdentifier.end());
            pids = FindProcessByName(wProcessName);
        } else if (args.count("processid")) {
            processIdentifier = args["processid"];
            try {
                pids.push_back(std::stoi(processIdentifier));
            } catch(...) { /* 无效ID */ }
        } else {
            std::cerr << "错误: 在一次性模式下, 必须提供 -ProcessName 或 -ProcessId 参数。" << std::endl;
            return 1;
        }
    } else {
        while (pids.empty()) {
            std::cout << "请输入目标进程名 (例如: chrome.exe), 或留空以输入进程ID: ";
            std::string name_input;
            std::getline(std::cin, name_input);
            if (!name_input.empty()) {
                processIdentifier = name_input;
                std::wstring wProcessName(name_input.begin(), name_input.end());
                pids = FindProcessByName(wProcessName);
            } else {
                std::cout << "请输入目标进程ID: ";
                std::string id_input;
                std::getline(std::cin, id_input);
                try {
                    processIdentifier = id_input;
                    pids.push_back(std::stoi(id_input));
                } catch(...) { /* 无效ID */ }
            }
            if (pids.empty()) {
                std::cerr << "未找到任何目标进程, 请重试。" << std::endl;
            }
        }
    }

    if (pids.empty()) {
        std::cerr << "未找到任何目标进程, 脚本将退出。" << std::endl;
        return 1;
    }

    std::cout << "已找到 " << pids.size() << " 个目标进程:" << std::endl;
    for (DWORD pid : pids) {
        std::cout << "  - PID: " << pid << std::endl;
    }

    std::wstring jobName = L"Global\\ProcessControllerJob_" + std::wstring(processIdentifier.begin(), processIdentifier.end());
    g_hJob = CreateJobObjectW(NULL, jobName.c_str());

    if (g_hJob == NULL) {
        std::cerr << "CreateJobObjectW 失败！错误码: " << GetLastError() << std::endl;
        return 1;
    }
    std::wcout << L"Job Object '" << jobName << L"' 已创建/打开。" << std::endl;

    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            if (!AssignProcessToJobObject(g_hJob, hProcess)) {
                std::cerr << "将 PID " << pid << " 分配到 Job Object 失败！错误码: " << GetLastError() << std::endl;
            }
            CloseHandle(hProcess);
        } else {
             std::cerr << "打开 PID " << pid << " 失败！错误码: " << GetLastError() << std::endl;
        }
    }
    std::cout << "已将所有目标进程分配到 Job Object。" << std::endl;

    JobController controller(g_hJob);

    if (isOneShotMode) {
        std::cout << "----------------------------------------------------" << std::endl;
        std::cout << "正在应用一次性设置..." << std::endl;
        if (args.count("affinity")) {
            DWORD_PTR mask;
            if (ParseAffinityString(args["affinity"], mask)) controller.affinity = mask;
        }
        if (args.count("priority")) {
            std::string p = args["priority"];
            std::transform(p.begin(), p.end(), p.begin(), ::tolower);
            if (p == "idle") controller.priority = IDLE_PRIORITY_CLASS;
            else if (p == "belownormal") controller.priority = BELOW_NORMAL_PRIORITY_CLASS;
            else if (p == "normal") controller.priority = NORMAL_PRIORITY_CLASS;
            else if (p == "abovenormal") controller.priority = ABOVE_NORMAL_PRIORITY_CLASS;
            else if (p == "high") controller.priority = HIGH_PRIORITY_CLASS;
            else if (p == "realtime") controller.priority = REALTIME_PRIORITY_CLASS;
        }
        if (args.count("scheduling")) controller.scheduling = std::stoi(args["scheduling"]);
        if (args.count("weight")) controller.weight = std::stoi(args["weight"]);
        if (args.count("cpulimit")) controller.cpuLimit = std::stoi(args["cpulimit"]);
        if (args.count("dscp")) controller.dscp = std::stoi(args["dscp"]);
        if (args.count("netlimit")) controller.netLimit = std::stoi(args["netlimit"]);
        
        if (controller.ApplySettings()) {
            std::cout << "设置已成功应用。脚本将退出，限制将持续有效。" << std::endl;
        } else {
            std::cerr << "应用设置失败！错误码: " << GetLastError() << std::endl;
        }
        // 在一次性模式下，不调用清理函数，让限制保留
        CloseHandle(g_hJob);
        g_hJob = NULL;

    } else { // 交互模式
        while (true) {
            controller.DisplayStatus();
            std::cout << "请选择要修改的功能 (1-7), 或输入 'exit' 自动解锁并退出: ";
            std::string choice;
            std::getline(std::cin, choice);

            if (choice == "1") {
                std::cout << "新亲和性 (例: 8,10,12-15) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                if (input == "-1") controller.affinity = 0;
                else ParseAffinityString(input, controller.affinity);
            } else if (choice == "2") {
                std::cout << "新优先级 (Idle, BelowNormal, Normal, AboveNormal, High, RealTime) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                std::transform(input.begin(), input.end(), input.begin(), ::tolower);
                if (input == "-1") controller.priority = -1;
                else if (input == "idle") controller.priority = IDLE_PRIORITY_CLASS;
                else if (input == "belownormal") controller.priority = BELOW_NORMAL_PRIORITY_CLASS;
                else if (input == "normal") controller.priority = NORMAL_PRIORITY_CLASS;
                else if (input == "abovenormal") controller.priority = ABOVE_NORMAL_PRIORITY_CLASS;
                else if (input == "high") controller.priority = HIGH_PRIORITY_CLASS;
                else if (input == "realtime") controller.priority = REALTIME_PRIORITY_CLASS;
            } else if (choice == "3") {
                std::cout << "新调度优先级 (0-9) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                if (input == "-1") controller.scheduling = -1; else controller.scheduling = std::stoi(input);
            } else if (choice == "4") {
                std::cout << "新时间片权重 (1-9) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                if (input == "-1") controller.weight = -1;
                else { controller.weight = std::stoi(input); controller.cpuLimit = -1; } // 权重和硬上限互斥
            } else if (choice == "5") {
                std::cout << "新数据包优先级 (0-63) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                if (input == "-1") controller.dscp = -1; else controller.dscp = std::stoi(input);
            } else if (choice == "6") {
                std::cout << "新CPU使用率上限 (1-100) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                if (input == "-1") controller.cpuLimit = -1;
                else { controller.cpuLimit = std::stoi(input); controller.weight = -1; } // 权重和硬上限互斥
            } else if (choice == "7") {
                std::cout << "新传出带宽上限 (KB/s) 或 -1 禁用: ";
                std::string input; std::getline(std::cin, input);
                if (input == "-1") controller.netLimit = -1; else controller.netLimit = std::stoi(input);
            } else if (choice == "exit") {
                break;
            } else {
                std::cout << "无效的选择, 请按回车键重试...";
                std::cin.get();
            }
            controller.ApplySettings();
        }
        CleanupAndExit();
    }

    return 0;
}