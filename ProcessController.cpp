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
    for (int i = 0; i < sizeof(DWORD_PTR) * 