# =========================================================================
#  JobObjectCheck.ps1
#
#  功能:
#  - 使用与主控制器完全相同的逻辑来定位并打开 Job Object
#  - 同时检查并报告亲和性、优先级、调度优先级、时间片权重、
#    CPU使用率限制、传出带宽限制、数据包优先级的状态
#
#  警告：必须以管理员身份运行！
# =========================================================================

# 步骤 1: 定义所有需要的 Win32 API 签名
try {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public static class NativeMethods {
        // --- Job Object API ---
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenJobObjectW(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

        // 为 QueryInformationJobObject 创建不同的入口点
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectBasic(IntPtr hJob, JOBOBJECT_INFO_CLASS i, out JOBOBJECT_BASIC_LIMIT_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectCpuRate(IntPtr hJob, JOBOBJECT_INFO_CLASS i, out JOBOBJECT_CPU_RATE_CONTROL_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectNetRate(IntPtr hJob, JOBOBJECT_INFO_CLASS i, out JOBOBJECT_NET_RATE_CONTROL_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        // --- 枚举定义 ---
        public enum JOBOBJECT_INFO_CLASS {
            JobObjectBasicLimitInformation = 2,
            JobObjectCpuRateControlInformation = 15,
            JobObjectNetRateControlInformation = 32
        }

        [Flags]
        public enum JOB_OBJECT_LIMIT_FLAGS : uint {
            JOB_OBJECT_LIMIT_WORKINGSET          = 0x00000001,
            JOB_OBJECT_LIMIT_AFFINITY              = 0x00000010,
            JOB_OBJECT_LIMIT_PRIORITY_CLASS      = 0x00000020,
            JOB_OBJECT_LIMIT_SCHEDULING_CLASS    = 0x00000080,
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE     = 0x1,
            JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED = 0x2,
            JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP   = 0x4,
            JOB_OBJECT_NET_RATE_CONTROL_ENABLE     = 0x1,
            JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH = 0x2,
            JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG   = 0x4
        }

        public enum PROCESS_PRIORITY_CLASS : uint {
            Idle        = 0x40,
            BelowNormal = 0x4000,
            Normal      = 0x20,
            AboveNormal = 0x8000,
            High        = 0x80,
            RealTime    = 0x100
        }

        // --- 结构体定义 ---
        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            public long p1,p2;
            public JOB_OBJECT_LIMIT_FLAGS LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint a;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
            [FieldOffset(0)] public JOB_OBJECT_LIMIT_FLAGS ControlFlags;
            [FieldOffset(4)] public uint CpuRate;
            [FieldOffset(4)] public uint Weight;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOBJECT_NET_RATE_CONTROL_INFORMATION {
            public ulong MaxBandwidth;
            public JOB_OBJECT_LIMIT_FLAGS ControlFlags;
            public byte DscpTag;
        }

        // --- 常量定义 ---
        public const uint JOB_OBJECT_QUERY = 0x0004;
    }
"@ -PassThru -ErrorAction Stop | Out-Null
} catch {
    Write-Host "C# 编译失败: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# --- 步骤 2: 辅助函数 ---

function Write-StatusLine {
    param($Label, $Value)
    $labelPadded = $Label.PadRight(30)
    if ($Value -eq "已禁用") {
        Write-Host "${labelPadded}: " -NoNewline
        Write-Host $Value -ForegroundColor Red
    } else {
        Write-Host "${labelPadded}: " -NoNewline
        Write-Host $Value -ForegroundColor Green
    }
}

# --- 步骤 3: 主逻辑 ---

# 使用与主控制器完全相同的逻辑来定位目标和构造名称
$jobObjectName = ""
$processNameInput = Read-Host -Prompt "请输入目标进程名 (不包含.exe), 或留空以输入进程ID"

if (-not [string]::IsNullOrWhiteSpace($processNameInput)) {
    $jobObjectName = "Global\ProcessControllerJob_$($processNameInput).exe_$($processId)"
} else {
    $processIdInput = Read-Host -Prompt "请输入目标进程ID"
    if (-not [string]::IsNullOrWhiteSpace($processIdInput)) {
        try {
            $processId = [int]$processIdInput
            $jobObjectName = "Global\ProcessControllerJob_Enable.exe_$($processId)"
        } catch {
            Write-Warning "无效的进程ID"
        }
    }
}

if ([string]::IsNullOrWhiteSpace($jobObjectName)) {
    Write-Host "未提供有效的目标信息脚本将退出" -ForegroundColor Yellow
    return
}

Write-Host "正在尝试打开并查询 Job Object: '$jobObjectName'..." -ForegroundColor Cyan
$jobHandle = [IntPtr]::Zero
try {
    $jobHandle = [NativeMethods]::OpenJobObjectW([NativeMethods]::JOB_OBJECT_QUERY, $false, $jobObjectName)
    if ($jobHandle -eq [IntPtr]::Zero) {
        Write-Host "OpenJobObjectW 失败！" -ForegroundColor Red
        Write-Host "请确认:" -ForegroundColor Yellow
        Write-Host "  1. 主控制器脚本正在运行" -ForegroundColor Yellow
        Write-Host "  2. 您在此处输入的进程名或ID与启动主控制器时使用的完全一致" -ForegroundColor Yellow
        return
    }
    Write-Host "成功打开 Job Object正在进行全面诊断查询..." -F Green
    
    # --- 初始化状态 ---
    $status = @{ Affinity = "已禁用"; Priority = "已禁用"; Scheduling = "已禁用"; Weight = "已禁用"; CpuLimit = "已禁用"; WorkingSet = "已禁用"; NetLimit = "已禁用"; DSCP = "已禁用" }

    # --- 查询 1: 基础限制 ---
    $basicInfo = New-Object NativeMethods+JOBOBJECT_BASIC_LIMIT_INFORMATION
    if ([NativeMethods]::QueryInformationJobObjectBasic($jobHandle, [NativeMethods+JOBOBJECT_INFO_CLASS]::JobObjectBasicLimitInformation, [ref]$basicInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($basicInfo), [ref]0)) {
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_AFFINITY) -ne 0) { $status.Affinity = "0x$($basicInfo.Affinity.ToUInt64().ToString('X'))" }
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_PRIORITY_CLASS) -ne 0) { $status.Priority = ([NativeMethods+PROCESS_PRIORITY_CLASS]$basicInfo.PriorityClass).ToString() }
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_SCHEDULING_CLASS) -ne 0) { $status.Scheduling = $basicInfo.SchedulingClass }
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_WORKINGSET) -ne 0) { $status.WorkingSet = "$($basicInfo.MinimumWorkingSetSize.ToUInt64()/1MB)MB - $($basicInfo.MaximumWorkingSetSize.ToUInt64()/1MB)MB" }
    }

    # --- 查询 2: CPU 速率限制 ---
    $cpuInfo = New-Object NativeMethods+JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    if ([NativeMethods]::QueryInformationJobObjectCpuRate($jobHandle, [NativeMethods+JOBOBJECT_INFO_CLASS]::JobObjectCpuRateControlInformation, [ref]$cpuInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($cpuInfo), [ref]0)) {
        if (($cpuInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED) -ne 0) { $status.Weight = $cpuInfo.Weight }
        if (($cpuInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) -ne 0) { $status.CpuLimit = "$($cpuInfo.CpuRate / 100)%" }
    }

    # --- 查询 3: 网络限制 ---
    $netInfo = New-Object NativeMethods+JOBOBJECT_NET_RATE_CONTROL_INFORMATION
    if ([NativeMethods]::QueryInformationJobObjectNetRate($jobHandle, [NativeMethods+JOBOBJECT_INFO_CLASS]::JobObjectNetRateControlInformation, [ref]$netInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($netInfo), [ref]0)) {
        if (($netInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) -ne 0) { $status.NetLimit = "$($netInfo.MaxBandwidth / 1KB) KB/s" }
        if (($netInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG) -ne 0) { $status.DSCP = $netInfo.DscpTag }
    }

    # --- 显示最终报告 ---
    Write-Host "`n--- Job Object 状态报告 ---" -ForegroundColor Yellow
    Write-StatusLine -Label "1. 亲和性 (Affinity)" -Value $status.Affinity
    Write-StatusLine -Label "2. 优先级 (Priority)" -Value $status.Priority
    Write-StatusLine -Label "3. 调度优先级 (Scheduling)" -Value $status.Scheduling
    Write-StatusLine -Label "4. 时间片权重 (Weight)" -Value $status.Weight
    Write-StatusLine -Label "5. 数据包优先级 (DSCP)" -Value $status.DSCP
    Write-StatusLine -Label "6. CPU使用率限制 (CpuLimit)" -Value $status.CpuLimit
    Write-StatusLine -Label "7. 传出带宽限制 (NetLimit)" -Value $status.NetLimit
    Write-StatusLine -Label "8. 物理内存限制 (WorkingSet)" -Value $status.WorkingSet
    Write-Host "---------------------------------"
}
finally {
    if ($jobHandle -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($jobHandle) }
}