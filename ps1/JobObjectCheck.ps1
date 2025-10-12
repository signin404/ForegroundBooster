# ------------------------------------------------------------------------------------
# ProcessController - 作业对象状态实时监控脚本 (v4 - 修复C#编译错误)
# ------------------------------------------------------------------------------------

# --- 步骤 1: 定义与 Windows API 交互所需的 C# 代码 ---
try {
    # [修复] 将所有类型定义（常量、枚举、结构体）移动到函数声明之前
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public static class NativeMethods {
        // --- 1. 常量定义 ---
        public const uint JOB_OBJECT_QUERY = 0x0004;

        // --- 2. 枚举定义 ---
        public enum JOBOJECT_INFO_CLASS {
            JobObjectBasicLimitInformation = 2,
            JobObjectCpuRateControlInformation = 15,
            JobObjectNetRateControlInformation = 32
        }

        [Flags]
        public enum JOB_OBJECT_LIMIT_FLAGS : uint {
            JOB_OBJECT_LIMIT_WORKINGSET          = 0x00000001,
            JOB_OBJECT_LIMIT_AFFINITY              = 0x00000010,
            JOB_OBJECT_LIMIT_PRIORITY_CLASS      = 0x00000020,
            JOB_OBJECT_LIMIT_SCHEDULING_CLASS    = 0x00000080
        }

        [Flags]
        public enum JOB_OBJECT_CPU_RATE_CONTROL_FLAGS : uint {
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE     = 0x1,
            JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED = 0x2,
            JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP   = 0x4
        }
        
        [Flags]
        public enum JOB_OBJECT_NET_RATE_CONTROL_FLAGS : uint {
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

        // --- 3. 结构体定义 ---
        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOJECT_BASIC_LIMIT_INFORMATION {
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
        public struct JOBOJECT_CPU_RATE_CONTROL_INFORMATION {
            [FieldOffset(0)] public JOB_OBJECT_CPU_RATE_CONTROL_FLAGS ControlFlags;
            [FieldOffset(4)] public uint CpuRate;
            [FieldOffset(4)] public uint Weight;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct JOBOJECT_NET_RATE_CONTROL_INFORMATION {
            public ulong MaxBandwidth;
            public JOB_OBJECT_NET_RATE_CONTROL_FLAGS ControlFlags;
            public byte DscpTag;
        }

        // --- 4. Job Object API 函数声明 ---
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenJobObjectW(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectBasic(IntPtr hJob, JOBOJECT_INFO_CLASS i, out JOBOJECT_BASIC_LIMIT_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectCpuRate(IntPtr hJob, JOBOJECT_INFO_CLASS i, out JOBOJECT_CPU_RATE_CONTROL_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectNetRate(IntPtr hJob, JOBOJECT_INFO_CLASS i, out JOBOJECT_NET_RATE_CONTROL_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);
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

function Convert-AffinityMaskToString {
    param([UInt64]$Mask)
    if ($Mask -eq 0) { return "已禁用" }
    
    $cores = @()
    for ($i = 0; $i -lt 64; $i++) {
        if ((($Mask -shr $i) -band 1) -eq 1) {
            $cores += $i
        }
    }

    if ($cores.Count -eq 0) { return "已禁用" }

    $result = @()
    $i = 0
    while ($i -lt $cores.Count) {
        $start = $cores[$i]
        $end = $start
        while (($i + 1 -lt $cores.Count) -and ($cores[$i+1] -eq $cores[$i] + 1)) {
            $end = $cores[$i+1]
            $i++
        }
        if ($start -eq $end) {
            $result += "$start"
        } else {
            $result += "$start-$end"
        }
        $i++
    }
    return $result -join " "
}


# --- 步骤 3: 查找目标进程并构建作业对象名称 ---

$targetProcess = $null
while ($targetProcess -eq $null) {
    $input = Read-Host "请输入目标进程名称或ID"
    if ($input -match "^\d+$") { # 检查输入是否为纯数字 (ID)
        $targetProcess = Get-Process -Id $input -ErrorAction SilentlyContinue
        if ($targetProcess -eq $null) { Write-Warning "未找到 ID 为 $input 的进程" }
    } else { # 否则 按名称查找
        $processNameToSearch = $input
        if ($processNameToSearch.EndsWith(".exe", [System.StringComparison]::InvariantCultureIgnoreCase)) {
            $processNameToSearch = $processNameToSearch.Substring(0, $processNameToSearch.Length - 4)
        }
        
        $targetProcess = Get-Process -Name $processNameToSearch -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($targetProcess -eq $null) { Write-Warning "未找到名为 '$input' 的进程" }
    }
}

$jobObjectName = "Global\ProcessControllerJob_$($targetProcess.MainModule.ModuleName)_$($targetProcess.Id)"

# --- 步骤 4: 主监控循环 ---

while ($true) {
    try {
        Get-Process -Id $targetProcess.Id -ErrorAction Stop | Out-Null
    } catch {
        Clear-Host
        Write-Host "目标进程 $($targetProcess.Name) (PID: $($targetProcess.Id)) 已退出监控脚本将停止" -ForegroundColor Yellow
        break
    }

    Clear-Host
    Write-Host "--- 正在监控 进程: $($targetProcess.Name) (PID: $($targetProcess.Id)) ---" -ForegroundColor Cyan
    Write-Host "--- 作业对象: $jobObjectName ---" -ForegroundColor Cyan
    Write-Host "--- (每秒刷新, 按 Ctrl+C 停止) ---`n"

    $jobHandle = [IntPtr]::Zero
    try {
        $jobHandle = [NativeMethods]::OpenJobObjectW([NativeMethods]::JOB_OBJECT_QUERY, $false, $jobObjectName)
        
        if ($jobHandle -eq [IntPtr]::Zero) {
            Write-Host "无法打开作业对象" -ForegroundColor Red
            Write-Host "请确保 ProcessController.exe 已对该进程成功应用过设置" -ForegroundColor Yellow
        } else {
            $status = @{ Affinity = "已禁用"; Priority = "已禁用"; Scheduling = "已禁用"; Weight = "已禁用"; CpuLimit = "已禁用"; WorkingSet = "已禁用"; NetLimit = "已禁用"; DSCP = "已禁用" }

            $basicInfo = New-Object NativeMethods+JOBOJECT_BASIC_LIMIT_INFORMATION
            if ([NativeMethods]::QueryInformationJobObjectBasic($jobHandle, [NativeMethods+JOBOJECT_INFO_CLASS]::JobObjectBasicLimitInformation, [ref]$basicInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($basicInfo), [ref]0)) {
                if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_AFFINITY) -ne 0) { 
                    $status.Affinity = Convert-AffinityMaskToString $basicInfo.Affinity.ToUInt64()
                }
                if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_PRIORITY_CLASS) -ne 0) { $status.Priority = ([NativeMethods+PROCESS_PRIORITY_CLASS]$basicInfo.PriorityClass).ToString() }
                if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_SCHEDULING_CLASS) -ne 0) { $status.Scheduling = $basicInfo.SchedulingClass }
                if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_WORKINGSET) -ne 0) { $status.WorkingSet = "$($basicInfo.MinimumWorkingSetSize.ToUInt64()/1MB)MB - $($basicInfo.MaximumWorkingSetSize.ToUInt64()/1MB)MB" }
            }

            $cpuInfo = New-Object NativeMethods+JOBOJECT_CPU_RATE_CONTROL_INFORMATION
            if ([NativeMethods]::QueryInformationJobObjectCpuRate($jobHandle, [NativeMethods+JOBOJECT_INFO_CLASS]::JobObjectCpuRateControlInformation, [ref]$cpuInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($cpuInfo), [ref]0)) {
                if (($cpuInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_CPU_RATE_CONTROL_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED) -ne 0) { $status.Weight = $cpuInfo.Weight }
                if (($cpuInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_CPU_RATE_CONTROL_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) -ne 0) { $status.CpuLimit = "$($cpuInfo.CpuRate / 100)%" }
            }

            $netInfo = New-Object NativeMethods+JOBOJECT_NET_RATE_CONTROL_INFORMATION
            if ([NativeMethods]::QueryInformationJobObjectNetRate($jobHandle, [NativeMethods+JOBOJECT_INFO_CLASS]::JobObjectNetRateControlInformation, [ref]$netInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($netInfo), [ref]0)) {
                if (($netInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_NET_RATE_CONTROL_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) -ne 0) { $status.NetLimit = "$($netInfo.MaxBandwidth / 1KB) KB/s" }
                if (($netInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_NET_RATE_CONTROL_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG) -ne 0) { $status.DSCP = $netInfo.DscpTag }
            }

            Write-Host "--- Job Object 状态报告 ---" -ForegroundColor Yellow
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
    }
    finally {
        if ($jobHandle -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($jobHandle) }
    }
    
    Start-Sleep -Seconds 1
}