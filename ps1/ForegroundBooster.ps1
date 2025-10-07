Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NativeMethods
{
    // --- I/O Priority ---
    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationProcess(IntPtr processHandle, PROCESS_INFORMATION_CLASS processInformationClass, ref IO_PRIORITY_HINT ioPriority, int processInformationLength);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr processHandle, PROCESS_INFORMATION_CLASS processInformationClass, out IO_PRIORITY_HINT ioPriority, int processInformationLength, out int returnLength);

    public enum PROCESS_INFORMATION_CLASS { ProcessIoPriority = 33 }
    public enum IO_PRIORITY_HINT { IoPriorityVeryLow = 0, IoPriorityLow = 1, IoPriorityNormal = 2, IoPriorityHigh = 3, IoPriorityCritical = 4, MaxIoPriorityTypes }

    // --- GPU Priority ---
    [DllImport("gdi32.dll")]
    public static extern int D3DKMTSetProcessSchedulingPriorityClass(IntPtr hProcess, D3DKMT_SCHEDULING_PRIORITY_CLASS Priority);

    [DllImport("gdi32.dll")]
    public static extern int D3DKMTGetProcessSchedulingPriorityClass(IntPtr hProcess, out D3DKMT_SCHEDULING_PRIORITY_CLASS Priority);

    public enum D3DKMT_SCHEDULING_PRIORITY_CLASS { Idle = 0, BelowNormal = 1, Normal = 2, AboveNormal = 3 , High = 4 , RealTime = 5 }

    // --- Foreground Window ---
    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError=true)]
    public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    // --- Job Object ---
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint="SetInformationJobObject")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetInformationJobObjectCpuRate(IntPtr hJob, JOB_OBJECT_INFO_CLASS JobObjectInfoClass, ref JOBOBJECT_CPU_RATE_CONTROL_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);
    
    [DllImport("kernel32.dll", SetLastError = true, EntryPoint="SetInformationJobObject")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetInformationJobObjectBasic(IntPtr hJob, JOB_OBJECT_INFO_CLASS JobObjectInfoClass, ref JOBOBJECT_BASIC_LIMIT_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint="SetInformationJobObject")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool SetInformationJobObjectNetRate(IntPtr hJob, JOB_OBJECT_INFO_CLASS JobObjectInfoClass, ref JOBOBJECT_NET_RATE_CONTROL_INFORMATION lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr hObject);

    // --- Thread Input Attachment ---
    [DllImport("user32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

    // --- Enums and Structs for Job Object ---
    public enum JOB_OBJECT_INFO_CLASS {
        JobObjectBasicLimitInformation = 2,
        JobObjectCpuRateControlInformation = 15,
        JobObjectNetRateControlInformation = 32
    }

    [Flags]
    public enum JOB_OBJECT_LIMIT_FLAGS : uint {
        JOB_OBJECT_CPU_RATE_CONTROL_ENABLE     = 0x1,
        JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED = 0x2,
        JOB_OBJECT_LIMIT_SCHEDULING_CLASS    = 0x00000080,
        JOB_OBJECT_NET_RATE_CONTROL_ENABLE     = 0x1,
        JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG   = 0x4
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        [FieldOffset(0)] public JOB_OBJECT_LIMIT_FLAGS ControlFlags;
        [FieldOffset(4)] public uint Weight;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public JOB_OBJECT_LIMIT_FLAGS LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_NET_RATE_CONTROL_INFORMATION {
        public ulong MaxBandwidth;
        public JOB_OBJECT_LIMIT_FLAGS ControlFlags;
        public byte DscpTag;
    }
}
"@ -PassThru | Out-Null

# --- 辅助函数区域 ---
function Get-ForegroundProcess {
    $hwnd = [NativeMethods]::GetForegroundWindow()
    if ($hwnd -eq [IntPtr]::Zero) { return $null }
    $processId = 0
    [NativeMethods]::GetWindowThreadProcessId($hwnd, [ref]$processId) | Out-Null
    if ($processId -eq 0) { return $null }
    return Get-Process -Id $processId -ErrorAction SilentlyContinue
}

# --- I/O 优先级函数 ---
function Get-ProcessIoPriority {
    param([Parameter(Mandatory=$true, ValueFromPipeline=$true)][System.Diagnostics.Process] $Process)
    $priorityHint = [NativeMethods+IO_PRIORITY_HINT]::IoPriorityNormal
    $returnLength = 0
    $result = [NativeMethods]::NtQueryInformationProcess($Process.Handle, [NativeMethods+PROCESS_INFORMATION_CLASS]::ProcessIoPriority, [ref]$priorityHint, 4, [ref]$returnLength)
    if ($result -eq 0) { return $priorityHint.ToString().Replace("IoPriority", "") } else { return $null }
}

function Set-ProcessIoPriority {
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)][System.Diagnostics.Process] $Process,
        [Parameter(Mandatory=$true)][ValidateSet("VeryLow", "Low", "Normal", "High")][string] $IoPriority
    )
    $priorityHint = [NativeMethods+IO_PRIORITY_HINT]::$("IoPriority" + $IoPriority)
    $infoLength = 4
    [NativeMethods]::NtSetInformationProcess($Process.Handle, [NativeMethods+PROCESS_INFORMATION_CLASS]::ProcessIoPriority, [ref]$priorityHint, $infoLength) | Out-Null
}

# --- GPU 优先级函数 ---
function Get-ProcessGpuPriority {
    param([Parameter(Mandatory=$true, ValueFromPipeline=$true)][System.Diagnostics.Process] $Process)
    $priority = [NativeMethods+D3DKMT_SCHEDULING_PRIORITY_CLASS]::Normal
    $result = [NativeMethods]::D3DKMTGetProcessSchedulingPriorityClass($Process.Handle, [ref]$priority)
    if ($result -eq 0) { return $priority } else { return $null }
}

function Set-ProcessGpuPriority {
    param([Parameter(Mandatory=$true, ValueFromPipeline=$true)][System.Diagnostics.Process] $Process, [Parameter(Mandatory=$true)][NativeMethods+D3DKMT_SCHEDULING_PRIORITY_CLASS] $Priority)
    [NativeMethods]::D3DKMTSetProcessSchedulingPriorityClass($Process.Handle, $Priority) | Out-Null
}

# --- 调度优先级函数 ---
function Set-ProcessSchedulingClass {
    param(
        [Parameter(Mandatory=$true)][IntPtr] $JobHandle,
        [Parameter(Mandatory=$true)][ValidateRange(-1,9)][int] $Scheduling # 允许-1以禁用
    )
    $limitInfo = New-Object NativeMethods+JOBOBJECT_BASIC_LIMIT_INFORMATION
    if ($Scheduling -ge 0 -and $Scheduling -le 9) {
        $limitInfo.LimitFlags = [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_SCHEDULING_CLASS
        $limitInfo.SchedulingClass = $Scheduling
    } else {
        $limitInfo.LimitFlags = 0 # 传入无效值则禁用
    }
    
    $result = [NativeMethods]::SetInformationJobObjectBasic(
        $JobHandle,
        [NativeMethods+JOB_OBJECT_INFO_CLASS]::JobObjectBasicLimitInformation,
        [ref]$limitInfo,
        [System.Runtime.InteropServices.Marshal]::SizeOf($limitInfo)
    )
    return $result
}

# --- 时间片权重函数 ---
function Set-ProcessQuantumWeight {
    param(
        [Parameter(Mandatory=$true)][IntPtr] $JobHandle,
        [Parameter(Mandatory=$true)][ValidateRange(0,9)][int] $Weight
    )
    $cpuInfo = New-Object NativeMethods+JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    if ($Weight -ge 1 -and $Weight -le 9) {
        $cpuInfo.ControlFlags = [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_ENABLE -bor [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED
        $cpuInfo.Weight = $Weight
    } else {
        # 权重为0或其他无效值意味着禁用控制
        $cpuInfo.ControlFlags = 0
    }
    
    # 使用专门为 CPU 速率控制创建的 P/Invoke 重载
    $result = [NativeMethods]::SetInformationJobObjectCpuRate(
        $JobHandle,
        [NativeMethods+JOB_OBJECT_INFO_CLASS]::JobObjectCpuRateControlInformation,
        [ref]$cpuInfo,
        [System.Runtime.InteropServices.Marshal]::SizeOf($cpuInfo)
    )
    return $result
}

# --- DSCP 函数 ---
function Set-ProcessDSCP {
    param(
        [Parameter(Mandatory=$true)][IntPtr] $JobHandle,
        [Parameter(Mandatory=$true)][ValidateRange(-1,63)][int] $DSCP # 允许-1以禁用
    )
    $netInfo = New-Object NativeMethods+JOBOBJECT_NET_RATE_CONTROL_INFORMATION
    $netInfo.MaxBandwidth = 0  # 不设置带宽限制
    
    if ($DSCP -ge 0 -and $DSCP -le 63) {
        $netInfo.ControlFlags = [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_ENABLE -bor [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG
        $netInfo.DscpTag = [byte]$DSCP
    } else {
        # DSCP为-1或其他无效值意味着禁用控制
        $netInfo.ControlFlags = 0
        $netInfo.DscpTag = 0
    }
    
    $result = [NativeMethods]::SetInformationJobObjectNetRate(
        $JobHandle,
        [NativeMethods+JOB_OBJECT_INFO_CLASS]::JobObjectNetRateControlInformation,
        [ref]$netInfo,
        [System.Runtime.InteropServices.Marshal]::SizeOf($netInfo)
    )
    return $result
}

# --- 主循环 ---
$lastProcess = $null
$originalIoPriority = $null
$originalGpuPriority = $null
$managedProcesses = @{}
$previousProcessIds = [System.Collections.Generic.HashSet[int]]::new()

# 附加到前台的进程
$attachWhitelist = @("AltSnap")
$lastAttachedForegroundThreadId = 0

# 进程黑名单
$processBlacklist = @("System", "Registry", "Idle", "csrss", "dwm", "services", "smss", "wininit", "chrome")

try {
    while ($true) {
        $currentProcess = Get-ForegroundProcess

        if ($null -ne $currentProcess -and $currentProcess.Id -ne $lastProcess.Id) {

            # --- 恢复上个前台进程的优先级 ---
            if ($null -ne $lastProcess) {
                try {
                    $procCheck = Get-Process -Id $lastProcess.Id -ErrorAction SilentlyContinue
                    if ($procCheck) {
                       if ($null -ne $originalIoPriority) {
                           Set-ProcessIoPriority -Process $lastProcess -IoPriority $originalIoPriority
                       }
                       #if ($null -ne $originalGpuPriority) {
                           #Set-ProcessGpuPriority -Process $lastProcess -Priority $originalGpuPriority
                       #}
                       # 解除 Job Object 限制
                       if ($managedProcesses.ContainsKey($lastProcess.Id)) {
                           Set-ProcessSchedulingClass -JobHandle $managedProcesses[$lastProcess.Id].JobHandle -Scheduling -1 | Out-Null
                           Set-ProcessQuantumWeight -JobHandle $managedProcesses[$lastProcess.Id].JobHandle -Weight 0 | Out-Null
                           Set-ProcessDSCP -JobHandle $managedProcesses[$lastProcess.Id].JobHandle -DSCP -1 | Out-Null
                           [NativeMethods]::CloseHandle($managedProcesses[$lastProcess.Id].JobHandle) | Out-Null
                           $managedProcesses.Remove($lastProcess.Id)
                       }
                    }
                } catch {}
            }

            # 重置状态 为处理新进程做准备
            $lastProcess = $null; $originalIoPriority = $null; $originalGpuPriority = $null

            # --- 处理新的前台进程 ---
            if ($currentProcess.Name -notin $processBlacklist) {
                
                # 标记我们正在管理这个进程
                $lastProcess = $currentProcess
                $didModify = $false

                # --- 独立处理 I/O 优先级 ---
                $newOriginalIoPriority = Get-ProcessIoPriority -Process $currentProcess
                if ($null -ne $newOriginalIoPriority -and $newOriginalIoPriority -ne "High" -and $newOriginalIoPriority -ne "Low" -and $newOriginalIoPriority -ne "VeryLow") {
                    Set-ProcessIoPriority -Process $currentProcess -IoPriority "High"
                    $originalIoPriority = $newOriginalIoPriority # 仅在修改时记录原始值
                    $didModify = $true
                }

                # --- 独立处理 GPU 优先级 ---
                #$newOriginalGpuPriority = Get-ProcessGpuPriority -Process $currentProcess
                #if ($null -ne $newOriginalGpuPriority -and $newOriginalGpuPriority -ne "RealTime" -and $newOriginalGpuPriority -ne "High" -and $newOriginalGpuPriority -ne "BelowNormal" -and $newOriginalGpuPriority -ne "Idle") {
                    #Set-ProcessGpuPriority -Process $currentProcess -Priority "High"
                    #$originalGpuPriority = $newOriginalGpuPriority # 仅在修改时记录原始值
                    #$didModify = $true
                #}

                # 处理新的前台进程
                # 检查是否是初次管理此进程
                if (-not $managedProcesses.ContainsKey($currentProcess.Id)) {
                    $jobObjectName = "Global\ForegroundBoosterJob_PID_$($currentProcess.Id)"
                    $jobHandle = [NativeMethods]::CreateJobObjectW([IntPtr]::Zero, $jobObjectName)
                    if ($jobHandle -ne [IntPtr]::Zero) {
                        [NativeMethods]::AssignProcessToJobObject($jobHandle, $currentProcess.Handle) | Out-Null
                        # 将句柄存入独立跟踪列表
                        $managedProcesses[$currentProcess.Id] = @{ JobHandle = $jobHandle }
                    }
                }
                # 无论是否初次都设置Job Object
                if ($managedProcesses.ContainsKey($currentProcess.Id)) {
                    Set-ProcessSchedulingClass -JobHandle $managedProcesses[$currentProcess.Id].JobHandle -Scheduling 9 | Out-Null
                    Set-ProcessQuantumWeight -JobHandle $managedProcesses[$currentProcess.Id].JobHandle -Weight 1 | Out-Null
                    Set-ProcessDSCP -JobHandle $managedProcesses[$currentProcess.Id].JobHandle -DSCP 46 | Out-Null
                    $didModify = $true # 确保此进程被跟踪
                }

                # 如果优先级都已经是最高 实际上没有修改
                if (-not $didModify) {
                    # 取消标记 因为没有修改 不需要恢复
                    $lastProcess = $null
                }
            }
        }

        # --- 后台线程附加到前台 ---
        if ($null -ne $currentProcess) {
            $currentForegroundHwnd = [NativeMethods]::GetForegroundWindow()
            $currentForegroundThreadId = 0
            if ($currentForegroundHwnd -ne [IntPtr]::Zero) {
                try { $currentForegroundThreadId = [NativeMethods]::GetWindowThreadProcessId($currentForegroundHwnd, [ref]0) } catch {}
            }
            
            if ($currentForegroundThreadId -ne 0 -and $currentForegroundThreadId -ne $lastAttachedForegroundThreadId) {
                $threadsToAttach = [System.Collections.ArrayList]::new()
                foreach ($name in $attachWhitelist) {
                    $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
                    foreach ($proc in $procs) {
                        foreach ($thread in $proc.Threads) {
                            [void]$threadsToAttach.Add($thread.Id)
                        }
                    }
                }

                if ($lastAttachedForegroundThreadId -ne 0 -and $threadsToAttach.Count -gt 0) {
					#Write-Host "$(Get-Date) - [附加模块] 前台窗口已切换 正在从旧线程 $lastAttachedForegroundThreadId 分离 $($threadsToAttach.Count) 个白名单线程..." -ForegroundColor Gray
                    foreach ($threadId in $threadsToAttach) {
                        [NativeMethods]::AttachThreadInput($threadId, $lastAttachedForegroundThreadId, $false) | Out-Null
                    }
                }

                if ($currentProcess.Name -notin $attachWhitelist -and $threadsToAttach.Count -gt 0) {
					#Write-Host "$(Get-Date) - [附加模块] 检测到新的前台线程: $currentForegroundThreadId (来自进程: $($currentProcess.Name))"
					#Write-Host "  -> 正在尝试将 $($threadsToAttach.Count) 个白名单线程附加到新前台..."
					$successCount = 0
                    foreach ($threadId in $threadsToAttach) {
                        if ([NativeMethods]::AttachThreadInput($threadId, $currentForegroundThreadId, $true)) {
                            $successCount++
                        }
                    }
                    #Write-Host "  -> 附加完成 成功: $successCount / $($threadsToAttach.Count)" -ForegroundColor Green
                }
                $lastAttachedForegroundThreadId = $currentForegroundThreadId
            }
        }

        # --- 进程列表变化检测 ---
        $allProcesses = Get-Process -ErrorAction SilentlyContinue
        $currentProcessIds = [System.Collections.Generic.HashSet[int]]::new()
        foreach ($id in $allProcesses.Id) {
            [void]$currentProcessIds.Add($id)
        }
        
        # 比较当前列表和上次列表
        $difference = Compare-Object -ReferenceObject $previousProcessIds -DifferenceObject $currentProcessIds
        
        # 仅在列表有变化时才执行
        if ($null -ne $difference) {
            # --- 检查并重置子进程I/O优先级 ---
            foreach ($proc in $allProcesses) {
                try {
                    if (($null -ne $lastProcess -and $proc.Id -eq $lastProcess.Id) -or ($proc.Name -in $processBlacklist)) {
                        continue
                    }
                    if ($null -ne $proc.PriorityClass) {
                        $cpuPriority = $proc.PriorityClass.ToString()
                        if ($cpuPriority -in "Normal", "BelowNormal", "Idle") {
                            $ioPriority = Get-ProcessIoPriority -Process $proc
                            if ($null -ne $ioPriority -and $ioPriority -eq "High") {
                                Set-ProcessIoPriority -Process $proc -IoPriority "Normal"
                            }
                        }
                    }
                } catch {}
            }
        }
        # 更新进程列表
        $previousProcessIds = $currentProcessIds
        Start-Sleep -Seconds 2
    }
}

finally {
    # --- 恢复进程优先级 ---
    if ($null -ne $lastProcess) {
        try {
             $procCheck = Get-Process -Id $lastProcess.Id -ErrorAction SilentlyContinue
             if ($procCheck) {
                if ($null -ne $originalIoPriority) {
                    Set-ProcessIoPriority -Process $lastProcess -IoPriority $originalIoPriority
                }
                #if ($null -ne $originalGpuPriority) {
                    #Set-ProcessGpuPriority -Process $lastProcess -Priority $originalGpuPriority
                #}
             }
        } catch {}
    }

    # --- 解除 Job Object 限制---
    foreach ($procId in $managedProcesses.Keys) {
        try {
            $procInfo = $managedProcesses[$procId]
            $procCheck = Get-Process -Id $procId -ErrorAction SilentlyContinue
            if ($procCheck) {
                # 禁用控制
                Set-ProcessSchedulingClass -JobHandle $procInfo.JobHandle -Scheduling -1 | Out-Null
                Set-ProcessQuantumWeight -JobHandle $procInfo.JobHandle -Weight 0 | Out-Null
                Set-ProcessDSCP -JobHandle $procInfo.JobHandle -DSCP -1 | Out-Null
                # 关闭句柄
                [NativeMethods]::CloseHandle($procInfo.JobHandle) | Out-Null
            }
        } catch {}
    }

    # --- 分离线程 ---
    if ($lastAttachedForegroundThreadId -ne 0) {
        $finalThreadsToDetach = [System.Collections.ArrayList]::new()
        foreach ($name in $attachWhitelist) {
            $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
            foreach ($proc in $procs) { foreach ($thread in $proc.Threads) { [void]$finalThreadsToDetach.Add($thread.Id) } }
        }
        if ($finalThreadsToDetach.Count -gt 0) {
            foreach ($threadId in $finalThreadsToDetach) {
                [NativeMethods]::AttachThreadInput($threadId, $lastAttachedForegroundThreadId, $false) | Out-Null
            }
        }
    }
}