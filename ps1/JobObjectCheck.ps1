# ------------------------------------------------------------------------------------
# ProcessController - ��ҵ����״̬ʵʱ��ؽű� (v4 - �޸�C#�������)
# ------------------------------------------------------------------------------------

# --- ���� 1: ������ Windows API ��������� C# ���� ---
try {
    # [�޸�] ���������Ͷ��壨������ö�١��ṹ�壩�ƶ�����������֮ǰ
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public static class NativeMethods {
        // --- 1. �������� ---
        public const uint JOB_OBJECT_QUERY = 0x0004;

        // --- 2. ö�ٶ��� ---
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

        // --- 3. �ṹ�嶨�� ---
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

        // --- 4. Job Object API �������� ---
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
    Write-Host "C# ����ʧ��: $($_.Exception.Message)" -ForegroundColor Red
    return
}

# --- ���� 2: �������� ---

function Write-StatusLine {
    param($Label, $Value)
    $labelPadded = $Label.PadRight(30)
    if ($Value -eq "�ѽ���") {
        Write-Host "${labelPadded}: " -NoNewline
        Write-Host $Value -ForegroundColor Red
    } else {
        Write-Host "${labelPadded}: " -NoNewline
        Write-Host $Value -ForegroundColor Green
    }
}

function Convert-AffinityMaskToString {
    param([UInt64]$Mask)
    if ($Mask -eq 0) { return "�ѽ���" }
    
    $cores = @()
    for ($i = 0; $i -lt 64; $i++) {
        if ((($Mask -shr $i) -band 1) -eq 1) {
            $cores += $i
        }
    }

    if ($cores.Count -eq 0) { return "�ѽ���" }

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


# --- ���� 3: ����Ŀ����̲�������ҵ�������� ---

$targetProcess = $null
while ($targetProcess -eq $null) {
    $input = Read-Host "������Ŀ��������ƻ�ID"
    if ($input -match "^\d+$") { # ��������Ƿ�Ϊ������ (ID)
        $targetProcess = Get-Process -Id $input -ErrorAction SilentlyContinue
        if ($targetProcess -eq $null) { Write-Warning "δ�ҵ� ID Ϊ $input �Ľ���" }
    } else { # ���� �����Ʋ���
        $processNameToSearch = $input
        if ($processNameToSearch.EndsWith(".exe", [System.StringComparison]::InvariantCultureIgnoreCase)) {
            $processNameToSearch = $processNameToSearch.Substring(0, $processNameToSearch.Length - 4)
        }
        
        $targetProcess = Get-Process -Name $processNameToSearch -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($targetProcess -eq $null) { Write-Warning "δ�ҵ���Ϊ '$input' �Ľ���" }
    }
}

$jobObjectName = "Global\ProcessControllerJob_$($targetProcess.MainModule.ModuleName)_$($targetProcess.Id)"

# --- ���� 4: �����ѭ�� ---

while ($true) {
    try {
        Get-Process -Id $targetProcess.Id -ErrorAction Stop | Out-Null
    } catch {
        Clear-Host
        Write-Host "Ŀ����� $($targetProcess.Name) (PID: $($targetProcess.Id)) ���˳���ؽű���ֹͣ" -ForegroundColor Yellow
        break
    }

    Clear-Host
    Write-Host "--- ���ڼ�� ����: $($targetProcess.Name) (PID: $($targetProcess.Id)) ---" -ForegroundColor Cyan
    Write-Host "--- ��ҵ����: $jobObjectName ---" -ForegroundColor Cyan
    Write-Host "--- (ÿ��ˢ��, �� Ctrl+C ֹͣ) ---`n"

    $jobHandle = [IntPtr]::Zero
    try {
        $jobHandle = [NativeMethods]::OpenJobObjectW([NativeMethods]::JOB_OBJECT_QUERY, $false, $jobObjectName)
        
        if ($jobHandle -eq [IntPtr]::Zero) {
            Write-Host "�޷�����ҵ����" -ForegroundColor Red
            Write-Host "��ȷ�� ProcessController.exe �ѶԸý��̳ɹ�Ӧ�ù�����" -ForegroundColor Yellow
        } else {
            $status = @{ Affinity = "�ѽ���"; Priority = "�ѽ���"; Scheduling = "�ѽ���"; Weight = "�ѽ���"; CpuLimit = "�ѽ���"; WorkingSet = "�ѽ���"; NetLimit = "�ѽ���"; DSCP = "�ѽ���" }

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

            Write-Host "--- Job Object ״̬���� ---" -ForegroundColor Yellow
            Write-StatusLine -Label "1. �׺��� (Affinity)" -Value $status.Affinity
            Write-StatusLine -Label "2. ���ȼ� (Priority)" -Value $status.Priority
            Write-StatusLine -Label "3. �������ȼ� (Scheduling)" -Value $status.Scheduling
            Write-StatusLine -Label "4. ʱ��ƬȨ�� (Weight)" -Value $status.Weight
            Write-StatusLine -Label "5. ���ݰ����ȼ� (DSCP)" -Value $status.DSCP
            Write-StatusLine -Label "6. CPUʹ�������� (CpuLimit)" -Value $status.CpuLimit
            Write-StatusLine -Label "7. ������������ (NetLimit)" -Value $status.NetLimit
            Write-StatusLine -Label "8. �����ڴ����� (WorkingSet)" -Value $status.WorkingSet
            Write-Host "---------------------------------"
        }
    }
    finally {
        if ($jobHandle -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($jobHandle) }
    }
    
    Start-Sleep -Seconds 1
}