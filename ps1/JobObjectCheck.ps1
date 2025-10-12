# =========================================================================
#  JobObjectCheck.ps1
#
#  ����:
#  - ʹ��������������ȫ��ͬ���߼�����λ���� Job Object
#  - ͬʱ��鲢�����׺��ԡ����ȼ����������ȼ���ʱ��ƬȨ�ء�
#    CPUʹ�������ơ������������ơ����ݰ����ȼ���״̬
#
#  ���棺�����Թ���Ա������У�
# =========================================================================

# ���� 1: ����������Ҫ�� Win32 API ǩ��
try {
    Add-Type -TypeDefinition @"
    using System;
    using System.Runtime.InteropServices;

    public static class NativeMethods {
        // --- Job Object API ---
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenJobObjectW(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, string lpName);

        // Ϊ QueryInformationJobObject ������ͬ����ڵ�
        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectBasic(IntPtr hJob, JOBOBJECT_INFO_CLASS i, out JOBOBJECT_BASIC_LIMIT_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectCpuRate(IntPtr hJob, JOBOBJECT_INFO_CLASS i, out JOBOBJECT_CPU_RATE_CONTROL_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="QueryInformationJobObject")]
        public static extern bool QueryInformationJobObjectNetRate(IntPtr hJob, JOBOBJECT_INFO_CLASS i, out JOBOBJECT_NET_RATE_CONTROL_INFORMATION l, uint s, out uint r);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        // --- ö�ٶ��� ---
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

        // --- �ṹ�嶨�� ---
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

        // --- �������� ---
        public const uint JOB_OBJECT_QUERY = 0x0004;
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

# --- ���� 3: ���߼� ---

# ʹ��������������ȫ��ͬ���߼�����λĿ��͹�������
$jobObjectName = ""
$processNameInput = Read-Host -Prompt "������Ŀ������� (������.exe), ���������������ID"

if (-not [string]::IsNullOrWhiteSpace($processNameInput)) {
    $jobObjectName = "Global\ProcessControllerJob_$($processNameInput).exe_$($processId)"
} else {
    $processIdInput = Read-Host -Prompt "������Ŀ�����ID"
    if (-not [string]::IsNullOrWhiteSpace($processIdInput)) {
        try {
            $processId = [int]$processIdInput
            $jobObjectName = "Global\ProcessControllerJob_Enable.exe_$($processId)"
        } catch {
            Write-Warning "��Ч�Ľ���ID"
        }
    }
}

if ([string]::IsNullOrWhiteSpace($jobObjectName)) {
    Write-Host "δ�ṩ��Ч��Ŀ����Ϣ�ű����˳�" -ForegroundColor Yellow
    return
}

Write-Host "���ڳ��Դ򿪲���ѯ Job Object: '$jobObjectName'..." -ForegroundColor Cyan
$jobHandle = [IntPtr]::Zero
try {
    $jobHandle = [NativeMethods]::OpenJobObjectW([NativeMethods]::JOB_OBJECT_QUERY, $false, $jobObjectName)
    if ($jobHandle -eq [IntPtr]::Zero) {
        Write-Host "OpenJobObjectW ʧ�ܣ�" -ForegroundColor Red
        Write-Host "��ȷ��:" -ForegroundColor Yellow
        Write-Host "  1. ���������ű���������" -ForegroundColor Yellow
        Write-Host "  2. ���ڴ˴�����Ľ�������ID��������������ʱʹ�õ���ȫһ��" -ForegroundColor Yellow
        return
    }
    Write-Host "�ɹ��� Job Object���ڽ���ȫ����ϲ�ѯ..." -F Green
    
    # --- ��ʼ��״̬ ---
    $status = @{ Affinity = "�ѽ���"; Priority = "�ѽ���"; Scheduling = "�ѽ���"; Weight = "�ѽ���"; CpuLimit = "�ѽ���"; WorkingSet = "�ѽ���"; NetLimit = "�ѽ���"; DSCP = "�ѽ���" }

    # --- ��ѯ 1: �������� ---
    $basicInfo = New-Object NativeMethods+JOBOBJECT_BASIC_LIMIT_INFORMATION
    if ([NativeMethods]::QueryInformationJobObjectBasic($jobHandle, [NativeMethods+JOBOBJECT_INFO_CLASS]::JobObjectBasicLimitInformation, [ref]$basicInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($basicInfo), [ref]0)) {
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_AFFINITY) -ne 0) { $status.Affinity = "0x$($basicInfo.Affinity.ToUInt64().ToString('X'))" }
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_PRIORITY_CLASS) -ne 0) { $status.Priority = ([NativeMethods+PROCESS_PRIORITY_CLASS]$basicInfo.PriorityClass).ToString() }
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_SCHEDULING_CLASS) -ne 0) { $status.Scheduling = $basicInfo.SchedulingClass }
        if (($basicInfo.LimitFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_LIMIT_WORKINGSET) -ne 0) { $status.WorkingSet = "$($basicInfo.MinimumWorkingSetSize.ToUInt64()/1MB)MB - $($basicInfo.MaximumWorkingSetSize.ToUInt64()/1MB)MB" }
    }

    # --- ��ѯ 2: CPU �������� ---
    $cpuInfo = New-Object NativeMethods+JOBOBJECT_CPU_RATE_CONTROL_INFORMATION
    if ([NativeMethods]::QueryInformationJobObjectCpuRate($jobHandle, [NativeMethods+JOBOBJECT_INFO_CLASS]::JobObjectCpuRateControlInformation, [ref]$cpuInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($cpuInfo), [ref]0)) {
        if (($cpuInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_WEIGHT_BASED) -ne 0) { $status.Weight = $cpuInfo.Weight }
        if (($cpuInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP) -ne 0) { $status.CpuLimit = "$($cpuInfo.CpuRate / 100)%" }
    }

    # --- ��ѯ 3: �������� ---
    $netInfo = New-Object NativeMethods+JOBOBJECT_NET_RATE_CONTROL_INFORMATION
    if ([NativeMethods]::QueryInformationJobObjectNetRate($jobHandle, [NativeMethods+JOBOBJECT_INFO_CLASS]::JobObjectNetRateControlInformation, [ref]$netInfo, [System.Runtime.InteropServices.Marshal]::SizeOf($netInfo), [ref]0)) {
        if (($netInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_MAX_BANDWIDTH) -ne 0) { $status.NetLimit = "$($netInfo.MaxBandwidth / 1KB) KB/s" }
        if (($netInfo.ControlFlags -band [NativeMethods+JOB_OBJECT_LIMIT_FLAGS]::JOB_OBJECT_NET_RATE_CONTROL_DSCP_TAG) -ne 0) { $status.DSCP = $netInfo.DscpTag }
    }

    # --- ��ʾ���ձ��� ---
    Write-Host "`n--- Job Object ״̬���� ---" -ForegroundColor Yellow
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
finally {
    if ($jobHandle -ne [IntPtr]::Zero) { [NativeMethods]::CloseHandle($jobHandle) }
}