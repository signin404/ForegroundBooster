<#
.SYNOPSIS
    设置指定线程的CPU Sets
.DESCRIPTION
    此脚本用于设置指定线程ID的CPU Sets 使用Windows API实现
.PARAMETER id
    线程ID
.PARAMETER c
    CPU编号（从0开始的逻辑处理器编号）
.EXAMPLE
    .\ThreadCpuSetsSet.ps1 -id 1234 -c 8
#>

param(
    [Parameter(Mandatory=$true)]
    [int]$id,

    [Parameter(Mandatory=$true)]
    [int]$c
)

# 定义Windows API和结构
Add-Type @"
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct SYSTEM_CPU_SET_INFORMATION {
    public uint Size;
    public uint Type;
    public uint Id;
    public ushort Group;
    public byte LogicalProcessorIndex;
    public byte CoreIndex;
    public byte LastLevelCacheIndex;
    public byte NumaNodeIndex;
    public byte EfficiencyClass;
    public byte AllFlags;
    public uint Reserved;
    public ulong AllocationTag;
}

public class ThreadCpuSets {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadSelectedCpuSets(
        IntPtr Thread,
        uint[] CpuSetIds,
        uint CpuSetIdCount
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadSelectedCpuSets(
        IntPtr Thread,
        uint[] CpuSetIds,
        uint CpuSetIdCount,
        out uint ReturnedIdCount
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetSystemCpuSetInformation(
        IntPtr Information,
        uint BufferLength,
        out uint ReturnLength,
        IntPtr Process,
        uint Flags
    );

    public const uint THREAD_SET_LIMITED_INFORMATION = 0x0400;
    public const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
}
"@

try {
    Write-Host "正在获取系统CPU Sets信息..." -ForegroundColor Cyan

    # 获取系统CPU Set信息
    $bufferSize = [System.UInt32]4096
    $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
    $returnLength = [System.UInt32]0

    $result = [ThreadCpuSets]::GetSystemCpuSetInformation(
        $buffer,
        $bufferSize,
        [ref]$returnLength,
        [IntPtr]::Zero,
        0
    )

    if (-not $result) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        throw "无法获取CPU Sets信息错误代码: $errorCode"
    }

    # 解析CPU Set信息 - 使用数组而不是哈希表
    $cpuSetList = @()
    $offset = 0
    $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][SYSTEM_CPU_SET_INFORMATION])

    while ($offset -lt $returnLength) {
        $cpuSetInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
            [IntPtr]::Add($buffer, $offset),
            [type][SYSTEM_CPU_SET_INFORMATION]
        )

        if ($cpuSetInfo.Type -eq 0) {  # CpuSetInformation type
            $logicalProc = [int]$cpuSetInfo.LogicalProcessorIndex
            $cpuSetId = [int]$cpuSetInfo.Id

            $cpuSetList += [PSCustomObject]@{
                LogicalProcessor = $logicalProc
                CpuSetId = $cpuSetId
            }

            Write-Host "  逻辑处理器 $logicalProc -> CPU Set ID $cpuSetId" -ForegroundColor Gray
        }

        $offset += $cpuSetInfo.Size
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)

    # 查找指定的逻辑处理器
    $targetCpuSet = $cpuSetList | Where-Object { $_.LogicalProcessor -eq $c }

    if ($null -eq $targetCpuSet) {
        $maxCpu = ($cpuSetList | Measure-Object -Property LogicalProcessor -Maximum).Maximum
        throw "逻辑处理器 $c 不存在可用范围: 0-$maxCpu"
    }

    $targetCpuSetId = $targetCpuSet.CpuSetId
    Write-Host "`n逻辑处理器 $c 对应的CPU Set ID: $targetCpuSetId" -ForegroundColor Yellow
    Write-Host "正在设置线程 $id 的CPU Sets..." -ForegroundColor Cyan

    # 打开线程句柄
    $threadHandle = [ThreadCpuSets]::OpenThread(
        [ThreadCpuSets]::THREAD_SET_LIMITED_INFORMATION -bor [ThreadCpuSets]::THREAD_QUERY_LIMITED_INFORMATION,
        $false,
        [System.UInt32]$id
    )

    if ($threadHandle -eq [IntPtr]::Zero) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "无法打开线程 $id错误代码: $errorCode请确认线程ID是否正确且有足够权限"
    }

    Write-Host "成功打开线程句柄" -ForegroundColor Green

    # 设置CPU Sets - 使用正确的CPU Set ID
    $cpuSetIds = New-Object System.UInt32[] 1
    $cpuSetIds[0] = [System.UInt32]$targetCpuSetId

    $result = [ThreadCpuSets]::SetThreadSelectedCpuSets(
        $threadHandle,
        $cpuSetIds,
        [System.UInt32]1
    )

    if (-not $result) {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        [ThreadCpuSets]::CloseHandle($threadHandle)
        throw "设置CPU Sets失败错误代码: $errorCode"
    }

    Write-Host "? 成功将线程 $id 的CPU Sets设置为逻辑处理器 $c (CPU Set ID: $targetCpuSetId)" -ForegroundColor Green

    # 验证设置
    $returnedIds = New-Object System.UInt32[] 64
    $returnedCount = [System.UInt32]0

    $verifyResult = [ThreadCpuSets]::GetThreadSelectedCpuSets(
        $threadHandle,
        $returnedIds,
        [System.UInt32]64,
        [ref]$returnedCount
    )

    if ($verifyResult -and $returnedCount -gt 0) {
        Write-Host "`n当前线程的CPU Sets配置:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $returnedCount; $i++) {
            $setCpuSetId = $returnedIds[$i]
            # 反向查找对应的逻辑处理器
            $cpuInfo = $cpuSetList | Where-Object { $_.CpuSetId -eq $setCpuSetId }
            if ($cpuInfo) {
                Write-Host "  CPU Set ID: $setCpuSetId (逻辑处理器: $($cpuInfo.LogicalProcessor))" -ForegroundColor White
            } else {
                Write-Host "  CPU Set ID: $setCpuSetId" -ForegroundColor White
            }
        }
    }

    # 关闭句柄
    [void][ThreadCpuSets]::CloseHandle($threadHandle)

} catch {
    Write-Host "错误: $_" -ForegroundColor Red
    exit 1
}