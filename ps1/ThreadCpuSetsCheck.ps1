<#
.SYNOPSIS
    监控指定线程的CPU Sets配置
.DESCRIPTION
    每秒循环检查并显示指定线程ID的当前CPU Sets配置
.PARAMETER id
    线程ID
.EXAMPLE
    .\ThreadCpuSetsCheck.ps1 -id 1234
#>

param(
    [Parameter(Mandatory=$true)]
    [int]$id
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

    public const uint THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
}
"@

function Get-CpuSetMapping {
    try {
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
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
            return $null
        }

        # 解析CPU Set信息
        $cpuSetList = @()
        $offset = 0

        while ($offset -lt $returnLength) {
            $cpuSetInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure(
                [IntPtr]::Add($buffer, $offset),
                [type][SYSTEM_CPU_SET_INFORMATION]
            )

            if ($cpuSetInfo.Type -eq 0) {
                $cpuSetList += [PSCustomObject]@{
                    LogicalProcessor = [int]$cpuSetInfo.LogicalProcessorIndex
                    CpuSetId = [int]$cpuSetInfo.Id
                }
            }

            $offset += $cpuSetInfo.Size
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
        return $cpuSetList

    } catch {
        return $null
    }
}

function Get-ThreadCpuSets {
    param([int]$ThreadId, [array]$CpuSetMapping)

    try {
        # 打开线程句柄
        $threadHandle = [ThreadCpuSets]::OpenThread(
            [ThreadCpuSets]::THREAD_QUERY_LIMITED_INFORMATION,
            $false,
            [System.UInt32]$ThreadId
        )

        if ($threadHandle -eq [IntPtr]::Zero) {
            return $null
        }

        # 获取CPU Sets
        $returnedIds = New-Object System.UInt32[] 64
        $returnedCount = [System.UInt32]0

        $result = [ThreadCpuSets]::GetThreadSelectedCpuSets(
            $threadHandle,
            $returnedIds,
            [System.UInt32]64,
            [ref]$returnedCount
        )

        [ThreadCpuSets]::CloseHandle($threadHandle)

        if (-not $result) {
            return $null
        }

        # 构建返回数据
        $cpuSets = @()
        for ($i = 0; $i -lt $returnedCount; $i++) {
            $setCpuSetId = [int]$returnedIds[$i]
            $cpuInfo = $CpuSetMapping | Where-Object { $_.CpuSetId -eq $setCpuSetId }

            $cpuSets += [PSCustomObject]@{
                CpuSetId = $setCpuSetId
                LogicalProcessor = if ($cpuInfo) { $cpuInfo.LogicalProcessor } else { "未知" }
            }
        }

        return $cpuSets

    } catch {
        return $null
    }
}

# 主循环
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host "线程CPU Sets监控器" -ForegroundColor Cyan
Write-Host "监控线程ID: $id" -ForegroundColor Yellow
Write-Host "按 Ctrl+C 退出" -ForegroundColor Gray
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# 获取CPU Set映射表（只需要获取一次）
Write-Host "正在加载CPU Sets映射表..." -ForegroundColor Gray
$cpuSetMapping = Get-CpuSetMapping

if ($null -eq $cpuSetMapping) {
    Write-Host "错误: 无法获取系统CPU Sets信息" -ForegroundColor Red
    exit 1
}

Write-Host "系统共有 $($cpuSetMapping.Count) 个逻辑处理器`n" -ForegroundColor Gray

$iteration = 0
$lastCpuSets = $null

try {
    while ($true) {
        $iteration++
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        # 获取当前CPU Sets
        $currentCpuSets = Get-ThreadCpuSets -ThreadId $id -CpuSetMapping $cpuSetMapping

        if ($null -eq $currentCpuSets) {
            Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
            Write-Host "线程 $id 不存在或无法访问" -ForegroundColor Red
        }
        elseif ($currentCpuSets.Count -eq 0) {
            Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
            Write-Host "线程 $id - CPU Sets: " -NoNewline -ForegroundColor White
            Write-Host "未设置 (使用所有CPU)" -ForegroundColor Yellow
        }
        else {
            # 检查是否有变化
            $currentString = ($currentCpuSets | ForEach-Object { "$($_.CpuSetId)" }) -join ","
            $hasChanged = $false

            if ($null -ne $lastCpuSets) {
                $lastString = ($lastCpuSets | ForEach-Object { "$($_.CpuSetId)" }) -join ","
                $hasChanged = ($currentString -ne $lastString)
            }

            Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
            Write-Host "线程 $id - CPU Sets: " -NoNewline -ForegroundColor White

            $cpuSetDisplay = @()
            foreach ($cpuSet in $currentCpuSets) {
                $cpuSetDisplay += "CPU$($cpuSet.LogicalProcessor) (ID:$($cpuSet.CpuSetId))"
            }

            if ($hasChanged) {
                Write-Host ($cpuSetDisplay -join ", ") -ForegroundColor Green
                Write-Host "                      *** 配置已变化 ***" -ForegroundColor Magenta
            } else {
                Write-Host ($cpuSetDisplay -join ", ") -ForegroundColor Cyan
            }

            $lastCpuSets = $currentCpuSets
        }

        # 每10次迭代显示一个分隔线
        if ($iteration % 10 -eq 0) {
            Write-Host ("-" * 80) -ForegroundColor DarkGray
        }

        Start-Sleep -Seconds 1
    }
}
catch {
    Write-Host "`n`n程序已终止" -ForegroundColor Yellow
}