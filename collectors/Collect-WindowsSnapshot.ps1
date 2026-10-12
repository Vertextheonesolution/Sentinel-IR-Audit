#requires -Version 5.1
<#
.SYNOPSIS
    Export a Windows security observation snapshot as JSONL for offline triage.
.DESCRIPTION
    Reads local process metadata, scheduled tasks and Run/RunOnce registry entries.
    Does not remediate, change host configuration, execute observed commands,
    or send information over the network. Only writes the explicitly named output file.
    By default process command lines, scheduled task arguments and registry values
    are excluded because they may contain personal data or credentials.
.EXAMPLE
    .\Collect-WindowsSnapshot.ps1 -OutputPath .\snapshot.jsonl
.EXAMPLE
    .\Collect-WindowsSnapshot.ps1 -OutputPath .\snapshot-full.jsonl -IncludeCommandDetails
    WARNING: Review and sanitize sensitive command details before sharing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath,

    [switch]$IncludeCommandDetails
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$fullPath = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $fullPath) {
    throw "Output file already exists; choose a new path: $fullPath"
}
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($fullPath)) | Out-Null
$utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$script:Writer = [System.IO.StreamWriter]::new($fullPath, $false, $utf8NoBom)
$script:ObservationCount = 0
$timestamp = (Get-Date).ToUniversalTime().ToString('o')

function Write-Observation {
    param([Parameter(Mandatory = $true)][hashtable]$Observation)
    $script:Writer.WriteLine(($Observation | ConvertTo-Json -Depth 5 -Compress))
    $script:ObservationCount++
}

try {
    try {
        $processes = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
        foreach ($proc in $processes) {
            $details = ''
            if ($IncludeCommandDetails) { $details = [string]$proc.CommandLine }
            Write-Observation @{
                    kind            = 'process'
                    name            = [string]$proc.Name
                    executable_path = [string]$proc.ExecutablePath
                    command_line    = $details
                    timestamp       = $timestamp
            }
        }
    }
    catch {
        Write-Warning "Process inventory unavailable: $($_.Exception.GetType().Name)"
    }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop)
        foreach ($task in $tasks) {
            foreach ($action in @($task.Actions)) {
                if ($null -eq $action) { continue }
                $arguments = ''
                if ($IncludeCommandDetails) { $arguments = [string]$action.Arguments }
                Write-Observation @{
                        kind       = 'scheduled_task'
                        task_name  = [string]$task.TaskName
                        task_path  = [string]$task.TaskPath
                        executable = [string]$action.Execute
                        arguments  = $arguments
                        timestamp  = $timestamp
                }
            }
        }
    }
    catch {
        Write-Warning "Scheduled task inventory unavailable: $($_.Exception.GetType().Name)"
    }

    $autorunKeys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($key in $autorunKeys) {
        try {
            if (-not (Test-Path -LiteralPath $key)) { continue }
            $entry = Get-ItemProperty -LiteralPath $key -ErrorAction Stop
            foreach ($property in $entry.PSObject.Properties) {
                if ($property.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    continue
                }
                if ($property.Value -isnot [string]) { continue }
                $command = ''
                if ($IncludeCommandDetails) { $command = [string]$property.Value }
                Write-Observation @{
                        kind         = 'startup_entry'
                        name         = [string]$property.Name
                        registry_key = $key
                        command      = $command
                        timestamp    = $timestamp
                }
            }
        }
        catch {
            Write-Warning "Autorun inventory unavailable for one key: $($_.Exception.GetType().Name)"
        }
    }
}
finally {
    $script:Writer.Dispose()
}

Write-Host "Exported $script:ObservationCount observations to $fullPath"
if (-not $IncludeCommandDetails) {
    Write-Host 'Command-line fields excluded by default for privacy. See -IncludeCommandDetails.'
}
