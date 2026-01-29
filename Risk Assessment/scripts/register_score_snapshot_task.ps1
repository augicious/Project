param(
    [string]$TaskName = "RiskTicketing Score Snapshot (Monthly)",
    [ValidateRange(1, 31)]
    [int]$DayOfMonth = 1,
    [string]$StartTime = "02:00",
    # App folder that contains app.py, templates/, data/, scripts/, etc.
    # For production on hdh-websrv, this is typically:
    #   C:\inetpub\wwwroot\Project\Risk Assessment
    # NOTE: Scheduled tasks running as SYSTEM should use a local disk path.
    [string]$AppRoot = "C:\inetpub\wwwroot\Project\Risk Assessment",
    [string]$PythonExe = "",
    # Only used when the script falls back to the Windows Python launcher (py.exe).
    # Examples: "3.12", "3"
    [string]$PythonLauncherVersion = "3.12",
    [string]$ScriptPath = "",
    [string]$RunAs = "SYSTEM"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-ExistingPath([string]$PathText) {
    if ([string]::IsNullOrWhiteSpace($PathText)) { return $null }
    $p = Resolve-Path -LiteralPath $PathText -ErrorAction SilentlyContinue
    if ($p) { return $p.Path }
    return $null
}

function Resolve-CommandPath([string]$CommandName) {
    if ([string]::IsNullOrWhiteSpace($CommandName)) { return $null }
    try {
        $cmd = Get-Command $CommandName -ErrorAction Stop
        if ($cmd -and $cmd.Path) { return $cmd.Path }
    } catch {
        return $null
    }
    return $null
}

function Convert-AdminShareToLocalPath([string]$PathText) {
    if ([string]::IsNullOrWhiteSpace($PathText)) { return $PathText }
    # Convert admin share paths like \\hdh-websrv\c$\inetpub\... to C:\inetpub\...
    if ($PathText -match '^[\\]{2}[^\\]+\\([a-zA-Z])\$\\(.+)$') {
        $drive = $Matches[1].ToUpper()
        $rest = $Matches[2] -replace '/', '\\'
        return "${drive}:\\$rest"
    }
    return $PathText
}

$originalAppRoot = $AppRoot
$convertedAppRoot = Convert-AdminShareToLocalPath $AppRoot

$resolvedAppRoot = Resolve-ExistingPath $convertedAppRoot
if (-not $resolvedAppRoot -and $convertedAppRoot -ne $originalAppRoot) {
    $resolvedAppRoot = Resolve-ExistingPath $originalAppRoot
}
if (-not $resolvedAppRoot) {
    throw "AppRoot not found: '$originalAppRoot'. Pass -AppRoot with the full path to your 'Risk Assessment' folder (prefer a local disk path for SYSTEM)."
}
$AppRoot = $resolvedAppRoot
$repoRoot = Split-Path -Parent $AppRoot

# Defaults (best effort) for dev/workstation usage.
if ([string]::IsNullOrWhiteSpace($PythonExe)) {
    $PythonExe = Resolve-ExistingPath (Join-Path $repoRoot ".venv\Scripts\python.exe")
    if (-not $PythonExe) {
        $PythonExe = Resolve-ExistingPath (Join-Path $AppRoot ".venv\Scripts\python.exe")
    }
}

$usePythonLauncher = $false
if (-not $PythonExe) {
    # Last-resort common install paths.
    $PythonExe = Resolve-ExistingPath "C:\Program Files\Python312\python.exe"
    if (-not $PythonExe) {
        $PythonExe = Resolve-ExistingPath "C:\Program Files (x86)\Python312\python.exe"
    }
}

if (-not $PythonExe) {
    # Next best: py.exe launcher if installed (common with Python from python.org).
    $pyLauncher = Resolve-CommandPath "py.exe"
    if ($pyLauncher) {
        $PythonExe = $pyLauncher
        $usePythonLauncher = $true
    }
}

if (-not $PythonExe) {
    throw "PythonExe not found. Pass -PythonExe with a full path to python.exe (NOT a Start Menu shortcut folder). Recommended: a local venv python (e.g. '$repoRoot\.venv\Scripts\python.exe') or ensure 'py.exe' is available."
}

if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
    $ScriptPath = Resolve-ExistingPath (Join-Path $AppRoot "scripts\capture_score_snapshot.py")
}
if (-not $ScriptPath) {
    throw "ScriptPath not found. Pass -ScriptPath with the full path to capture_score_snapshot.py."
}

# IMPORTANT: Scheduled tasks running as SYSTEM typically cannot see mapped drives like V:\.
# In production, use a local path (e.g. C:\ProgramData\RiskTicketing\...) or a UNC path.

$args = if ($usePythonLauncher) {
    if ([string]::IsNullOrWhiteSpace($PythonLauncherVersion)) {
        ('"{0}"' -f $ScriptPath)
    } else {
        ('-{0} "{1}"' -f $PythonLauncherVersion, $ScriptPath)
    }
} else {
    ('"{0}"' -f $ScriptPath)
}

$action = New-ScheduledTaskAction -Execute $PythonExe -Argument $args -WorkingDirectory $AppRoot

$trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth $DayOfMonth -At $StartTime

$principal = if ($RunAs -eq 'SYSTEM') {
    New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
} else {
    New-ScheduledTaskPrincipal -UserId $RunAs -LogonType Password -RunLevel Highest
}

$settings = New-ScheduledTaskSettingsSet -Compatibility Win8 -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

Register-ScheduledTask -TaskName $TaskName -InputObject $task -Force | Out-Null

Write-Host "Registered scheduled task: $TaskName" -ForegroundColor Green
Write-Host "Runs: $PythonExe $args" 
Write-Host "Schedule: Monthly day $DayOfMonth at $StartTime" 
