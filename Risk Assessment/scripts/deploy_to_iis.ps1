[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Path to local source (workspace) app folder
    [Parameter()]
    [string]$Source = "",

    # Path to IIS deployment folder
    [Parameter()]
    [string]$Destination = "\\hdh-websrv\c$\inetpub\wwwroot\Project\Risk Assessment",

    # Create a timestamped backup of the Destination before copying
    [Parameter()]
    [switch]$Backup,

    # Backup root (only used when -Backup is set)
    [Parameter()]
    [string]$BackupRoot = "\\hdh-websrv\c$\inetpub\wwwroot\Project\_deploy_backups",

    # Only copy the web app payload (app.py, templates, static, web.config, run_waitress.py, requirements.txt)
    # Excludes data/, logs/, __pycache__/, .venv/, etc.
    [Parameter()]
    [switch]$PayloadOnly = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Destination([string]$Path) {
    # If running on the server, convert \\HOST\c$\path -> C:\path to avoid UNC oddities.
    $m = [regex]::Match($Path, '^\\\\([^\\]+)\\([a-zA-Z])\$\\(.+)$')
    if ($m.Success) {
        $destHost = $m.Groups[1].Value
        $drive = $m.Groups[2].Value
        $rest = $m.Groups[3].Value
        if ($env:COMPUTERNAME -and (($destHost -ieq $env:COMPUTERNAME) -or ($destHost -ieq 'localhost'))) {
            return ($drive + ':\' + $rest)
        }
    }
    return $Path
}

function Test-FileUnlockedForWrite([string]$Path) {
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        $fs.Close()
        return $true
    } catch {
        return $false
    }
}

function Assert-PathExists([string]$Path, [string]$Label) {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "$Label path not found: $Path"
    }
}

function New-Timestamp() {
    return (Get-Date).ToString('yyyyMMdd-HHmmss')
}

function Invoke-RoboCopy([string]$From, [string]$To, [string[]]$Args) {
    $cmd = @('robocopy', $From, $To) + $Args
    Write-Output ("Running: " + ($cmd -join ' '))
    & robocopy $From $To @Args

    # Robocopy exit codes: 0-7 are success-ish; >= 8 indicate failures.
    if ($LASTEXITCODE -ge 8) {
        throw "Robocopy failed with exit code $LASTEXITCODE"
    }
}

if (-not $Source) {
    # Default to the folder containing the project (parent of scripts/)
    $Source = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
}

Assert-PathExists -Path $Source -Label 'Source'
$Destination = Normalize-Destination $Destination
Assert-PathExists -Path $Destination -Label 'Destination'

$sourceResolved = (Resolve-Path -LiteralPath $Source).Path
$destResolved = (Resolve-Path -LiteralPath $Destination).Path

# Normalize UNC admin shares (\\HOST\c$\...) to local drive paths (C:\...) when running on that host,
# so "source == destination" detection works even if one side is UNC and the other is local.
$sourceCompare = Normalize-Destination $sourceResolved
$destCompare = Normalize-Destination $destResolved
$sourceCompare = [System.IO.Path]::GetFullPath($sourceCompare)
$destCompare = [System.IO.Path]::GetFullPath($destCompare)

Write-Output "Source      : $sourceResolved"
Write-Output "Destination : $destResolved"

if ($sourceCompare.TrimEnd('\\') -ieq $destCompare.TrimEnd('\\')) {
    throw "Source and Destination resolve to the same path. Run this script from your workspace copy, or pass -Source to point at the folder you want to deploy from. Source=$sourceResolved Destination=$destResolved"
}

if ($Backup) {
    $stamp = New-Timestamp
    $backupDir = Join-Path $BackupRoot ("RiskAssessment-" + $stamp)

    if ($PSCmdlet.ShouldProcess($backupDir, "Create backup folder")) {
        New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    }

    if ($PSCmdlet.ShouldProcess($backupDir, "Backup destination")) {
        # Mirror destination into backup
        Invoke-RoboCopy -From $destResolved -To $backupDir -Args @(
            '/MIR',
            '/R:2',
            '/W:2',
            '/NFL',
            '/NDL',
            '/NP'
        )
    }
}

if ($PayloadOnly) {
    # Top-level files
    $topFiles = @('app.py', 'run_waitress.py', 'web.config', 'requirements.txt')
    foreach ($f in $topFiles) {
        $srcFile = Join-Path $sourceResolved $f
        if (Test-Path -LiteralPath $srcFile) {
            $dstFile = Join-Path $destResolved $f
            if ($PSCmdlet.ShouldProcess($destResolved, "Copy $f")) {
                if (Test-Path -LiteralPath $dstFile) {
                    if (-not (Test-FileUnlockedForWrite $dstFile)) {
                        Write-Warning "Skipping $f because destination file is locked: $dstFile. Stop the service and re-run if you need to update code files."
                        continue
                    }
                }
                Copy-Item -LiteralPath $srcFile -Destination $dstFile -Force
            }
        }
    }

    # Folders we want to deploy
    $folders = @('templates', 'static', 'tools')
    foreach ($folder in $folders) {
        $srcDir = Join-Path $sourceResolved $folder
        if (-not (Test-Path -LiteralPath $srcDir)) { continue }

        $dstDir = Join-Path $destResolved $folder

        if ($PSCmdlet.ShouldProcess($dstDir, "Robocopy $folder")) {
            Invoke-RoboCopy -From $srcDir -To $dstDir -Args @(
                '/MIR',
                '/R:2',
                '/W:2',
                '/XF', 'Thumbs.db',
                '/XD', '__pycache__',
                '/NFL',
                '/NDL',
                '/NP'
            )
        }
    }

    Write-Output "Deploy complete (payload only)."
    Write-Output "Note: This does not restart the service."
    exit 0
}

# Full mirror (not recommended unless you know what you're doing)
if ($PSCmdlet.ShouldProcess($destResolved, 'Robocopy full mirror')) {
    Invoke-RoboCopy -From $sourceResolved -To $destResolved -Args @(
        '/MIR',
        '/R:2',
        '/W:2',
        '/XD', '.venv', 'data', '__pycache__', '.git',
        '/XF', '*.pyc',
        '/NP'
    )
}

Write-Output "Deploy complete (full mirror)."
