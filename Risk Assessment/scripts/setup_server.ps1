param(
    [string]$ProjectPath = "C:\inetpub\wwwroot\project\Risk Assessment",
    [string]$ServiceName = "RiskTicketing",
    [string]$DisplayName = "Risk Ticketing System",
    [string]$Description = "Flask risk ticketing system (Waitress)",
    [int]$Port = 5001,
    [string]$AdminPassword = "ChangeMe",
    [string]$SecretKey = "ChangeMe",
    [string]$OidcTenantId = "",
    [string]$OidcClientId = "",
    [string]$OidcClientSecret = "",
    [string]$OidcRedirectUri = "",
    [string]$OidcPostLogoutRedirectUri = "",
    [bool]$AuthRequired = $true,
    [string]$EnvFile = "",
    [string]$BindHost = "127.0.0.1",
    [string]$LogDir = "C:\ProgramData\RiskTicketing\logs",
    [string]$ServiceAccount = "highnet\vfsa",
    [bool]$RecreateService = $true
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $ProjectPath)) {
    throw "Project path not found: $ProjectPath"
}

$VenvPath = Join-Path $ProjectPath ".venv"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path $PythonExe)) {
    Write-Host "Creating virtual environment at $VenvPath"
    python -m venv $VenvPath
}

Write-Host "Installing dependencies"
& $PythonExe -m pip install --upgrade pip
& $PythonExe -m pip install -r (Join-Path $ProjectPath "requirements.txt")

Write-Host "Configuring service environment variables"
[Environment]::SetEnvironmentVariable("ADMIN_PASSWORD", $AdminPassword, "Machine")
[Environment]::SetEnvironmentVariable("FLASK_SECRET_KEY", $SecretKey, "Machine")
[Environment]::SetEnvironmentVariable("FLASK_PORT", "$Port", "Machine")
[Environment]::SetEnvironmentVariable("FLASK_HOST", $BindHost, "Machine")
[Environment]::SetEnvironmentVariable("RISK_TICKETING_LOG_DIR", $LogDir, "Machine")

# Microsoft 365 (Entra ID) OIDC settings
if ($OidcTenantId) { [Environment]::SetEnvironmentVariable("OIDC_TENANT_ID", $OidcTenantId, "Machine") }
if ($OidcClientId) { [Environment]::SetEnvironmentVariable("OIDC_CLIENT_ID", $OidcClientId, "Machine") }
if ($OidcClientSecret) { [Environment]::SetEnvironmentVariable("OIDC_CLIENT_SECRET", $OidcClientSecret, "Machine") }
if ($OidcRedirectUri) { [Environment]::SetEnvironmentVariable("OIDC_REDIRECT_URI", $OidcRedirectUri, "Machine") }
if ($OidcPostLogoutRedirectUri) { [Environment]::SetEnvironmentVariable("OIDC_POST_LOGOUT_REDIRECT_URI", $OidcPostLogoutRedirectUri, "Machine") }

[Environment]::SetEnvironmentVariable("AUTH_REQUIRED", ($(if ($AuthRequired) { "true" } else { "false" })), "Machine")

# Optional dotenv file path (app.py loads ENV_FILE if python-dotenv is installed)
if ($EnvFile) {
    [Environment]::SetEnvironmentVariable("ENV_FILE", $EnvFile, "Machine")
}

if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

if ($ServiceAccount) {
    Write-Host "Granting folder access to service account: $ServiceAccount"
    icacls $ProjectPath /grant "${ServiceAccount}:(OI)(CI)M" /T | Out-Null
    icacls $LogDir /grant "${ServiceAccount}:(OI)(CI)M" /T | Out-Null
}

$RunPath = Join-Path $ProjectPath "run_waitress.py"
$Command = "cd /d `"$ProjectPath`" && `"$PythonExe`" `"$RunPath`""
$BinaryPath = "cmd.exe /c `"$Command`""

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    if ($RecreateService) {
        Write-Host "Recreating service: $ServiceName"
        Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
        sc.exe delete $ServiceName | Out-Null
        $attempts = 0
        while (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Start-Sleep -Seconds 2
            $attempts += 1
            if ($attempts -ge 15) {
                throw "Service deletion is pending. Re-run the script after a minute."
            }
        }
        New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName $DisplayName -Description $Description -StartupType Automatic
    } else {
        Write-Host "Updating service binary path: $ServiceName"
        sc.exe config $ServiceName binPath= $BinaryPath | Out-Null
    }
} else {
    Write-Host "Creating service: $ServiceName"
    New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName $DisplayName -Description $Description -StartupType Automatic
}

Write-Host "Starting service"
Set-Service -Name $ServiceName -StartupType Automatic
Start-Service -Name $ServiceName
Write-Host "Done. Service status:"
Get-Service -Name $ServiceName
