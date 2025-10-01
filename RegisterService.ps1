# Ensure running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $IsAdmin) {
    Write-Warning "This script must be run as Administrator. Please restart PowerShell as Administrator."
    exit 1
}

# -------------------------------
# Service configuration
# -------------------------------
$ServiceName   = "InteractiveLauncher"
$RelativePath  = "InteractiveSessionLauncher\bin\Debug\net9.0-windows10.0.19041.0\InteractiveSessionLauncher.exe"
$ServiceExePath = Join-Path $PSScriptRoot $RelativePath

# Verify the exe exists
if (-not (Test-Path $ServiceExePath)) {
    Write-Error "Executable not found at: $ServiceExePath"
    exit 1
}

# -------------------------------
# Remove existing service if present
# -------------------------------
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Write-Output "Service '$ServiceName' already exists. Deleting it first..."
    sc.exe delete $ServiceName | Out-Null

    # Wait until the service entry is removed
    while (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 1
    }
}

# -------------------------------
# Create new service
# -------------------------------
Write-Output "Creating service '$ServiceName' pointing to:"
Write-Output "  $ServiceExePath"

sc.exe create $ServiceName binPath= "`"$ServiceExePath`"" start= demand DisplayName= "Interactive Session Launcher"

if ($LASTEXITCODE -eq 0) {
    Write-Output "Service '$ServiceName' created successfully (Manual startup)."
} else {
    Write-Error "Failed to create service '$ServiceName'."
}
