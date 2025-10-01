# Check if running as Administrator
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if (-not $IsAdmin) {
    Write-Warning "This script must be run as Administrator. Please restart PowerShell as Administrator."
    exit 1
}

$ServiceName = "InteractiveLauncher"

# Check if service exists
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue

if ($null -eq $service) {
    Write-Output "Service '$ServiceName' does not exist."
    exit 0
}

# Stop the service if it's running
if ($service.Status -eq "Running") {
    Write-Output "Stopping service '$ServiceName'..."
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 2
}

# Delete the service
Write-Output "Deleting service '$ServiceName'..."
sc.exe delete $ServiceName | Out-Null

Write-Output "Service '$ServiceName' deleted successfully."
