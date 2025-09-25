<#
NetworkAlert.ps1
- Simple TCP listener that prints incoming alerts.
- Optional desktop notifications via BurntToast (Install-Module BurntToast -Scope CurrentUser)

Usage:
  powershell -ExecutionPolicy Bypass -File .\scripts\NetworkAlert.ps1 -Port 65111
#>

param(
    [int]$Port = 65111
)

Write-Host "Starting IDS alert listener on port $Port..." -ForegroundColor Cyan

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
$listener.Start()
try {
    while ($true) {
        if ($listener.Pending()) {
            $client = $listener.AcceptTcpClient()
            try {
                $stream = $client.GetStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $msg = $reader.ReadToEnd()
                $reader.Close()
                $client.Close()

                $timestamp = Get-Date -Format o
                Write-Host "[$timestamp] ALERT RECEIVED: $msg" -ForegroundColor Yellow

                # Optional toast notification
                if (Get-Module -ListAvailable -Name BurntToast) {
                    try {
                        Import-Module BurntToast -ErrorAction Stop
                        New-BurntToastNotification -Text "IDS Alert", $msg | Out-Null
                    } catch {
                        Write-Host "Toast failed: $_" -ForegroundColor Red
                    }
                } else {
                    # Uncomment to install BurntToast automatically (requires admin prompt)
                    # Install-Module BurntToast -Scope CurrentUser -Force
                }
            } finally {
                if ($client) { $client.Dispose() }
            }
        } else {
            Start-Sleep -Milliseconds 200
        }
    }
} finally {
    $listener.Stop()
    Write-Host "Listener stopped."
}
