# SOC Fundamentals Lab - C2 Beaconing Simulation (T1071.001)
# FOR TRAINING PURPOSES ONLY
param(
    [string]$C2Uri         = "http://CHANGEME:8080",
    [int]$BeaconCount      = 10,
    [int]$BeaconInterval   = 30,
    [string]$UserAgent     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

for ($i = 1; $i -le $BeaconCount; $i++) {
    try {
        Invoke-WebRequest -Uri $C2Uri -UserAgent $UserAgent -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
        Write-Host "[L7] Beacon $i/$BeaconCount at $(Get-Date -Format 'HH:mm:ss')"
    } catch {
        Write-Host "[L7] Beacon $i/$BeaconCount failed (unreachable)"
    }
    if ($i -lt $BeaconCount) { Start-Sleep -Seconds $BeaconInterval }
}
