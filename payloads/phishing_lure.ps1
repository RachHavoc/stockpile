# SOC Fundamentals Lab - Phishing Payload Simulation (L8 Sc.1)
# Simulates execution of a phishing attachment
# FOR TRAINING PURPOSES ONLY
param(
    [string]$C2Uri = "http://192.168.0.1:8080"  # overridden by ability command
)

Write-Host "[L8] Phishing lure executed on $env:COMPUTERNAME by $env:USERNAME"

# Drop a marker artefact so analysts can find it
$markerDir  = "$env:APPDATA\Microsoft\Windows\Themes"
$markerFile = "$markerDir\update_$(Get-Date -Format 'yyyyMMddHHmmss').log"
New-Item -Path $markerDir -ItemType Directory -Force | Out-Null
Set-Content -Path $markerFile -Value "[L8] SOC-Fundamentals phishing simulation — $(Get-Date -Format 'o')"

# Outbound "initial check-in" beacon visible in Zeek + Arkime
try {
    Invoke-WebRequest -Uri $C2Uri -Method GET -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
} catch {}

Write-Host "[L8] Beacon sent to $C2Uri — marker dropped at $markerFile"
