# SOC Fundamentals Lab - Ransomware File Rename Simulation (T1486)
# FOR TRAINING PURPOSES ONLY
param(
    [string]$TargetPath = "$env:USERPROFILE\Documents",
    [string]$Extension  = ".soc_encrypted",
    [int]$MaxFiles      = 50
)

$files = Get-ChildItem -Path $TargetPath -File -Recurse -ErrorAction SilentlyContinue |
         Select-Object -First $MaxFiles
$count = 0

foreach ($file in $files) {
    try {
        Rename-Item -Path $file.FullName -NewName ($file.Name + $Extension) -ErrorAction Stop
        $count++
    } catch {}
}

Write-Host "[L6] Renamed $count files with extension $Extension in $TargetPath"
