# SOC Fundamentals Lab - CreateRemoteThread Simulation (T1055)
# Triggers Sysmon EID 8 for detection training
# FOR TRAINING PURPOSES ONLY

$typeDef = "using System;" +
           "using System.Runtime.InteropServices;" +
           "public class K32Sim {" +
           "    [DllImport(`"kernel32.dll`", SetLastError=true)]" +
           "    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);" +
           "    [DllImport(`"kernel32.dll`", SetLastError=true)]" +
           "    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);" +
           "    [DllImport(`"kernel32.dll`", SetLastError=true)]" +
           "    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);" +
           "    [DllImport(`"kernel32.dll`", SetLastError=true)]" +
           "    public static extern bool CloseHandle(IntPtr hObject);" +
           "    [DllImport(`"kernel32.dll`", SetLastError=true)]" +
           "    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);" +
           "}"

Add-Type -TypeDefinition $typeDef

$target = Start-Process -FilePath "notepad.exe" -PassThru
Start-Sleep -Milliseconds 400

$hProc = [K32Sim]::OpenProcess(0x1F0FFF, $false, $target.Id)
if ($hProc -ne [IntPtr]::Zero) {
    $addr = [K32Sim]::VirtualAllocEx($hProc, [IntPtr]::Zero, 4096, 0x3000, 0x40)
    if ($addr -ne [IntPtr]::Zero) {
        $tid = [IntPtr]::Zero
        $hThread = [K32Sim]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 4, [ref]$tid)
        Write-Host "[L5-7] CreateRemoteThread called -- Sysmon EID 8 generated"
        if ($hThread -ne [IntPtr]::Zero) { [K32Sim]::CloseHandle($hThread) | Out-Null }
        [K32Sim]::VirtualFreeEx($hProc, $addr, 0, 0x8000) | Out-Null
    }
    [K32Sim]::CloseHandle($hProc) | Out-Null
}
$target.Kill()
