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

    public class Kernel32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
"@
$THREAD_SUSPEND_RESUME = 0x0002

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
	echo $tokenPrivileges
}

Enable-DebugPrivilege

$process = Get-Process -Name "<proc_name>"
$threads = $process.Threads
foreach ($thread in $threads) {
    $hThread = [Kernel32]::OpenThread($THREAD_SUSPEND_RESUME, $false, $thread.Id)
    if ($hThread -ne [IntPtr]::Zero) {
        [Kernel32]::SuspendThread($hThread)
        [Kernel32]::CloseHandle($hThread)
    }
}
