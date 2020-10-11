rule Check_Wine
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of Wine"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$ ="wine_get_unix_file_name"
	condition:
		any of them
}

rule Check_DriveSize
{
	meta:
		Author = "Nick Hoffman"
		Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO
	condition:
		pe.imports("kernel32.dll","CreateFileA") and
		pe.imports("kernel32.dll","DeviceIoControl") and
		$dwIoControlCode and
		$physicaldrive
}

rule disable_uax {
    meta:
        author = "x0r"
        description = "Disable User Access Control"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule disable_firewall {
    meta:
        author = "x0r"
        description = "Disable Firewall"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue"
        $r1 = "FirewallPolicy"
        $r2 = "EnableFirewall"
        $r3 = "FirewallDisableNotify"
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue"
        $r1 = "DisableRegistryTools"
        $r2 = "DisableRegedit"
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_dep {
    meta:
        author = "x0r"
        description = "Bypass DEP"
	version = "0.1"
    strings:
        $c1 = "EnableExecuteProtectionSupport"
        $c2 = "NtSetInformationProcess"
        $c3 = "VirtualProctectEx"
        $c4 = "SetProcessDEPPolicy"
        $c5 = "ZwProtectVirtualMemory"
    condition:
        any of them
}

rule disable_taskmanager {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr"
    condition:
        1 of ($p*) and 1 of ($r*)
}

rule check_patchlevel {
    meta:
        author = "x0r"
        description = "Check if hotfix are applied"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}

rule win_hook {
    meta:
        author = "x0r"
        description = "Affect hook table"
    version = "0.1"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"
    condition:
        $f1 and 1 of ($c*)
}



