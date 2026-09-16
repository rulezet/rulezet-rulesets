rule HKTL_CN_Dos_GetPass {
	meta:
		description = "Chinese Hacktool Set - file GetPass.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Dos_GetPass"
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
		id = "08635096-474c-5fdf-825e-6c7c8c8d4061"
	strings:
		$s0 = "GetLogonS" ascii
		$s3 = "/showthread.php?t=156643" ascii
		$s8 = "To Run As Administ" ascii
		$s18 = "EnableDebugPrivileg" fullword ascii
		$s19 = "sedebugnameValue" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 890KB and all of them
}