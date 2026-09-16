rule HKTL_CN_Dos_sys {
	meta:
		description = "Chinese Hacktool Set - file sys.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2023-01-06"
		old_rule_name = "Dos_sys"
		hash = "b5837047443f8bc62284a0045982aaae8bab6f18"
		id = "c4b740f2-f4f8-59ff-ad1f-c06718040b50"
	strings:
		$s0 = "'SeDebugPrivilegeOpen " fullword ascii
		$s6 = "Author: Cyg07*2" fullword ascii
		$s12 = "from golds7n[LAG]'J" fullword ascii
		$s14 = "DAMAGE" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 150KB and all of them
}