rule Dos_NtGod {
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
		id = "c2f0733d-5519-5cb8-b077-0ae8472400b4"
	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 250KB and all of them
}