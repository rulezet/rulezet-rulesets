rule CN_Tools_pc {
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
		id = "11cc6c46-33c0-5c53-88f8-700be9ca8add"
	strings:
		$s0 = "\\svchost.exe" ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 300KB and all of them
}