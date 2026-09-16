rule NtGodMode {
	meta:
		description = "Chinese Hacktool Set - file NtGodMode.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "8baac735e37523d28fdb6e736d03c67274f7db77"
		id = "3de620bf-0405-536b-9f6d-3a7f02417b20"
	strings:
		$s0 = "to HOST!" fullword ascii
		$s1 = "SS.EXE" fullword ascii
		$s5 = "lstrlen0" fullword ascii
		$s6 = "Virtual" fullword ascii  
		$s19 = "RtlUnw" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 45KB and all of them
}