rule update_PcInit {
	meta:
		description = "Chinese Hacktool Set - file PcInit.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
		id = "71c34049-97a2-5611-a081-21a85f8631d9"
	strings:
		$s1 = "\\svchost.exe" ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Global\\ps%08x" fullword ascii
		$s4 = "drivers\\" ascii 
		$s5 = "StrStrA" fullword ascii 
		$s6 = "StrToIntA" fullword ascii 
	condition:
		uint16(0) == 0x5a4d and filesize < 50KB and all of them
}