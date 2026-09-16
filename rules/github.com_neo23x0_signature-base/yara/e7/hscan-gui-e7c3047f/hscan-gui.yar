rule hscan_gui {
	meta:
		description = "Chinese Hacktool Set - file hscan-gui.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "1885f0b7be87f51c304b39bc04b9423539825c69"
		id = "27f9d2e9-0a62-57ca-9061-c32945c59c7e"
	strings:
		$s0 = "Hscan.EXE" fullword wide
		$s1 = "RestTool.EXE" fullword ascii
		$s3 = "Hscan Application " fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 550KB and all of them
}