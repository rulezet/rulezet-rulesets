rule Dos_look {
	meta:
		description = "Chinese Hacktool Set - file look.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "e1a37f31170e812185cf00a838835ee59b8f64ba"
		id = "910d1469-9173-5a7d-91ea-a50ee921f662"
	strings:
		$s1 = "<description>CHKen QQ:41901298</description>" fullword ascii
		$s2 = "version=\"9.9.9.9\"" fullword ascii
		$s3 = "name=\"CH.Ken.Tool\"" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 40KB and all of them
}