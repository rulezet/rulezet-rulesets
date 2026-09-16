rule ipsearcher {
	meta:
		description = "Chinese Hacktool Set - file ipsearcher.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2022-12-21"
		hash = "1e96e9c5c56fcbea94d26ce0b3f1548b224a4791"
		id = "bb33535a-e8cc-545d-bee8-3c31902eedb9"
	strings:
		$s0 = "http://www.wzpg.com" fullword ascii
		$s1 = "ipsearcher\\ipsearcher\\Release\\ipsearcher.pdb" ascii
		$s3 = "_GetAddress" fullword ascii
		$s5 = "ipsearcher.dll" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 140KB and all of them
}