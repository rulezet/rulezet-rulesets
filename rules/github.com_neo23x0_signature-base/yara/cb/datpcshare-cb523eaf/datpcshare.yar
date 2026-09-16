rule datPcShare {
	meta:
		description = "Chinese Hacktool Set - file datPcShare.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
		id = "1bf44c0d-6aa7-5486-baee-c17d3e82403f"
	strings:
		$s1 = "PcShare.EXE" fullword wide
		$s2 = "MZKERNEL32.DLL" fullword ascii
		$s3 = "PcShare" fullword wide
		$s4 = "QQ:4564405" fullword wide
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}