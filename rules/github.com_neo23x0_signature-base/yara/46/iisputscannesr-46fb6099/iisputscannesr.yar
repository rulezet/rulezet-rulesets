rule IISPutScannesr {
	meta:
		description = "Chinese Hacktool Set - file IISPutScannesr.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
		id = "c5d358e8-955f-5b96-89e7-eb0b6c4d0af0"
	strings:
		$s1 = "yoda & M.o.D." ascii
		$s2 = "-> come.to/f2f **************" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 500KB and all of them
}