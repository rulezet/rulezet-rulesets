rule CheshireCat_Sample2 {
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
		date = "2015-08-08"
		score = 70
		hash = "dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
		id = "14448138-0af3-5669-8aa3-f9e773e2a008"
	strings:
		$s0 = "mpgvwr32.dll" fullword ascii
		$s1 = "Unexpected failure of wait! (%d)" fullword ascii
		$s2 = "\"%s\" /e%d /p%s" fullword ascii
		$s4 = "error in params!" fullword ascii
		$s5 = "sscanf" fullword ascii
		$s6 = "<>Param : 0x%x" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and 4 of ($s*)
}