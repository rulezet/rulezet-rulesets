rule EQGRP_morel {
	meta:
		description = "Detects tool from EQGRP toolset - file morel.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "a9152e67f507c9a179bb8478b58e5c71c444a5a39ae3082e04820a0613cd6d9f"
		id = "e741b727-0e41-53d0-832c-df7f4ea7964a"
	strings:
		$s1 = "%d - %d, %d" fullword ascii
		$s2 = "%d - %lu.%lu %d.%lu" fullword ascii
		$s3 = "%d - %d %d" fullword ascii
	condition:
		( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}