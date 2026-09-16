rule EQGRP_teflonhandle {
	meta:
		description = "Detects tool from EQGRP toolset - file teflonhandle.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		id = "4d82cc41-3777-5f8c-9392-aca69e6ed781"
	strings:
		$s1 = "%s [infile] [outfile] /k 0x[%i character hex key] </g>" fullword ascii
		$s2 = "File %s already exists.  Overwrite? (y/n) " fullword ascii
		$s3 = "Random Key : 0x" fullword ascii
		$s4 = "done (%i bytes written)." fullword ascii
		$s5 = "%s --> %s..." fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 20KB and 2 of them
}