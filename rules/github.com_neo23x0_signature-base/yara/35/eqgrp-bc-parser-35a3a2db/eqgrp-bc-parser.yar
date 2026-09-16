rule EQGRP_bc_parser {
	meta:
		description = "Detects tool from EQGRP toolset - file bc-parser"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-15"
		score = 75
		hash1 = "879f2f1ae5d18a3a5310aeeafec22484607649644e5ecb7d8a72f0877ac19cee"
		id = "ed4523de-b126-503a-83bd-aafd8533b0e5"
	strings:
		$s1 = "*** Target may be susceptible to FALSEMOREL      ***" fullword ascii
		$s2 = "*** Target is susceptible to FALSEMOREL          ***" fullword ascii
	condition:
		uint16(0) == 0x457f and 1 of them
}