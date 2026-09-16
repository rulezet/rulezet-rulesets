rule EQGRP_BUSURPER_3001_724 {
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-3001-724.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "6b558a6b8bf3735a869365256f9f2ad2ed75ccaa0eefdc61d6274df4705e978b"
		id = "006877e9-1e73-5a27-8b3a-bca3513a2035"
	strings:
		$s1 = "IMPLANT" fullword ascii
		$s2 = "KEEPGOING" fullword ascii
		$s3 = "upgrade_implant" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 200KB and 2 of them ) or ( all of them )
}