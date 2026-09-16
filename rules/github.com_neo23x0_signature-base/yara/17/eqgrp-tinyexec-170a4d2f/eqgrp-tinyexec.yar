rule EQGRP_tinyexec {
	meta:
		description = "EQGRP Toolset Firewall - from files tinyexec"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "b783bafd-52e2-59e8-98ab-47de3250415e"
	strings:
		$s1 = { 73 68 73 74 72 74 61 62 00 2E 74 65 78 74 }
		$s2 = { 5A 58 55 52 89 E2 55 50 89 E1 }
	condition:
		uint32(0) == 0x464c457f and filesize < 270 and all of them
}