rule EQGRP_BUSURPER_2211_724 {
	meta:
		description = "EQGRP Toolset Firewall - file BUSURPER-2211-724.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "d809d6ff23a9eee53d2132d2c13a9ac5d0cb3037c60e229373fc59a4f14bc744"
		id = "d109210e-14df-5b90-a496-fa8a2454126b"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "_start_text" ascii
		$s3 = "IMPLANT" fullword ascii
		$s4 = "KEEPGOING" fullword ascii
		$s5 = "upgrade_implant" fullword ascii
	condition:
		all of them
}