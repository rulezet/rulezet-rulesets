rule EQGRP_epicbanana_2_1_0_1 {
	meta:
		description = "EQGRP Toolset Firewall - file epicbanana_2.1.0.1.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4b13cc183c3aaa8af43ef3721e254b54296c8089a0cd545ee3b867419bb66f61"
		id = "cc3346bd-0347-5cf3-b946-5c017d68d93e"
	strings:
		$s1 = "failed to create version-specific payload" fullword ascii
		$s2 = "(are you sure you did \"make [version]\" in versions?)" fullword ascii
	condition:
		1 of them
}