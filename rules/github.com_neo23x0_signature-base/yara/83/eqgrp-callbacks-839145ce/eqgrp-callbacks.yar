rule EQGRP_callbacks {
	meta:
		description = "EQGRP Toolset Firewall - Callback addresses"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "dd1fbe09-4def-562d-825d-e790dc2c3dd9"
	strings:
		$s1 = "30.40.50.60:9342" fullword ascii wide 
	condition:
		1 of them
}