rule EQGRP_payload {
	meta:
		description = "EQGRP Toolset Firewall - file payload.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "21bed6d699b1fbde74cbcec93575c9694d5bea832cd191f59eb3e4140e5c5e07"
		id = "949cb68b-e384-578c-a906-a4d9234dc668"
	strings:
		$s1 = "can't find target version module!" fullword ascii
		$s2 = "class Payload:" fullword ascii
	condition:
		all of them
}