rule EQGRP_RC5_RC6_Opcode {
	meta:
		description = "EQGRP Toolset Firewall - RC5 / RC6 opcode"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://securelist.com/blog/incidents/75812/the-equation-giveaway/"
		date = "2016-08-17"
		id = "b12a1a2c-8d32-5318-a658-6aa1a08c3263"
	strings:
		
		$s1 = { 8B 74 91 FC 81 EE 47 86 C8 61 89 34 91 42 83 FA 2B }
	condition:
		1 of them
}