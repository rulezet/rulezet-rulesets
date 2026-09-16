rule EQGRP_BananaAid {
	meta:
		description = "EQGRP Toolset Firewall - file BananaAid"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "7a4fb825e63dc612de81bc83313acf5eccaa7285afc05941ac1fef199279519f"
		id = "bdd3ce51-1809-5b2f-9c7e-6c0b056d022b"
	strings:
		$x1 = "(might have to delete key in ~/.ssh/known_hosts on linux box)" fullword ascii
		$x2 = "scp BGLEE-" ascii
		$x3 = "should be 4bfe94b1 for clean bootloader version 3.0; " fullword ascii
		$x4 = "scp <configured implant> <username>@<IPaddr>:onfig" fullword ascii
	condition:
		1 of them
}