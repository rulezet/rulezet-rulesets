rule EQGRP_MixText {
	meta:
		description = "EQGRP Toolset Firewall - file MixText.py"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "e4d24e30e6cc3a0aa0032dbbd2b68c60bac216bef524eaf56296430aa05b3795"
		id = "99b06100-8a05-5c22-8b7d-ed451d5f4e81"
	strings:
		$s1 = "BinStore enabled implants." fullword ascii
	condition:
		1 of them
}