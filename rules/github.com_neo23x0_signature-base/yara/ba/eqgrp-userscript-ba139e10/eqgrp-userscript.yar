rule EQGRP_userscript {
	meta:
		description = "EQGRP Toolset Firewall - file userscript.FW"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "5098ff110d1af56115e2c32f332ff6e3973fb7ceccbd317637c9a72a3baa43d7"
		id = "c6c1b70e-437f-50e7-9055-b943a1a62e6c"
	strings:
		$x1 = "Are you sure? Don't forget that NETSCREEN firewalls require BANANALIAR!! " fullword ascii
	condition:
		1 of them
}