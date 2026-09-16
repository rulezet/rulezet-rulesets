rule EQGRP_Unique_Strings {
	meta:
		description = "EQGRP Toolset Firewall - Unique strings"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "08f5f1e3-ce4e-54ef-922f-50446edfcd70"
	strings:
		$s1 = "/BananaGlee/ELIGIBLEBOMB" ascii
		$s2 = "Protocol must be either http or https (Ex: https://1.2.3.4:1234)"
	condition:
		1 of them
}