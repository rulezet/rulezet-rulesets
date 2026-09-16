rule EQGRP_uninstallPBD {
	meta:
		description = "EQGRP Toolset Firewall - file uninstallPBD.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "692fdb449f10057a114cf2963000f52ce118d9a40682194838006c66af159bd0"
		id = "0153cb2a-a0de-51f9-80c2-22136d56f16d"
	strings:
		$s1 = "memset 00e9a05c 4 38845b88" fullword ascii
		$s2 = "_hidecmd" ascii
		$s3 = "memset 013abd04 1 0d" fullword ascii
	condition:
		all of them
}