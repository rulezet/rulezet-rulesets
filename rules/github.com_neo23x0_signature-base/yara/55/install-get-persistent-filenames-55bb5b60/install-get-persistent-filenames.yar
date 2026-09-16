rule install_get_persistent_filenames {
	meta:
		description = "EQGRP Toolset Firewall - file install_get_persistent_filenames"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "4a50ec4bf42087e932e9e67e0ea4c09e52a475d351981bb4c9851fda02b35291"
		id = "cf74b479-4b78-537a-878c-2f3ce004b775"
	strings:
		$s1 = "Generates the persistence file name and prints it out." fullword ascii
	condition:
		( uint16(0) == 0x457f and all of them )
}