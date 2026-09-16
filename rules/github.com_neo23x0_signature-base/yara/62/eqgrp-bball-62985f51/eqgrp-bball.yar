rule EQGRP_BBALL {
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_E28F6-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "498fc9f20b938b8111adfa3ca215325f265a08092eefd5300c4168876deb7bf6"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
	strings:
		$s1 = "Components/Modules/BiosModule/Implant/E28F6/../e28f640j3_asm.S" fullword ascii
		$s2 = ".got_loader" fullword ascii
		$s3 = "handler_readBIOS" fullword ascii
		$s4 = "cmosReadByte" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
		$s6 = "checksumAreaConfirmed.0" fullword ascii
		$s7 = "writeSpeedPlow.c" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 4 of ($s*) ) or ( all of them )
}