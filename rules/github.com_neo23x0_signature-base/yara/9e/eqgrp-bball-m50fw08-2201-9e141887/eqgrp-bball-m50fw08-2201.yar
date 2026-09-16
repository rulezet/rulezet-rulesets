rule EQGRP_BBALL_M50FW08_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BBALL_M50FW08-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "80c0b68adb12bf3c15eff9db70a57ab999aad015da99c4417fdfd28156d8d3f7"
		id = "bced11a2-fac4-58e5-a4a8-1c6d5fe418f9"
	strings:
		$s1 = ".got_loader" fullword ascii
		$s2 = "LOADED" fullword ascii
		$s3 = "pageTable.c" fullword ascii
		$s4 = "_start_text" ascii
		$s5 = "handler_readBIOS" fullword ascii
		$s6 = "KEEPGOING" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and 5 of ($s*) )
}