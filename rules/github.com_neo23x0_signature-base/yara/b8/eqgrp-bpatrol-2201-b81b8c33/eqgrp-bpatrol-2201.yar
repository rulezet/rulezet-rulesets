rule EQGRP_BPATROL_2201 {
	meta:
		description = "EQGRP Toolset Firewall - file BPATROL-2201.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "aa892750b893033eed2fedb2f4d872f79421174eb217f0c34a933c424ae66395"
		id = "864a346c-e8aa-5c66-9867-faccb14b8bee"
	strings:
		$s1 = "dumpConfig" fullword ascii
		$s2 = "getstatusHandler" fullword ascii
		$s3 = ".got_loader" fullword ascii
		$s4 = "xtractdata" fullword ascii
		$s5 = "KEEPGOING" fullword ascii
	condition:
		( uint16(0) == 0x457f and filesize < 40KB and all of them )
}