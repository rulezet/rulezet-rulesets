rule EQGRP_Extrabacon_Output {
	meta:
		description = "EQGRP Toolset Firewall - Extrabacon exploit output"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Research"
		date = "2016-08-16"
		id = "b2070ed7-e95a-534a-8f27-63c5ca9251b4"
	strings:
		$s1 = "|###[ SNMPresponse ]###" fullword ascii
		$s2 = "[+] generating exploit for exec mode pass-disable" fullword ascii
		$s3 = "[+] building payload for mode pass-disable" fullword ascii
		$s4 = "[+] Executing:  extrabacon" fullword ascii
		$s5 = "appended AAAADMINAUTH_ENABLE payload" fullword ascii
	condition:
		2 of them
}