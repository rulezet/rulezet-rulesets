rule Trojan_Win32_lokibot_RPE_MTB{
	meta:
		description = "Trojan:Win32/lokibot.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 28 03 c2 8a 0c 38 39 9c 24 c0 00 00 00 74 07 b8 d0 39 57 00 2b c2 42 88 08 3b d6 7c e0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}