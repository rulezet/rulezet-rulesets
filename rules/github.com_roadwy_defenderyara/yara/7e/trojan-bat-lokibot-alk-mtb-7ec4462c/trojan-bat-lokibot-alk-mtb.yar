rule Trojan_BAT_Lokibot_ALK_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ALK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 30 07 06 11 06 9a 28 ?? 00 00 06 13 07 11 05 72 ?? 04 00 70 17 17 8d ?? 00 00 01 13 0e 11 0e 16 11 07 a2 11 0e 28 ?? 00 00 06 26 11 06 17 58 13 06 11 06 06 8e 69 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}