rule Trojan_BAT_Lokibot_ABL_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 0b 2b 14 00 06 07 06 07 91 07 28 ?? 00 00 06 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}