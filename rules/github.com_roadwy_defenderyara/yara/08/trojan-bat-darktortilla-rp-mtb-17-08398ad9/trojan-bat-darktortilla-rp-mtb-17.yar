rule Trojan_BAT_DarkTortilla_RP_MTB_17{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 da 17 d6 8d ?? ?? 00 01 0c 72 ?? ?? 00 70 0d 09 28 ?? ?? 00 06 13 04 11 04 28 ?? ?? 00 06 13 05 08 06 17 da 11 05 28 ?? ?? 00 0a a2 08 06 28 ?? ?? 00 06 00 de 10 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}