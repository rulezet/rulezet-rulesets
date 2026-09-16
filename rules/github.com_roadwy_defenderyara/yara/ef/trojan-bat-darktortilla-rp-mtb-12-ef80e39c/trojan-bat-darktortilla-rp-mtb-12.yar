rule Trojan_BAT_DarkTortilla_RP_MTB_12{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 28 38 02 00 06 0b 07 06 17 da 72 d2 61 00 70 28 8d 00 00 06 28 33 02 00 06 a2 07 06 28 39 02 00 06 00 de 10 25 28 33 00 00 0a 13 05 00 28 85 00 00 0a de 00 00 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}