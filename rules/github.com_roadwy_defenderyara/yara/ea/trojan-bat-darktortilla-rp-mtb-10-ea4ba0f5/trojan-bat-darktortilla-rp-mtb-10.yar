rule Trojan_BAT_DarkTortilla_RP_MTB_10{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 da 17 d6 8d 03 00 00 01 0b 07 ?? 0a 00 00 1b 06 17 da 72 d0 2d 00 70 28 df 01 00 06 28 39 00 00 06 a2 07 74 0a 00 00 1b 06 28 b1 00 00 06 de 0f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}