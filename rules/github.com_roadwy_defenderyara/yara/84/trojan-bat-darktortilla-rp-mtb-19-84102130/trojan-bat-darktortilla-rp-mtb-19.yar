rule Trojan_BAT_DarkTortilla_RP_MTB_19{
	meta:
		description = "Trojan:BAT/DarkTortilla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 14 72 ?? ?? 00 70 17 8d ?? ?? 00 01 25 16 06 72 ?? ?? 00 70 28 ?? ?? 00 0a a2 14 14 14 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 06 11 06 2c 0e 08 11 05 28 ?? ?? 00 0a 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}