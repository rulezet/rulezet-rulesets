rule Trojan_BAT_DarkComet_ADD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 06 a2 11 06 17 1a 8c ?? 00 00 01 a2 11 06 18 06 8e b7 1a da 8c ?? 00 00 01 a2 11 06 13 07 11 07 14 14 19 8d ?? 00 00 01 13 08 11 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}