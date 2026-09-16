rule Trojan_BAT_DarkComet_ADA_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 17 59 32 02 2b 2d 07 08 8e b7 32 02 16 0b 11 06 11 07 93 13 0a 08 07 93 13 08 11 0a 09 59 11 08 59 13 09 11 05 11 07 11 09 28 ?? 00 00 0a 9d 07 17 58 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}