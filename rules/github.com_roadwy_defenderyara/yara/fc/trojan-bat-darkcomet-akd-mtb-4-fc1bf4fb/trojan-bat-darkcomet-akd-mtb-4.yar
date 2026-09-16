rule Trojan_BAT_DarkComet_AKD_MTB_4{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0a 11 09 07 94 d6 11 06 07 94 d6 20 00 01 00 00 5d 13 0a 11 09 07 94 13 0c 11 09 07 11 09 11 0a 94 9e 11 09 11 0a 11 0c 9e 7e ?? 00 00 04 7e ?? 00 00 04 12 01 28 ?? 00 00 06 07 17 da 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}