rule Trojan_BAT_DarkComet_AD_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 15 13 04 07 09 16 09 8e 69 6f 0c 00 00 0a 13 04 38 17 00 00 00 08 09 16 11 04 6f 09 00 00 0a 07 09 16 09 8e 69 6f 0c 00 00 0a 13 04 11 04 16 30 e4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}