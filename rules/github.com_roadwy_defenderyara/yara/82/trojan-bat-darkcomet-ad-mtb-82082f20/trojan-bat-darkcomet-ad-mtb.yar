rule Trojan_BAT_DarkComet_AD_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 08 06 16 06 8e b7 6f 5d 00 00 0a 08 6f 5e 00 00 0a 28 5f 00 00 0a 11 04 6f 60 00 00 0a 6f 61 00 00 0a 13 09 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}