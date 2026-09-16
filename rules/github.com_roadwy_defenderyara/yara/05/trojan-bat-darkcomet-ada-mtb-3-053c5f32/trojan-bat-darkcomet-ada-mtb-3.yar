rule Trojan_BAT_DarkComet_ADA_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 02 8e 69 0d 02 8e 69 18 5a 06 8e 69 58 13 04 38 2f 00 00 00 11 04 17 58 0c 02 11 04 09 5d 02 11 04 09 5d 91 06 11 04 06 8e 69 5d 91 61 02 08 09 5d 91 28 ?? 00 00 06 07 58 07 5d d2 9c 11 04 15 58 13 04 11 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}