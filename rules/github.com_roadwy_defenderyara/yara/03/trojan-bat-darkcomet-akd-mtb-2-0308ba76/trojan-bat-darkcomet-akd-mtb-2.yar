rule Trojan_BAT_DarkComet_AKD_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 43 16 0c 2b 35 06 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 16 0d 2b 18 06 08 06 08 91 03 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 03 8e 69 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}