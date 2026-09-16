rule Trojan_BAT_DarkComet_AD_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 09 11 10 58 11 05 11 0e 6e 11 10 6a 58 d4 91 9c 00 11 10 17 58 13 10 11 10 6a 11 0d 6e fe 04 13 13 11 13 2d d8 } 		$a_01_1 = {51 75 69 63 6b 4c 5a } 		$a_01_2 = {53 77 61 67 67 65 72 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}