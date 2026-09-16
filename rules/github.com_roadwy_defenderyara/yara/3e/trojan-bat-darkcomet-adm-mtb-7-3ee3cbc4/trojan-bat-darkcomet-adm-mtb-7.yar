rule Trojan_BAT_DarkComet_ADM_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 02 8e b7 17 da 13 08 13 07 2b 33 09 11 07 02 11 07 91 11 05 61 11 04 11 06 91 61 9c 11 04 28 ?? ?? ?? 0a 11 06 11 04 8e b7 17 da } 		$a_01_1 = {0d 0b 2b 24 16 0c 02 07 94 08 33 0f 06 08 17 da 13 04 11 04 06 11 04 94 17 d6 9e 08 17 d6 0c 08 1f 0a 31 e2 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}