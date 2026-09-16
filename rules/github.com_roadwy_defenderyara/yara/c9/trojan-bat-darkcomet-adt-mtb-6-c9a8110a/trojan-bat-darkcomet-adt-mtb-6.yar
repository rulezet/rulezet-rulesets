rule Trojan_BAT_DarkComet_ADT_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 16 06 8e b7 17 da 13 05 13 04 2b 15 06 11 04 06 11 04 91 08 11 04 09 5d 91 61 9c 11 04 17 d6 13 04 11 04 } 		$a_01_1 = {8e b7 17 da 13 06 13 04 2b 15 06 11 04 06 11 04 91 08 11 04 07 5d 91 61 9c 11 04 17 d6 13 04 11 04 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}