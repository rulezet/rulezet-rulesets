rule Trojan_BAT_DarkComet_AKD_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.AKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 0c 2b 37 09 08 9a 0b 07 72 ?? 09 00 70 72 ?? 09 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 2c 18 07 72 ?? 09 00 70 72 ?? 09 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0a 2b 0a 08 17 d6 0c 08 } 		$a_01_1 = {17 da 32 02 2b 2d 08 09 8e b7 32 02 16 0c 11 06 11 07 93 13 08 09 08 93 13 09 11 08 11 05 da 11 09 da 13 0a 07 11 07 11 0a 28 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}