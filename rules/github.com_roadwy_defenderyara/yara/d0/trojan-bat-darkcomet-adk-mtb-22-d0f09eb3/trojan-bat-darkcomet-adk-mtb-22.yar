rule Trojan_BAT_DarkComet_ADK_MTB_22{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {15 13 05 08 06 16 06 8e b7 6f ?? 00 00 0a 13 05 2b 1a 11 04 06 16 11 05 6f ?? 00 00 0a 00 08 06 16 06 8e b7 6f ?? 00 00 0a 13 05 00 11 05 16 fe 02 13 06 11 06 2d db } 		$a_03_1 = {13 04 0d 2b 39 03 09 18 28 ?? 00 00 0a 0b 08 72 ?? 00 00 70 07 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a b7 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 09 17 d6 0d 00 09 17 d6 0d 09 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}