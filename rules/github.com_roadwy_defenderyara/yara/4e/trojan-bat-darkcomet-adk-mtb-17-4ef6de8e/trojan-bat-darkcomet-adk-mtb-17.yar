rule Trojan_BAT_DarkComet_ADK_MTB_17{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1e 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 06 08 6f ?? 00 00 0a d2 61 d2 9c 08 17 58 0c 08 06 } 		$a_03_1 = {16 13 05 2b 1d 11 04 11 05 91 0c 07 08 13 06 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 07 11 07 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}