rule Trojan_BAT_DarkComet_ADK_MTB_19{
	meta:
		description = "Trojan:BAT/DarkComet.ADK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {b5 0b 07 02 1f 20 19 16 15 28 ?? 00 00 0a 17 8d ?? 00 00 01 0c 08 16 07 9e 08 28 ?? 00 00 0a de 0e 28 ?? 00 00 0a 17 0a 28 } 		$a_03_1 = {02 50 17 8d ?? 00 00 01 13 04 11 04 16 06 8c ?? 00 00 01 a2 11 04 14 28 ?? 00 00 0a 02 50 17 8d ?? 00 00 01 13 05 11 05 16 07 8c ?? 00 00 01 a2 11 05 14 28 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}