rule Trojan_BAT_DarkComet_ADC_MTB_11{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 38 6e 01 00 00 11 05 11 09 09 94 d6 20 00 01 00 00 5d 13 05 } 		$a_01_1 = {11 09 09 94 13 0f 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 0f 9e 11 09 11 09 09 94 11 09 11 05 94 d6 20 00 01 00 00 5d 94 13 10 fe 0c 01 00 6d 16 5f 16 fe 01 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}