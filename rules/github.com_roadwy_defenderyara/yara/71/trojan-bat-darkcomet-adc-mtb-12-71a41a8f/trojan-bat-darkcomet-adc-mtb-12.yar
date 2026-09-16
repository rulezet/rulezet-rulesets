rule Trojan_BAT_DarkComet_ADC_MTB_12{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e } 		$a_01_1 = {43 00 72 00 79 00 70 00 6f 00 6f 00 53 00 53 00 } 		$a_01_2 = {53 00 62 00 69 00 65 00 43 00 74 00 72 00 6c 00 } 		$a_01_3 = {44 00 6f 00 6c 00 6c 00 44 00 6c 00 6c 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}