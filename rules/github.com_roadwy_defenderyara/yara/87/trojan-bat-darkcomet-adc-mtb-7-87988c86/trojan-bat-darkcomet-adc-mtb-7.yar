rule Trojan_BAT_DarkComet_ADC_MTB_7{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0b 2b 21 28 ?? ?? ?? 0a 09 8e b7 17 da 6b 5a 6b 6c 28 ?? ?? ?? 0a b7 13 04 06 09 11 04 93 6f ?? ?? ?? 0a 26 06 6f } 		$a_01_1 = {46 00 72 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}