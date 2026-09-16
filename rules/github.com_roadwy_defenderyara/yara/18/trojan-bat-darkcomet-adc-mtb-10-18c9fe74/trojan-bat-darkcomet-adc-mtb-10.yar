rule Trojan_BAT_DarkComet_ADC_MTB_10{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 16 03 6f ?? 00 00 0a 17 da 13 05 0c 2b 61 16 03 6f ?? 00 00 0a 17 da 13 06 13 04 2b 48 03 08 11 04 6f ?? 00 00 0a 0d 09 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}