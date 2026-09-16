rule Trojan_BAT_DarkComet_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 2c 02 2b 50 72 ?? 00 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 17 17 6f ?? 00 00 0a 0b 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}