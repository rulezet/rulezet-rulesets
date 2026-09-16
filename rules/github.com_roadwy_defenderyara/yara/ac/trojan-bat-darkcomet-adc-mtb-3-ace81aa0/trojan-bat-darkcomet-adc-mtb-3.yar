rule Trojan_BAT_DarkComet_ADC_MTB_3{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 16 08 a2 11 06 17 03 16 9a 74 ?? 00 00 1b a2 11 06 18 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a a2 11 06 6f } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}