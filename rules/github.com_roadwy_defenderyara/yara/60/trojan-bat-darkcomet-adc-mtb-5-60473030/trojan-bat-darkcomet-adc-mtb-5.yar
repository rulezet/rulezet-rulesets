rule Trojan_BAT_DarkComet_ADC_MTB_5{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 12 02 12 01 28 ?? ?? ?? 06 74 01 00 00 1b 13 04 12 03 12 00 28 ?? ?? ?? 06 74 01 00 00 1b 13 05 11 05 28 ?? ?? ?? 0a 13 06 11 04 13 07 28 ?? ?? ?? 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}