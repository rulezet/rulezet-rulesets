rule Trojan_BAT_DarkComet_ADC_MTB{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1a 00 02 06 7e 04 00 00 04 06 91 03 06 0e 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}