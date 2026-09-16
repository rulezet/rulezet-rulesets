rule Trojan_BAT_DarkComet_ADC_MTB_8{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0d 0c 2b 49 07 08 91 1f 1f fe 02 07 08 91 1f 7f fe 04 5f 2c 19 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 18 d6 b4 59 86 9c 07 08 91 1f 20 2f 14 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 1f 5f 58 86 9c 08 17 d6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}