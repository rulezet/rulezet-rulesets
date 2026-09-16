rule Trojan_BAT_DarkComet_ADC_MTB_6{
	meta:
		description = "Trojan:BAT/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 2b 48 06 17 d6 20 ff 00 00 00 5f 0a 07 11 05 06 91 d6 20 ff 00 00 00 5f 0b 11 05 06 91 13 07 11 05 06 11 05 07 91 9c 11 05 07 11 07 9c 09 08 11 05 11 05 06 91 11 05 07 91 d6 20 ff 00 00 00 5f 91 02 08 91 61 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}