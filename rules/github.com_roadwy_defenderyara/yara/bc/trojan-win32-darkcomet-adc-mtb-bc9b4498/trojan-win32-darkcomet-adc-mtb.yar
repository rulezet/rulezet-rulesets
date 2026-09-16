rule Trojan_Win32_DarkComet_ADC_MTB{
	meta:
		description = "Trojan:Win32/DarkComet.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 50 6a 00 0f 29 84 24 ?? ?? ?? ?? ff d7 6a 00 6a 00 6a 00 8d 84 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}