rule Trojan_BAT_DCRat_ADC_MTB{
	meta:
		description = "Trojan:BAT/DCRat.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 18 00 00 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 3f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}