rule Trojan_BAT_DCRat_ADC_MTB_2{
	meta:
		description = "Trojan:BAT/DCRat.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0d 07 09 16 11 05 6f 17 00 00 0a 26 16 13 06 2b 11 09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69 32 e8 } 		$a_01_1 = {44 00 43 00 52 00 61 00 74 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}