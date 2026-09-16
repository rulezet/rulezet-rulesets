rule Trojan_BAT_DCRat_ADC_MTB_3{
	meta:
		description = "Trojan:BAT/DCRat.ADC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 2b 24 2b 1c 2b 23 7b 02 00 00 04 1f 31 2b 1d 58 d1 2b 1c 26 2b 20 16 2d 02 17 58 16 2d e2 2b 19 2b 1a 1b 32 df 2a 0a 2b d9 02 2b da 06 2b e0 6f } 		$a_03_1 = {26 06 17 58 0a 06 18 32 ad 16 0b 1e 2c f7 07 18 5d 2d 10 02 7b 02 00 00 04 1f 58 6f ?? 00 00 0a 26 2b 0e 02 7b 02 00 00 04 1f 59 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}