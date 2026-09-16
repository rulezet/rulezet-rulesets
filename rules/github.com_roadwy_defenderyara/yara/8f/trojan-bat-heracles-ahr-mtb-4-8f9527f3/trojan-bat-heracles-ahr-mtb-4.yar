rule Trojan_BAT_Heracles_AHR_MTB_4{
	meta:
		description = "Trojan:BAT/Heracles.AHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 58 1f 18 6a 58 11 09 6a 58 11 0a 1f 28 5a 6a 58 28 13 00 00 0a 13 0b 11 0b 28 17 00 00 0a 1f 2e 40 19 01 00 00 11 0b 28 12 00 00 0a 17 6a 58 28 } 		$a_01_1 = {08 06 8e 69 28 0e 00 00 0a 1f 40 12 01 6f 12 00 00 06 26 06 16 08 06 8e 69 28 0f 00 00 0a 7e 04 00 00 04 08 06 8e 69 28 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}