rule Trojan_BAT_Bladabindi_AB_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 0f 00 00 0a 0d 09 06 1f 10 6f 10 00 00 0a 6f 11 00 00 0a 09 06 1f 10 6f 10 00 00 0a 6f 12 00 00 0a 09 6f 13 00 00 0a 02 16 02 8e 69 6f 14 00 00 0a 0b 07 8e 69 1f 11 da 17 d6 8d 06 00 00 01 0c 07 1f 10 08 16 07 8e 69 1f 10 da 28 15 00 00 0a 08 2a } 		$a_01_1 = {47 65 74 42 79 74 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}