rule Trojan_BAT_RedLineStealer_NL_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {03 1f 55 61 d1 2a 3a 03 0f 02 28 29 00 00 0a 28 2a 00 00 0a 2a } 		$a_80_1 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } 		$a_80_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } 	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}