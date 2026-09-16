rule Trojan_BAT_KillMBR_ARAU_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 11 07 11 07 11 07 1f 3e 5b 1f 14 5b 5a 59 11 07 61 d2 9c 11 07 17 58 13 07 11 07 11 06 8e 69 32 db } 		$a_80_1 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 		$a_80_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_80_3 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } 	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}