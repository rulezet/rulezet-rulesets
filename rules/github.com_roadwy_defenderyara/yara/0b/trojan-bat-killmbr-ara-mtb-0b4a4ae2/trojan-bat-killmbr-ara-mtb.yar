rule Trojan_BAT_KillMBR_ARA_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 06 11 07 11 07 11 07 1a 63 11 07 1e 63 5f 11 07 1f 0a 63 61 5a d2 9c 11 07 17 58 13 07 11 07 11 06 8e 69 32 da } 		$a_01_1 = {50 6c 61 79 53 79 6e 63 } 		$a_01_2 = {53 6f 75 6e 64 50 6c 61 79 65 72 } 		$a_80_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*1) >=7
 
}