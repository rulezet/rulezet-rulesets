rule Trojan_BAT_KillMBR_ARA_MTB_5{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {6f 6f 62 65 5c 77 69 6e 64 65 70 6c 6f 79 2e 65 78 65 } 		$a_80_1 = {74 72 6f 6a 61 6e 20 69 73 20 67 6f 69 6e 67 20 74 6f 20 72 65 62 6f 6f 74 20 79 6f 75 72 20 64 65 76 69 63 65 } 		$a_80_2 = {6f 76 65 72 77 72 69 74 65 20 74 68 65 20 4d 42 52 20 73 65 63 74 6f 72 } 		$a_80_3 = {4c 6f 67 6f 6e 55 49 20 77 69 6c 6c 20 62 65 20 6f 76 65 72 77 72 69 74 74 65 6e } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}