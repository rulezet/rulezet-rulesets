rule Trojan_BAT_KillMBR_ARA_MTB_2{
	meta:
		description = "Trojan:BAT/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 50 73 79 63 68 6f 6d 65 6d 65 2e 70 64 62 } 		$a_01_1 = {44 65 73 74 72 6f 79 42 6f 6f 74 4c 6f 61 64 65 72 } 		$a_01_2 = {44 65 73 74 72 6f 79 46 6f 6c 64 65 72 } 		$a_01_3 = {44 65 73 74 72 6f 79 46 69 6c 65 } 		$a_01_4 = {54 61 6b 65 4f 77 6e 65 72 53 68 69 70 4f 66 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}