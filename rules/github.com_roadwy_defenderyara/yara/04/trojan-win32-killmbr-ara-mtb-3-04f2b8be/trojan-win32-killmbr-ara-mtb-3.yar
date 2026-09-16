rule Trojan_Win32_KillMBR_ARA_MTB_3{
	meta:
		description = "Trojan:Win32/KillMBR.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 20 74 68 69 6e 6b 20 6d 62 72 20 77 69 6c 6c 20 64 69 65 } 		$a_01_1 = {54 68 69 73 20 69 73 20 61 20 76 69 72 75 73 21 } 		$a_01_2 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } 		$a_01_3 = {44 69 73 61 62 6c 65 43 4d 44 } 		$a_01_4 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}