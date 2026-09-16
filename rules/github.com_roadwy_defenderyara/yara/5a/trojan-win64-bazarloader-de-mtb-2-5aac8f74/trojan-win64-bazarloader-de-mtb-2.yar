rule Trojan_Win64_BazarLoader_DE_MTB_2{
	meta:
		description = "Trojan:Win64/BazarLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_81_0 = {78 6c 6c 2d 74 72 61 6e 73 66 65 72 2e 78 6c 6c } 		$a_81_1 = {44 6c 6c 4d 61 69 6e } 		$a_81_2 = {53 65 74 45 78 63 65 6c 31 32 45 6e 74 72 79 50 74 } 		$a_81_3 = {58 4c 43 61 6c 6c 56 65 72 } 		$a_81_4 = {4a 61 76 61 4f 62 6a 65 63 74 52 65 66 6c 65 63 74 69 76 65 } 		$a_81_5 = {53 61 76 65 20 77 67 65 74 2e 65 78 65 20 74 6f } 	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3) >=18
 
}