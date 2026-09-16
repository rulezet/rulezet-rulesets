rule Backdoor_AndroidOS_Badok_A_MTB{
	meta:
		description = "Backdoor:AndroidOS/Badok.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {4e 65 74 77 72 6f 6b 4d 6f 6e 69 74 6f 72 } 		$a_01_1 = {42 61 63 6b 64 6f 6f 72 2f 70 68 6f 6e 65 5f 6e 75 6d 5f 73 75 62 6d 69 74 } 		$a_01_2 = {2f 42 61 63 6b 64 6f 6f 72 2f 74 61 73 6b 5f 71 75 65 72 79 } 		$a_01_3 = {61 6c 6c 4e 65 74 77 6f 72 6b 49 6e 66 6f } 		$a_01_4 = {53 45 4e 54 5f 53 4d 53 5f 41 43 54 49 4f 4e } 		$a_01_5 = {73 65 74 43 6f 6d 70 6f 6e 65 6e 74 45 6e 61 62 6c 65 64 53 65 74 74 69 6e 67 } 		$a_01_6 = {53 65 6e 64 20 53 4d 53 20 72 65 70 6f 72 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}