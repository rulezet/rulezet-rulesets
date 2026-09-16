rule Trojan_Win32_Dridex_RM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {9b de 0f ac 8f 0f e9 31 7c 2f 2e c6 99 30 cf d5 60 30 44 69 7a 3a 60 71 27 4d a3 82 4b 0a db d5 7b fd 8f cb 5c 5b e9 51 30 2f ae b2 b8 11 50 09 } 		$a_81_1 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } 		$a_81_2 = {48 69 64 65 43 61 72 65 74 } 		$a_81_3 = {6e 74 64 6c 6c 2e 64 6c } 		$a_81_4 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } 		$a_81_5 = {4e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e 45 6e 75 6d } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}