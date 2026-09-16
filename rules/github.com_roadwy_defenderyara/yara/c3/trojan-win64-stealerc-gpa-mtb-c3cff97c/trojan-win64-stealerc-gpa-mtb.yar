rule Trojan_Win64_Stealerc_GPA_MTB{
	meta:
		description = "Trojan:Win64/Stealerc.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_81_0 = {74 65 72 6e 69 6d 61 74 65 } 		$a_01_1 = {73 65 61 6c 5f 70 6b 00 6b 78 5f 70 6b 00 00 00 73 69 67 6e 5f 70 6b 00 70 72 69 76 69 6c 65 64 67 65 5f 65 73 63 61 6c 61 74 69 6f 6e 00 00 00 61 75 72 6f 74 75 6e } 		$a_81_2 = {58 43 68 61 43 68 61 32 30 2d 50 6f 6c 79 31 33 30 35 } 		$a_81_3 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 } 	condition:
		((#a_81_0  & 1)*4+(#a_01_1  & 1)*4+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=10
 
}