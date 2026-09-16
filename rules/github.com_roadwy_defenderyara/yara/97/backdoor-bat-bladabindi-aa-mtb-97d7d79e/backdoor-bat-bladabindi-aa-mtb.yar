rule Backdoor_BAT_Bladabindi_AA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d 44 b9 ff ff ff } 		$a_81_1 = {53 69 6d 70 6c 65 44 65 74 65 63 74 6f 72 } 		$a_81_2 = {53 79 73 74 65 6d 2e 4e 65 74 2e 4e 65 74 77 6f 72 6b 49 6e 66 6f 72 6d 61 74 69 6f 6e } 		$a_81_3 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}