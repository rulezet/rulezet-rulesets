rule Backdoor_Linux_Nixgi_A_xp{
	meta:
		description = "Backdoor:Linux/Nixgi.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 78 69 6e 67 79 69 5f 72 65 76 65 72 73 65 5f 70 69 64 } 		$a_01_1 = {2f 74 6d 70 2f 78 69 6e 67 79 69 5f 62 69 6e 64 73 68 65 6c 6c 5f 70 69 64 } 		$a_01_2 = {2f 74 6d 70 2f 78 69 6e 67 79 69 5f 72 65 76 65 72 73 65 5f 70 6f 72 74 } 		$a_01_3 = {2f 74 6d 70 2f 78 69 6e 67 79 69 5f 62 69 6e 64 73 68 65 6c 6c 5f 70 6f 72 74 } 		$a_01_4 = {73 77 30 72 64 6d 34 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}